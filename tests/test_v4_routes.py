from __future__ import annotations
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from app.auth import create_development_token
from app.authorization_models import ResourceGrant, TenantPermissionGrant, TenantPrincipal
from app.permissions import ResourcePermission, TenantPermission
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from sqlalchemy.exc import IntegrityError
from app.v4_database import initialize_v4_database
from app.v4_models import V4AuditEvent
from app.services.v4_audit_service import append_v4_audit_event, begin_v4_write_transaction
from app.services.v4_audit_service import archive_v4_events, redact_v4_event, verify_v4_tenant_chain
from app.v4_models import V4AuditEventArchive, V4AuditEventRedaction

@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("AUDIT_JWT_SIGNING_KEY","v4-route-test-key-with-at-least-thirty-two-characters")
    monkeypatch.setenv("AUDIT_JWT_ISSUER","v4-test")
    monkeypatch.setenv("AUDIT_JWT_AUDIENCE","v4-test")
    monkeypatch.setenv("AUDIT_V4_DB_PATH", str(tmp_path / "entry.sqlite"))
    from app.v4_main import create_v4_app
    path=str(tmp_path/"v4.sqlite"); engine=initialize_v4_database(path)
    with Session(engine) as session:
        for tenant,subject in (("tenant-a","writer"),("tenant-a","auditor"),("tenant-a","admin"),("tenant-b","writer")):
            p=TenantPrincipal(tenant_id=tenant,subject=subject,active=True); session.add(p); session.flush()
            permission=ResourcePermission.CREATE_EVENT.value if subject=="writer" else (ResourcePermission.REDACT_EVENT.value if subject=="admin" else ResourcePermission.READ_EVENT.value)
            session.add(ResourceGrant(tenant_id=tenant,principal_id=p.id,resource_type="customer_account",resource_id="account-1",permission=permission,active=True))
            if subject=="admin": session.add(TenantPermissionGrant(tenant_id=tenant,principal_id=p.id,permission=TenantPermission.RUN_RETENTION.value,active=True))
        session.commit()
    yield TestClient(create_v4_app(path)), engine
    engine.dispose()
def headers(subject, role, tenant): return {"Authorization":"Bearer "+create_development_token(subject,[role],tenant_id=tenant)}
EVENT={"eventType":"UPDATED","actorId":"advisor","resourceType":"customer_account","resourceId":"account-1","payload":{"x":1}}
def test_v4_create_and_tenant_scoped_replay(client):
    api,engine=client; h=headers("writer","writer","tenant-a")|{"Idempotency-Key":"one"}
    first=api.post("/audit/events",json=EVENT,headers=h); replay=api.post("/audit/events",json=EVENT,headers=h)
    assert first.status_code==201 and replay.status_code==200
    assert first.json()["eventRef"]==replay.json()["eventRef"] and "id" not in first.json()
def test_v4_creation_and_broad_read_require_live_grants(client):
    api,engine=client
    assert api.post("/audit/events",json=EVENT,headers=headers("writer","writer","tenant-b")).status_code==201
    assert api.get("/audit/events",headers=headers("auditor","auditor","tenant-a")).status_code==200
    assert api.get("/audit/events",headers=headers("writer","writer","tenant-b")).json()==[]
    denied={**EVENT,"resourceId":"account-2"}
    assert api.post("/audit/events",json=denied,headers=headers("writer","writer","tenant-a")).status_code==403

def test_v4_queries_authorize_before_pagination_and_actor_filtering(client):
    api,engine=client
    assert api.post("/audit/events",json=EVENT,headers=headers("writer","writer","tenant-a")).status_code==201
    with Session(engine) as session:
        begin_v4_write_transaction(session)
        append_v4_audit_event(session,tenant_id="tenant-a",event_type="UPDATED",actor_id="other",resource_type="customer_account",resource_id="account-2",payload={"hidden":True})
        session.commit()
    response=api.get("/audit/events?limit=1&offset=0",headers=headers("auditor","auditor","tenant-a"))
    assert response.status_code==200 and [row["resourceId"] for row in response.json()]==["account-1"]
    assert api.get("/audit/events?actorId=other",headers=headers("auditor","auditor","tenant-a")).json()==[]

def test_v4_denies_inactive_or_revoked_replay_and_allows_tenant_scoped_same_key(client):
    api,engine=client; key={"Idempotency-Key":"same-key"}
    assert api.post("/audit/events",json=EVENT,headers=headers("writer","writer","tenant-a")|key).status_code==201
    assert api.post("/audit/events",json=EVENT,headers=headers("writer","writer","tenant-b")|key).status_code==201
    with Session(engine) as session:
        grant=session.scalar(__import__("sqlalchemy").select(ResourceGrant).where(ResourceGrant.tenant_id=="tenant-a",ResourceGrant.permission==ResourcePermission.CREATE_EVENT.value)); grant.active=False; session.commit()
    assert api.post("/audit/events",json=EVENT,headers=headers("writer","writer","tenant-a")|key).status_code==403
    with Session(engine) as session:
        principal=session.scalar(__import__("sqlalchemy").select(TenantPrincipal).where(TenantPrincipal.tenant_id=="tenant-b",TenantPrincipal.subject=="writer")); principal.active=False; session.commit()
    assert api.post("/audit/events",json=EVENT,headers=headers("writer","writer","tenant-b")|{"Idempotency-Key":"new"}).status_code==403

def test_v4_app_does_not_expose_legacy_routes_or_internal_identifiers(client):
    api,_=client
    assert api.get("/audit/verify",headers=headers("writer","writer","tenant-a")).status_code==404
    assert api.get("/audit/retention/run",headers=headers("writer","writer","tenant-a")).status_code==405
    created=api.post("/audit/events",json=EVENT,headers=headers("writer","writer","tenant-a"))
    assert created.status_code==201 and "id" not in created.json() and "tenantSequence" not in created.json()

def test_v4_redaction_masks_reads_and_guessed_or_ungranted_targets_are_not_disclosed(client):
    api,_=client; payload={**EVENT,"payload":{"secret":"value","public":"ok"}}
    event=api.post("/audit/events",json=payload,headers=headers("writer","writer","tenant-a")).json()
    assert api.post(f"/audit/events/{event['eventRef']}/redact",json={"paths":["/secret"],"reason":"PRIVACY_REQUEST"},headers=headers("admin","admin","tenant-a")).status_code==200
    listed=api.get("/audit/events",headers=headers("auditor","auditor","tenant-a")).json()
    assert listed[0]["payload"]["secret"] == "[REDACTED]"
    assert api.post("/audit/events/00000000-0000-4000-8000-000000000001/redact",json={"paths":["/secret"],"reason":"PRIVACY_REQUEST"},headers=headers("admin","admin","tenant-a")).status_code==404

def test_v4_retention_is_tenant_scoped_and_hides_archived_events(client):
    api,engine=client
    with Session(engine) as session:
        begin_v4_write_transaction(session)
        append_v4_audit_event(session,tenant_id="tenant-a",event_type="OLD",actor_id="advisor",resource_type="customer_account",resource_id="account-1",payload={},timestamp=datetime.now(timezone.utc)-timedelta(days=31))
        append_v4_audit_event(session,tenant_id="tenant-b",event_type="OLD",actor_id="advisor",resource_type="customer_account",resource_id="account-1",payload={},timestamp=datetime.now(timezone.utc)-timedelta(days=31))
        session.commit()
    result=api.post("/audit/retention/run",headers=headers("admin","admin","tenant-a"))
    assert result.status_code==200 and result.json()["archivedEventCount"]==1
    assert api.get("/audit/events",headers=headers("auditor","auditor","tenant-a")).json()==[]

def test_v4_lifecycle_tampering_fails_closed_and_reserved_events_are_rejected(client):
    api,engine=client; event=api.post("/audit/events",json={**EVENT,"payload":{"secret":"x"}},headers=headers("writer","writer","tenant-a")).json()
    assert api.post("/audit/events",json={**EVENT,"eventType":"V4_EVENT_REDACTED"},headers=headers("writer","writer","tenant-a")).status_code==422
    assert api.post(f"/audit/events/{event['eventRef']}/redact",json={"paths":["/secret"],"reason":"PRIVACY_REQUEST"},headers=headers("admin","admin","tenant-a")).status_code==200
    with engine.begin() as connection: connection.exec_driver_sql("UPDATE v4_audit_event_redactions SET json_pointer='/missing'")
    assert api.get("/audit/events",headers=headers("auditor","auditor","tenant-a")).status_code==409
    assert api.post("/audit/events",json=EVENT,headers=headers("writer","writer","tenant-a")).status_code==409

def test_v4_lifecycle_rollback_and_noop_behavior(client):
    api,engine=client; event=api.post("/audit/events",json={**EVENT,"payload":{"secret":"x"}},headers=headers("writer","writer","tenant-a")).json()
    with Session(engine) as session:
        begin_v4_write_transaction(session); redact_v4_event(session,tenant_id="tenant-a",event_ref=event["eventRef"],paths=["/secret"],reason="PRIVACY_REQUEST",operator="admin"); session.rollback()
    with Session(engine) as session: assert session.query(V4AuditEventRedaction).count()==0
    body={"paths":["/secret"],"reason":"PRIVACY_REQUEST"}; assert api.post(f"/audit/events/{event['eventRef']}/redact",json=body,headers=headers("admin","admin","tenant-a")).json()["redactedPaths"]==["/secret"]
    assert api.post(f"/audit/events/{event['eventRef']}/redact",json=body,headers=headers("admin","admin","tenant-a")).json()["redactedPaths"]==[]

def test_v4_lifecycle_revocation_cross_scope_and_unexpected_metadata_fail_closed(client):
    api,engine=client; event=api.post("/audit/events",json={**EVENT,"payload":{"secret":"x"}},headers=headers("writer","writer","tenant-a")).json()
    with Session(engine) as session:
        grant=session.scalar(__import__("sqlalchemy").select(ResourceGrant).where(ResourceGrant.tenant_id=="tenant-a",ResourceGrant.permission==ResourcePermission.REDACT_EVENT.value)); grant.active=False; session.commit()
    assert api.post(f"/audit/events/{event['eventRef']}/redact",json={"paths":["/secret"],"reason":"PRIVACY_REQUEST"},headers=headers("admin","admin","tenant-a")).status_code==404
    with Session(engine) as session:
        begin_v4_write_transaction(session); action=append_v4_audit_event(session,tenant_id="tenant-a",event_type="ORDINARY",actor_id="writer",resource_type="customer_account",resource_id="account-1",payload={}); action_id=action.id; session.commit()
    with engine.begin() as connection: connection.exec_driver_sql("INSERT INTO v4_audit_event_archives (tenant_id,target_event_id,archive_action_event_id,archived_at) VALUES ('tenant-a',1,?,?)",(action_id,datetime.now(timezone.utc).isoformat()))
    assert api.get("/audit/events",headers=headers("auditor","auditor","tenant-a")).status_code==409

def test_v4_cross_tenant_lifecycle_foreign_key_rejection_preserves_evidence(client):
    api,engine=client
    first=api.post("/audit/events",json=EVENT,headers=headers("writer","writer","tenant-a")).json()
    second=api.post("/audit/events",json=EVENT,headers=headers("writer","writer","tenant-b")).json()
    with Session(engine) as session:
        a=session.scalar(__import__("sqlalchemy").select(V4AuditEvent).where(V4AuditEvent.event_ref==first["eventRef"])); b=session.scalar(__import__("sqlalchemy").select(V4AuditEvent).where(V4AuditEvent.event_ref==second["eventRef"]))
        session.add(V4AuditEventArchive(tenant_id="tenant-a",target_event_id=a.id,archive_action_event_id=b.id,archived_at=datetime.now(timezone.utc)))
        with pytest.raises(IntegrityError): session.commit()
        session.rollback(); assert session.query(V4AuditEventArchive).count()==0

def test_v4_concurrent_redaction_serializes_to_one_metadata_row(client):
    api,engine=client; event=api.post("/audit/events",json={**EVENT,"payload":{"secret":"x"}},headers=headers("writer","writer","tenant-a")).json(); barrier=Barrier(2)
    def redact():
        with Session(engine) as session:
            barrier.wait(timeout=3); begin_v4_write_transaction(session)
            redact_v4_event(session,tenant_id="tenant-a",event_ref=event["eventRef"],paths=["/secret"],reason="PRIVACY_REQUEST",operator="admin"); session.commit()
    with ThreadPoolExecutor(max_workers=2) as pool: list(pool.map(lambda _: redact(), range(2)))
    with Session(engine) as session:
        assert session.query(V4AuditEventRedaction).count()==1
        assert verify_v4_tenant_chain(session,"tenant-a").is_intact

@pytest.mark.parametrize("key", ["", "bad key", "x" * 129])
def test_v4_rejects_invalid_idempotency_keys_without_writes(client, key):
    api,engine=client
    assert api.post("/audit/events",json=EVENT,headers=headers("writer","writer","tenant-a")|{"Idempotency-Key":key}).status_code==422
    with Session(engine) as session: assert session.query(V4AuditEvent).count()==0
