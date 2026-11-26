from __future__ import annotations
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from app.auth import create_development_token
from app.authorization_models import ResourceGrant, TenantPermissionGrant, TenantPrincipal
from app.permissions import ResourcePermission, TenantPermission
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier, Event as ThreadEvent
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from app.v4_database import initialize_v4_database
from app.v4_models import V4AuditEvent, V4TenantChainState
from app.services.v4_audit_service import append_v4_audit_event, begin_v4_write_transaction
from app.services.v4_audit_service import archive_v4_events, redact_v4_event, verify_v4_tenant_chain
from app.v4_models import V4AuditEventArchive, V4AuditEventRedaction
from app.services.export_service import calculate_bundle_digest
from app.verify_v4_export import verify_v4_bundle

@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("AUDIT_JWT_SIGNING_KEY","v4-route-test-key-with-at-least-thirty-two-characters")
    monkeypatch.setenv("AUDIT_JWT_ISSUER","v4-test")
    monkeypatch.setenv("AUDIT_JWT_AUDIENCE","v4-test")
    monkeypatch.setenv("AUDIT_V4_DB_PATH", str(tmp_path / "entry.sqlite"))
    from app.v4_main import create_v4_app
    path=str(tmp_path/"v4.sqlite"); engine=initialize_v4_database(path)
    with Session(engine) as session:
        for tenant,subject in (("tenant-a","writer"),("tenant-a","auditor"),("tenant-a","admin"),("tenant-a","regulator"),("tenant-b","writer")):
            p=TenantPrincipal(tenant_id=tenant,subject=subject,active=True); session.add(p); session.flush()
            permission=ResourcePermission.CREATE_EVENT.value if subject=="writer" else (ResourcePermission.REDACT_EVENT.value if subject=="admin" else (ResourcePermission.READ_ACCESS_REPORT.value if subject=="regulator" else (ResourcePermission.EXPORT_RESOURCE.value if subject=="auditor" else ResourcePermission.READ_EVENT.value)))
            session.add(ResourceGrant(tenant_id=tenant,principal_id=p.id,resource_type="customer_account",resource_id="account-1",permission=permission,active=True))
            if subject=="auditor": session.add(ResourceGrant(tenant_id=tenant,principal_id=p.id,resource_type="customer_account",resource_id="account-1",permission=ResourcePermission.READ_EVENT.value,active=True))
            if subject=="admin": session.add(TenantPermissionGrant(tenant_id=tenant,principal_id=p.id,permission=TenantPermission.RUN_RETENTION.value,active=True))
            if subject=="auditor": session.add(TenantPermissionGrant(tenant_id=tenant,principal_id=p.id,permission=TenantPermission.EXPORT_TENANT_WITNESS.value,active=True))
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
    assert api.get("/audit/verify",headers=headers("writer","writer","tenant-a")).status_code==403
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
        append_v4_audit_event(session,tenant_id="tenant-a",event_type="OLD",actor_id="advisor",resource_type="customer_account",resource_id="account-1",payload={},timestamp=datetime.now(timezone.utc)-timedelta(days=91))
        append_v4_audit_event(session,tenant_id="tenant-b",event_type="OLD",actor_id="advisor",resource_type="customer_account",resource_id="account-1",payload={},timestamp=datetime.now(timezone.utc)-timedelta(days=91))
        session.commit()
    result=api.post("/audit/retention/run",headers=headers("admin","admin","tenant-a"))
    assert result.status_code==200 and result.json()["archivedEventCount"]==1
    assert api.get("/audit/events",headers=headers("auditor","auditor","tenant-a")).json()==[]


def test_v4_default_retention_keeps_events_younger_than_ninety_days(client, monkeypatch):
    """The route must use the shared 90-day default, not an independent value."""

    api,engine=client
    monkeypatch.delenv("AUDIT_RETENTION_DAYS", raising=False)
    with Session(engine) as session:
        begin_v4_write_transaction(session)
        retained=append_v4_audit_event(session,tenant_id="tenant-a",event_type="MIDDLE_AGE",actor_id="advisor",resource_type="customer_account",resource_id="account-1",payload={},timestamp=datetime.now(timezone.utc)-timedelta(days=45))
        archived=append_v4_audit_event(session,tenant_id="tenant-a",event_type="OLD",actor_id="advisor",resource_type="customer_account",resource_id="account-1",payload={},timestamp=datetime.now(timezone.utc)-timedelta(days=100))
        retained_id,archived_id=retained.id,archived.id
        session.commit()

    response=api.post("/audit/retention/run",headers=headers("admin","admin","tenant-a"))
    assert response.status_code==200 and response.json()=={"archivedEventCount":1}
    with Session(engine) as session:
        archived_ids=set(session.scalars(__import__("sqlalchemy").select(V4AuditEventArchive.target_event_id)))
        assert archived_id in archived_ids and retained_id not in archived_ids


def test_v4_explicit_retention_configuration_is_applied(client, monkeypatch):
    api,engine=client
    monkeypatch.setenv("AUDIT_RETENTION_DAYS","30")
    with Session(engine) as session:
        begin_v4_write_transaction(session)
        event=append_v4_audit_event(session,tenant_id="tenant-a",event_type="OLD",actor_id="advisor",resource_type="customer_account",resource_id="account-1",payload={},timestamp=datetime.now(timezone.utc)-timedelta(days=45))
        event_id=event.id
        session.commit()

    assert api.post("/audit/retention/run",headers=headers("admin","admin","tenant-a")).json()=={"archivedEventCount":1}
    with Session(engine) as session:
        assert event_id in set(session.scalars(__import__("sqlalchemy").select(V4AuditEventArchive.target_event_id)))

def test_v4_lifecycle_tampering_fails_closed_and_reserved_events_are_rejected(client):
    api,engine=client; event=api.post("/audit/events",json={**EVENT,"payload":{"secret":"x"}},headers=headers("writer","writer","tenant-a")).json()
    assert api.post("/audit/events",json={**EVENT,"eventType":"V4_EVENT_REDACTED"},headers=headers("writer","writer","tenant-a")).status_code==422
    assert api.post(f"/audit/events/{event['eventRef']}/redact",json={"paths":["/secret"],"reason":"PRIVACY_REQUEST"},headers=headers("admin","admin","tenant-a")).status_code==200
    with engine.begin() as connection: connection.exec_driver_sql("UPDATE v4_audit_event_redactions SET json_pointer='/missing'")
    assert api.get("/audit/events",headers=headers("auditor","auditor","tenant-a")).status_code==409
    assert api.post("/audit/events",json=EVENT,headers=headers("writer","writer","tenant-a")).status_code==409

def test_v4_deleted_redaction_metadata_fails_closed_without_exposing_payload(client):
    """A chained redaction action without metadata must not reveal its target."""

    api,engine=client
    body={**EVENT,"eventType":"CLIENT_ACCOUNT_ACCESS","payload":{"operation":"READ","outcome":"SUCCESS","details":{"secret":"classified"}}}
    created=api.post("/audit/events",json=body,headers=headers("writer","writer","tenant-a")|{"Idempotency-Key":"redaction-replay"})
    assert created.status_code==201
    event_ref=created.json()["eventRef"]
    assert api.post(f"/audit/events/{event_ref}/redact",json={"paths":["/details/secret"],"reason":"PRIVACY_REQUEST"},headers=headers("admin","admin","tenant-a")).status_code==200
    with Session(engine) as session:
        principal=session.scalar(__import__("sqlalchemy").select(TenantPrincipal).where(TenantPrincipal.tenant_id=="tenant-a",TenantPrincipal.subject=="auditor"))
        session.add(TenantPermissionGrant(tenant_id="tenant-a",principal_id=principal.id,permission=TenantPermission.VERIFY_TENANT_CHAIN.value,active=True))
        session.commit()
    with engine.begin() as connection:
        connection.exec_driver_sql("DELETE FROM v4_audit_event_redactions WHERE tenant_id='tenant-a'")
    with Session(engine) as session:
        before=(session.query(V4AuditEvent).count(),session.get(V4TenantChainState,"tenant-a").event_count)

    responses=[
        api.get("/audit/events",headers=headers("auditor","auditor","tenant-a")),
        api.post("/audit/events",json=body,headers=headers("writer","writer","tenant-a")|{"Idempotency-Key":"redaction-replay"}),
        api.post("/audit/events",json=EVENT,headers=headers("writer","writer","tenant-a")),
        api.post(f"/audit/events/{event_ref}/redact",json={"paths":["/details/secret"],"reason":"PRIVACY_REQUEST"},headers=headers("admin","admin","tenant-a")),
        api.post("/audit/retention/run",headers=headers("admin","admin","tenant-a")),
        api.post("/audit/exports",json={"resourceId":"account-1"},headers=headers("auditor","auditor","tenant-a")),
        api.get("/audit/access-reports?from=2020-01-01T00:00:00Z&to=2030-01-01T00:00:00Z",headers=headers("regulator","regulator","tenant-a")),
    ]
    assert all(response.status_code==409 for response in responses)
    assert all("classified" not in response.text for response in responses)
    verified=api.get("/audit/verify",headers=headers("auditor","auditor","tenant-a"))
    assert verified.status_code==200 and verified.json()["isIntact"] is False
    with Session(engine) as session:
        after=(session.query(V4AuditEvent).count(),session.get(V4TenantChainState,"tenant-a").event_count)
    assert after==before

def test_v4_partial_redaction_metadata_deletion_is_detected(client):
    api,engine=client
    event=api.post("/audit/events",json={**EVENT,"payload":{"first":"one","second":"two"}},headers=headers("writer","writer","tenant-a")).json()
    assert api.post(f"/audit/events/{event['eventRef']}/redact",json={"paths":["/first","/second"],"reason":"PRIVACY_REQUEST"},headers=headers("admin","admin","tenant-a")).status_code==200
    with engine.begin() as connection:
        connection.exec_driver_sql("DELETE FROM v4_audit_event_redactions WHERE json_pointer='/first'")
    assert api.get("/audit/events",headers=headers("auditor","auditor","tenant-a")).status_code==409
    with Session(engine) as session:
        assert not verify_v4_tenant_chain(session,"tenant-a").is_intact

def test_v4_partial_archive_metadata_deletion_is_detected(client):
    api,engine=client
    with Session(engine) as session:
        begin_v4_write_transaction(session)
        first=append_v4_audit_event(session,tenant_id="tenant-a",event_type="OLD",actor_id="advisor",resource_type="customer_account",resource_id="account-1",payload={},timestamp=datetime.now(timezone.utc)-timedelta(days=100))
        append_v4_audit_event(session,tenant_id="tenant-a",event_type="OLD",actor_id="advisor",resource_type="customer_account",resource_id="account-1",payload={},timestamp=datetime.now(timezone.utc)-timedelta(days=101))
        first_id=first.id
        session.commit()
    assert api.post("/audit/retention/run",headers=headers("admin","admin","tenant-a")).json()=={"archivedEventCount":2}
    with engine.begin() as connection:
        connection.exec_driver_sql("DELETE FROM v4_audit_event_archives WHERE target_event_id=?",(first_id,))
    assert api.get("/audit/events",headers=headers("auditor","auditor","tenant-a")).status_code==409
    with Session(engine) as session:
        assert not verify_v4_tenant_chain(session,"tenant-a").is_intact

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

def test_v4_verify_and_access_reports_are_tenant_resource_scoped(client):
    api,_=client
    payload={"operation":"READ","outcome":"SUCCESS"}
    assert api.post("/audit/events",json={**EVENT,"eventType":"CLIENT_ACCOUNT_ACCESS","payload":payload},headers=headers("writer","writer","tenant-a")).status_code==201
    # No tenant-wide verification grant is provisioned for the regulator.
    assert api.get("/audit/verify",headers=headers("regulator","regulator","tenant-a")).status_code==403
    report=api.get("/audit/access-reports?from=2020-01-01T00:00:00Z&to=2030-01-01T00:00:00Z",headers=headers("regulator","regulator","tenant-a"))
    assert report.status_code==200 and len(report.json())==1 and "id" not in report.json()[0]

def test_v4_export_requires_witness_and_masks_records(client):
    api,engine=client; event=api.post("/audit/events",json={**EVENT,"payload":{"secret":"x"}},headers=headers("writer","writer","tenant-a")).json()
    assert api.post(f"/audit/events/{event['eventRef']}/redact",json={"paths":["/secret"],"reason":"PRIVACY_REQUEST"},headers=headers("admin","admin","tenant-a")).status_code==200
    bundle=api.post("/audit/exports",json={"resourceId":"account-1"},headers=headers("auditor","auditor","tenant-a"))
    assert bundle.status_code==200 and bundle.json()["records"][0]["payload"]["secret"]=="[REDACTED]" and "resourceId" not in bundle.json()["chainWitness"][0]
    exported=bundle.json(); assert exported["bundleDigest"]==calculate_bundle_digest(exported) and verify_v4_bundle(exported)["isValid"]
    with Session(engine) as session:
        grant=session.scalar(__import__("sqlalchemy").select(TenantPermissionGrant).where(TenantPermissionGrant.permission==TenantPermission.EXPORT_TENANT_WITNESS.value)); grant.active=False; session.commit()
    assert api.post("/audit/exports",json={"resourceId":"account-1"},headers=headers("auditor","auditor","tenant-a")).status_code==403

def test_v4_export_and_reports_deny_cross_resource_and_revoked_access(client):
    api,engine=client
    with Session(engine) as session:
        begin_v4_write_transaction(session)
        append_v4_audit_event(session,tenant_id="tenant-a",event_type="CLIENT_ACCOUNT_ACCESS",actor_id="shared",resource_type="customer_account",resource_id="account-2",payload={"operation":"READ","outcome":"SUCCESS"})
        session.commit()
    hidden=api.post("/audit/exports",json={"actorId":"shared"},headers=headers("auditor","auditor","tenant-a"))
    assert hidden.status_code==200 and hidden.json()["records"]==[]
    assert api.get("/audit/access-reports?from=2020-01-01T00:00:00Z&to=2030-01-01T00:00:00Z",headers=headers("regulator","regulator","tenant-a")).json()==[]
    with Session(engine) as session:
        grant=session.scalar(__import__("sqlalchemy").select(ResourceGrant).where(ResourceGrant.tenant_id=="tenant-a",ResourceGrant.permission==ResourcePermission.EXPORT_RESOURCE.value)); grant.active=False; session.commit()
    assert api.post("/audit/exports",json={"resourceId":"account-1"},headers=headers("auditor","auditor","tenant-a")).status_code==403

def test_v4_actor_exports_use_authorized_subset_without_existence_oracle(client):
    api,engine=client
    with Session(engine) as session:
        begin_v4_write_transaction(session)
        append_v4_audit_event(session,tenant_id="tenant-a",event_type="UPDATED",actor_id="mixed",resource_type="customer_account",resource_id="account-1",payload={"visible":True})
        append_v4_audit_event(session,tenant_id="tenant-a",event_type="UPDATED",actor_id="mixed",resource_type="customer_account",resource_id="account-2",payload={"hidden":True})
        append_v4_audit_event(session,tenant_id="tenant-a",event_type="UPDATED",actor_id="hidden-only",resource_type="customer_account",resource_id="account-2",payload={"hidden":True})
        session.commit()
    mixed=api.post("/audit/exports",json={"actorId":"mixed"},headers=headers("auditor","auditor","tenant-a"))
    hidden=api.post("/audit/exports",json={"actorId":"hidden-only"},headers=headers("auditor","auditor","tenant-a"))
    absent=api.post("/audit/exports",json={"actorId":"does-not-exist"},headers=headers("auditor","auditor","tenant-a"))
    assert mixed.status_code==200 and [row["resourceId"] for row in mixed.json()["records"]]==["account-1"]
    assert hidden.status_code==absent.status_code==200
    assert hidden.json()["records"]==absent.json()["records"]==[]
    assert "account-2" not in str(mixed.json())+str(hidden.json())+str(absent.json())
    with Session(engine) as session:
        grant=session.scalar(__import__("sqlalchemy").select(ResourceGrant).where(ResourceGrant.tenant_id=="tenant-a",ResourceGrant.permission==ResourcePermission.EXPORT_RESOURCE.value))
        grant.active=False; session.commit()
    assert api.post("/audit/exports",json={"actorId":"mixed"},headers=headers("auditor","auditor","tenant-a")).json()["records"]==[]
    assert api.post("/audit/exports",json={"resourceId":"account-1"},headers=headers("auditor","auditor","tenant-a")).status_code==403

def test_v4_archive_filtering_occurs_before_pagination(client):
    api,engine=client
    with Session(engine) as session:
        begin_v4_write_transaction(session)
        old=append_v4_audit_event(session,tenant_id="tenant-a",event_type="CLIENT_ACCOUNT_ACCESS",actor_id="a",resource_type="customer_account",resource_id="account-1",payload={"operation":"READ","outcome":"SUCCESS"},timestamp=datetime.now(timezone.utc)-timedelta(days=2))
        action=append_v4_audit_event(session,tenant_id="tenant-a",event_type="V4_EVENT_ARCHIVED",actor_id="admin",resource_type="customer_account",resource_id="account-1",payload={"eventRef":old.event_ref,"retentionDays":1})
        session.add(V4AuditEventArchive(tenant_id="tenant-a",target_event_id=old.id,archive_action_event_id=action.id,archived_at=action.timestamp)); session.commit()
    result=api.get("/audit/access-reports?from=2020-01-01T00:00:00Z&to=2030-01-01T00:00:00Z&includeArchived=false&limit=1",headers=headers("regulator","regulator","tenant-a"))
    assert result.status_code==200 and result.json()==[]

@pytest.mark.parametrize("key", ["", "bad key", "x" * 129])
def test_v4_rejects_invalid_idempotency_keys_without_writes(client, key):
    api,engine=client
    assert api.post("/audit/events",json=EVENT,headers=headers("writer","writer","tenant-a")|{"Idempotency-Key":key}).status_code==422
    with Session(engine) as session: assert session.query(V4AuditEvent).count()==0

def test_v4_redaction_reference_denials_are_indistinguishable_and_nonmutating(client):
    api,engine=client
    with Session(engine) as session:
        begin_v4_write_transaction(session)
        ungranted=append_v4_audit_event(session,tenant_id="tenant-a",event_type="UPDATED",actor_id="advisor",resource_type="customer_account",resource_id="account-2",payload={})
        cross_tenant=append_v4_audit_event(session,tenant_id="tenant-b",event_type="UPDATED",actor_id="advisor",resource_type="customer_account",resource_id="account-1",payload={})
        session.commit()
        ungranted_ref,cross_tenant_ref=ungranted.event_ref,cross_tenant.event_ref
    with Session(engine) as session:
        before=(session.query(V4AuditEvent).count(),session.query(V4AuditEventRedaction).count(),session.get(V4TenantChainState,"tenant-a").event_count)
    body={"paths":["/missing"],"reason":"PRIVACY_REQUEST"}
    responses=[
        api.post(f"/audit/events/{ungranted_ref}/redact",json=body,headers=headers("admin","admin","tenant-a")),
        api.post(f"/audit/events/{cross_tenant_ref}/redact",json=body,headers=headers("admin","admin","tenant-a")),
        api.post("/audit/events/00000000-0000-4000-8000-000000000001/redact",json=body,headers=headers("admin","admin","tenant-a")),
    ]
    assert [response.status_code for response in responses]==[404,404,404]
    assert len({response.text for response in responses})==1
    with Session(engine) as session:
        after=(session.query(V4AuditEvent).count(),session.query(V4AuditEventRedaction).count(),session.get(V4TenantChainState,"tenant-a").event_count)
    assert after==before

def test_v4_inactive_memberships_deny_sensitive_operations(client):
    api,engine=client
    event=api.post("/audit/events",json=EVENT,headers=headers("writer","writer","tenant-a")).json()
    with Session(engine) as session:
        auditor=session.scalar(select(TenantPrincipal).where(TenantPrincipal.tenant_id=="tenant-a",TenantPrincipal.subject=="auditor"))
        session.add(TenantPermissionGrant(tenant_id="tenant-a",principal_id=auditor.id,permission=TenantPermission.VERIFY_TENANT_CHAIN.value,active=True))
        for subject in ("admin","auditor","regulator"):
            session.scalar(select(TenantPrincipal).where(TenantPrincipal.tenant_id=="tenant-a",TenantPrincipal.subject==subject)).active=False
        session.commit()
    assert api.post(f"/audit/events/{event['eventRef']}/redact",json={"paths":["/x"],"reason":"PRIVACY_REQUEST"},headers=headers("admin","admin","tenant-a")).status_code==404
    assert api.post("/audit/retention/run",headers=headers("admin","admin","tenant-a")).status_code==403
    assert api.post("/audit/exports",json={"resourceId":"account-1"},headers=headers("auditor","auditor","tenant-a")).status_code==403
    assert api.get("/audit/verify",headers=headers("auditor","auditor","tenant-a")).status_code==403
    assert api.get("/audit/access-reports?from=2020-01-01T00:00:00Z&to=2030-01-01T00:00:00Z",headers=headers("regulator","regulator","tenant-a")).status_code==403

def test_v4_revoked_lifecycle_permissions_leave_evidence_unchanged(client):
    api,engine=client
    with Session(engine) as session:
        begin_v4_write_transaction(session)
        event=append_v4_audit_event(session,tenant_id="tenant-a",event_type="OLD",actor_id="advisor",resource_type="customer_account",resource_id="account-1",payload={"secret":"x"},timestamp=datetime.now(timezone.utc)-timedelta(days=100))
        event_ref=event.event_ref
        session.commit()
        for permission in (ResourcePermission.REDACT_EVENT.value,TenantPermission.RUN_RETENTION.value):
            session.scalar(select(ResourceGrant if permission==ResourcePermission.REDACT_EVENT.value else TenantPermissionGrant).where((ResourceGrant if permission==ResourcePermission.REDACT_EVENT.value else TenantPermissionGrant).permission==permission)).active=False
        session.commit()
        before=(session.query(V4AuditEvent).count(),session.query(V4AuditEventArchive).count(),session.query(V4AuditEventRedaction).count(),session.get(V4TenantChainState,"tenant-a").event_count)
    assert api.post(f"/audit/events/{event_ref}/redact",json={"paths":["/secret"],"reason":"PRIVACY_REQUEST"},headers=headers("admin","admin","tenant-a")).status_code==404
    assert api.post("/audit/retention/run",headers=headers("admin","admin","tenant-a")).status_code==403
    with Session(engine) as session:
        after=(session.query(V4AuditEvent).count(),session.query(V4AuditEventArchive).count(),session.query(V4AuditEventRedaction).count(),session.get(V4TenantChainState,"tenant-a").event_count)
    assert after==before

def test_v4_cross_resource_idempotency_conflict_does_not_bypass_authorization(client):
    api,engine=client
    key={"Idempotency-Key":"cross-resource-key"}
    assert api.post("/audit/events",json=EVENT,headers=headers("writer","writer","tenant-a")|key).status_code==201
    denied=api.post("/audit/events",json={**EVENT,"resourceId":"account-2"},headers=headers("writer","writer","tenant-a")|key)
    assert denied.status_code==403 and denied.json()=={"detail":"Insufficient permissions"}
    with Session(engine) as session:
        assert session.query(V4AuditEvent).count()==1 and session.get(V4TenantChainState,"tenant-a").event_count==1

@pytest.mark.parametrize("kind",["events","exports","reports"])
def test_v4_read_snapshots_are_consistent_during_concurrent_grant_revocation(client,monkeypatch,kind):
    api,engine=client
    body={**EVENT,"eventType":"CLIENT_ACCOUNT_ACCESS","payload":{"operation":"READ","outcome":"SUCCESS"}} if kind=="reports" else EVENT
    assert api.post("/audit/events",json=body,headers=headers("writer","writer","tenant-a")).status_code==201
    subject,permission=("regulator",ResourcePermission.READ_ACCESS_REPORT.value) if kind=="reports" else ("auditor",ResourcePermission.EXPORT_RESOURCE.value if kind=="exports" else ResourcePermission.READ_EVENT.value)
    import app.api.v4_audit_routes as routes
    original=routes.active_tenant_principal; entered=ThreadEvent(); release=ThreadEvent(); revoked=ThreadEvent()
    def paused(session,identity):
        principal=original(session,identity)
        entered.set(); assert release.wait(3)
        return principal
    monkeypatch.setattr(routes,"active_tenant_principal",paused)
    def request():
        if kind=="events": return api.get("/audit/events",headers=headers("auditor","auditor","tenant-a"))
        if kind=="exports": return api.post("/audit/exports",json={"actorId":"advisor"},headers=headers("auditor","auditor","tenant-a"))
        return api.get("/audit/access-reports?from=2020-01-01T00:00:00Z&to=2030-01-01T00:00:00Z",headers=headers("regulator","regulator","tenant-a"))
    def revoke():
        assert entered.wait(3)
        with Session(engine) as session:
            grant=session.scalar(select(ResourceGrant).join(TenantPrincipal).where(TenantPrincipal.tenant_id=="tenant-a",TenantPrincipal.subject==subject,ResourceGrant.permission==permission))
            grant.active=False; session.commit()
        revoked.set()
    with ThreadPoolExecutor(max_workers=2) as pool:
        future=pool.submit(request)
        assert entered.wait(3)
        revocation=pool.submit(revoke)
        assert not revoked.wait(.2)
        release.set()
        response=future.result(timeout=5); revocation.result(timeout=5)
    assert response.status_code==200
    assert len(response.json()["records"] if kind=="exports" else response.json())==1
    if kind=="events": after=api.get("/audit/events",headers=headers("auditor","auditor","tenant-a")).json()
    elif kind=="exports": after=api.post("/audit/exports",json={"actorId":"advisor"},headers=headers("auditor","auditor","tenant-a")).json()["records"]
    else: after=api.get("/audit/access-reports?from=2020-01-01T00:00:00Z&to=2030-01-01T00:00:00Z",headers=headers("regulator","regulator","tenant-a")).json()
    assert after==[]
