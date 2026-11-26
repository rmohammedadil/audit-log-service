from __future__ import annotations
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from app.auth import create_development_token
from app.authorization_models import ResourceGrant, TenantPrincipal
from app.permissions import ResourcePermission
from app.v4_database import initialize_v4_database
from app.v4_models import V4AuditEvent
from app.services.v4_audit_service import append_v4_audit_event, begin_v4_write_transaction

@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("AUDIT_JWT_SIGNING_KEY","v4-route-test-key-with-at-least-thirty-two-characters")
    monkeypatch.setenv("AUDIT_JWT_ISSUER","v4-test")
    monkeypatch.setenv("AUDIT_JWT_AUDIENCE","v4-test")
    monkeypatch.setenv("AUDIT_V4_DB_PATH", str(tmp_path / "entry.sqlite"))
    from app.v4_main import create_v4_app
    path=str(tmp_path/"v4.sqlite"); engine=initialize_v4_database(path)
    with Session(engine) as session:
        for tenant,subject in (("tenant-a","writer"),("tenant-a","auditor"),("tenant-b","writer")):
            p=TenantPrincipal(tenant_id=tenant,subject=subject,active=True); session.add(p); session.flush()
            permission=ResourcePermission.CREATE_EVENT.value if subject=="writer" else ResourcePermission.READ_EVENT.value
            session.add(ResourceGrant(tenant_id=tenant,principal_id=p.id,resource_type="customer_account",resource_id="account-1",permission=permission,active=True))
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
    assert api.get("/audit/retention/run",headers=headers("writer","writer","tenant-a")).status_code==404
    created=api.post("/audit/events",json=EVENT,headers=headers("writer","writer","tenant-a"))
    assert created.status_code==201 and "id" not in created.json() and "tenantSequence" not in created.json()

@pytest.mark.parametrize("key", ["", "bad key", "x" * 129])
def test_v4_rejects_invalid_idempotency_keys_without_writes(client, key):
    api,engine=client
    assert api.post("/audit/events",json=EVENT,headers=headers("writer","writer","tenant-a")|{"Idempotency-Key":key}).status_code==422
    with Session(engine) as session: assert session.query(V4AuditEvent).count()==0
