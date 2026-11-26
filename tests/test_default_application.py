"""Focused integration tests for the supported ``app.main:app`` entry point."""

from __future__ import annotations

import importlib
import os
from pathlib import Path
import subprocess
import sys

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth import create_development_token
from app.authorization_models import ResourceGrant, TenantPrincipal
from app.permissions import ResourcePermission


EVENT = {
    "eventType": "ACCOUNT_UPDATED",
    "actorId": "advisor-001",
    "resourceType": "customer_account",
    "resourceId": "account-1",
    "payload": {"change": "address"},
}

EXPECTED_AUDIT_OPERATIONS = {
    ("POST", "/audit/events"),
    ("GET", "/audit/events"),
    ("GET", "/audit/verify"),
    ("POST", "/audit/exports"),
    ("POST", "/audit/retention/run"),
    ("POST", "/audit/events/{event_ref}/redact"),
    ("GET", "/audit/access-reports"),
}


def _token(subject: str, role: str, tenant_id: str) -> dict[str, str]:
    return {
        "Authorization": (
            "Bearer " + create_development_token(subject, [role], tenant_id=tenant_id)
        )
    }


def _grant(
    session: Session,
    *,
    tenant_id: str,
    subject: str,
    permission: ResourcePermission,
    resource_id: str,
) -> None:
    principal = session.scalar(
        select(TenantPrincipal).where(
            TenantPrincipal.tenant_id == tenant_id,
            TenantPrincipal.subject == subject,
        )
    )
    if principal is None:
        principal = TenantPrincipal(tenant_id=tenant_id, subject=subject, active=True)
        session.add(principal)
        session.flush()
    session.add(
        ResourceGrant(
            tenant_id=tenant_id,
            principal_id=principal.id,
            resource_type="customer_account",
            resource_id=resource_id,
            permission=permission.value,
            active=True,
        )
    )


@pytest.fixture
def default_client(tmp_path, monkeypatch):
    """Load the production entry point only after isolated V4 configuration."""

    monkeypatch.setenv(
        "AUDIT_JWT_SIGNING_KEY", "default-app-test-signing-key-at-least-thirty-two-chars"
    )
    monkeypatch.setenv("AUDIT_JWT_ISSUER", "default-app-test")
    monkeypatch.setenv("AUDIT_JWT_AUDIENCE", "default-app-test")
    monkeypatch.setenv("AUDIT_RETENTION_DAYS", "30")
    monkeypatch.setenv("AUDIT_V4_DB_PATH", str(tmp_path / "default-v4.sqlite"))
    monkeypatch.delenv("AUDIT_DB_PATH", raising=False)

    import app.v4_main as v4_main
    import app.main as main

    # ``app.v4_main`` constructs its application at import time. Reloading both
    # modules makes this test exercise the same entry point Uvicorn imports.
    importlib.reload(v4_main)
    main = importlib.reload(main)
    engine = main.app.state.engine
    with Session(engine) as session:
        _grant(
            session,
            tenant_id="tenant-a",
            subject="writer-a",
            permission=ResourcePermission.CREATE_EVENT,
            resource_id="account-1",
        )
        _grant(
            session,
            tenant_id="tenant-a",
            subject="auditor-a",
            permission=ResourcePermission.READ_EVENT,
            resource_id="account-1",
        )
        _grant(
            session,
            tenant_id="tenant-a",
            subject="writer-no-grant",
            permission=ResourcePermission.READ_EVENT,
            resource_id="account-1",
        )
        _grant(
            session,
            tenant_id="tenant-b",
            subject="writer-b",
            permission=ResourcePermission.CREATE_EVENT,
            resource_id="account-1",
        )
        _grant(
            session,
            tenant_id="tenant-b",
            subject="auditor-b",
            permission=ResourcePermission.READ_EVENT,
            resource_id="account-1",
        )
        session.commit()

    with TestClient(main.app) as client:
        yield client, engine
    engine.dispose()


def test_default_application_exposes_exact_v4_audit_inventory(default_client):
    client, _ = default_client

    assert client.get("/").status_code == 200
    assert client.get("/health").status_code == 200
    assert client.get("/ready").status_code == 200
    assert client.get("/docs").status_code == 200

    paths = client.get("/openapi.json").json()["paths"]
    actual = {
        (method.upper(), path)
        for path, operations in paths.items()
        for method in operations
        if method.upper() in {"GET", "POST", "PUT", "PATCH", "DELETE"}
        and path.startswith("/audit/")
    }
    assert actual == EXPECTED_AUDIT_OPERATIONS


def test_default_application_creates_and_retrieves_with_tenant_grants(default_client):
    client, _ = default_client

    created = client.post("/audit/events", json=EVENT, headers=_token("writer-a", "writer", "tenant-a"))
    assert created.status_code == 201
    assert "id" not in created.json()
    assert "eventRef" in created.json()

    listed = client.get("/audit/events", headers=_token("auditor-a", "auditor", "tenant-a"))
    assert listed.status_code == 200
    assert [event["eventRef"] for event in listed.json()] == [created.json()["eventRef"]]


def test_default_application_rejects_legacy_token_without_tenant_claim(default_client):
    client, _ = default_client
    legacy_token = create_development_token("writer-a", ["writer"])

    response = client.post(
        "/audit/events", json=EVENT, headers={"Authorization": f"Bearer {legacy_token}"}
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid authentication token"}


def test_default_application_denies_missing_and_revoked_resource_grants(default_client):
    client, engine = default_client

    denied = client.post(
        "/audit/events", json=EVENT, headers=_token("writer-no-grant", "writer", "tenant-a")
    )
    assert denied.status_code == 403

    assert client.post("/audit/events", json=EVENT, headers=_token("writer-a", "writer", "tenant-a")).status_code == 201
    with Session(engine) as session:
        grant = session.scalar(
            select(ResourceGrant).join(TenantPrincipal).where(
                TenantPrincipal.tenant_id == "tenant-a",
                TenantPrincipal.subject == "auditor-a",
                ResourceGrant.permission == ResourcePermission.READ_EVENT.value,
            )
        )
        assert grant is not None
        grant.active = False
        session.commit()

    revoked = client.get("/audit/events", headers=_token("auditor-a", "auditor", "tenant-a"))
    assert revoked.status_code == 200
    assert revoked.json() == []


def test_default_application_prevents_cross_tenant_and_cross_resource_reads(default_client):
    client, engine = default_client

    assert client.post("/audit/events", json=EVENT, headers=_token("writer-a", "writer", "tenant-a")).status_code == 201
    with Session(engine) as session:
        _grant(
            session,
            tenant_id="tenant-a",
            subject="writer-a",
            permission=ResourcePermission.CREATE_EVENT,
            resource_id="account-2",
        )
        session.commit()
    hidden = {**EVENT, "resourceId": "account-2"}
    assert client.post("/audit/events", json=hidden, headers=_token("writer-a", "writer", "tenant-a")).status_code == 201

    cross_tenant = client.get("/audit/events", headers=_token("auditor-b", "auditor", "tenant-b"))
    assert cross_tenant.status_code == 200
    assert cross_tenant.json() == []

    cross_resource = client.get(
        "/audit/events?resourceId=account-2", headers=_token("auditor-a", "auditor", "tenant-a")
    )
    assert cross_resource.status_code == 200
    assert cross_resource.json() == []


def test_default_application_import_fails_without_v4_path_even_with_legacy_path(tmp_path):
    environment = os.environ.copy()
    environment.update(
        {
            "AUDIT_JWT_SIGNING_KEY": "default-app-test-signing-key-at-least-thirty-two-chars",
            "AUDIT_JWT_ISSUER": "default-app-test",
            "AUDIT_JWT_AUDIENCE": "default-app-test",
            "AUDIT_RETENTION_DAYS": "30",
            "AUDIT_DB_PATH": str(tmp_path / "legacy-fallback.sqlite"),
        }
    )
    environment.pop("AUDIT_V4_DB_PATH", None)

    result = subprocess.run(
        [sys.executable, "-c", "import app.main"],
        cwd=os.fspath(Path(__file__).resolve().parents[1]),
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "AUDIT_V4_DB_PATH is required" in result.stderr
    assert not (tmp_path / "legacy-fallback.sqlite").exists()
