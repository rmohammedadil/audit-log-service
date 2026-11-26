"""Focused tests for the isolated Task 36A V4 authorization foundation."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import sqlite3

import jwt
import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.auth import TenantAuthenticatedIdentity, authenticate_v4, create_development_token
from app.authorization_models import ResourceGrant, TenantPermissionGrant, TenantPrincipal
from app.authorization_service import (
    AuthorizationDeniedError,
    active_tenant_principal,
    authorized_resource_ids,
    require_resource_grant,
    require_tenant_grant,
)
from app.manage_grants import (
    AuthorizationDatabaseError,
    authorization_engine,
    grant_resource,
    grant_tenant,
    main as grants_main,
    provision_principal,
)
from app.permissions import ResourcePermission, TenantPermission
from app.database import Base


@pytest.fixture
def configured_jwt(monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    config = {
        "key": "task-36a-signing-key-with-at-least-thirty-two-characters",
        "issuer": "task-36a-issuer",
        "audience": "task-36a-audience",
    }
    monkeypatch.setenv("AUDIT_JWT_SIGNING_KEY", config["key"])
    monkeypatch.setenv("AUDIT_JWT_ISSUER", config["issuer"])
    monkeypatch.setenv("AUDIT_JWT_AUDIENCE", config["audience"])
    return config


@pytest.fixture
def authorization_session(tmp_path):
    engine = authorization_engine(str(tmp_path / "authorization.sqlite"))
    with Session(engine) as session:
        yield session
    engine.dispose()


def _credentials(token: str) -> HTTPAuthorizationCredentials:
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


def _identity(tenant_id: str = "tenant-a", subject: str = "user-a") -> TenantAuthenticatedIdentity:
    return TenantAuthenticatedIdentity(subject=subject, tenant_id=tenant_id, roles=frozenset({"writer"}))


def _principal(session: Session, tenant_id: str = "tenant-a", subject: str = "user-a", active: bool = True) -> TenantPrincipal:
    principal = TenantPrincipal(tenant_id=tenant_id, subject=subject, active=active)
    session.add(principal)
    session.commit()
    return principal


def test_v4_authentication_accepts_verified_tenant_token(configured_jwt: dict[str, str]) -> None:
    token = create_development_token("user-a", ["writer"], tenant_id="tenant-a")
    identity = authenticate_v4(_credentials(token))
    assert identity == _identity()


@pytest.mark.parametrize("tenant_claim", [None, "", " tenant-a", 7, ["tenant-a"]])
def test_v4_authentication_rejects_missing_blank_or_malformed_tenant_claim(
    configured_jwt: dict[str, str], tenant_claim: object
) -> None:
    now = datetime.now(timezone.utc)
    claims = {"sub": "user-a", "roles": ["writer"], "iss": configured_jwt["issuer"], "aud": configured_jwt["audience"], "exp": now + timedelta(minutes=5)}
    if tenant_claim is not None:
        claims["tenant_id"] = tenant_claim
    token = jwt.encode(claims, configured_jwt["key"], algorithm="HS256")
    with pytest.raises(HTTPException) as error:
        authenticate_v4(_credentials(token))
    assert error.value.status_code == 401


@pytest.mark.parametrize("claim_name, value", [("iss", "wrong"), ("aud", "wrong")])
def test_v4_authentication_preserves_issuer_and_audience_validation(
    configured_jwt: dict[str, str], claim_name: str, value: str
) -> None:
    now = datetime.now(timezone.utc)
    claims = {"sub": "user-a", "roles": ["writer"], "tenant_id": "tenant-a", "iss": configured_jwt["issuer"], "aud": configured_jwt["audience"], "exp": now + timedelta(minutes=5)}
    claims[claim_name] = value
    token = jwt.encode(claims, configured_jwt["key"], algorithm="HS256")
    with pytest.raises(HTTPException) as error:
        authenticate_v4(_credentials(token))
    assert error.value.status_code == 401


def test_v4_authentication_rejects_invalid_signature_and_expiry(configured_jwt: dict[str, str]) -> None:
    now = datetime.now(timezone.utc)
    claims = {"sub": "user-a", "roles": ["writer"], "tenant_id": "tenant-a", "iss": configured_jwt["issuer"], "aud": configured_jwt["audience"], "exp": now - timedelta(minutes=1)}
    expired = jwt.encode(claims, configured_jwt["key"], algorithm="HS256")
    wrong_key = jwt.encode({**claims, "exp": now + timedelta(minutes=5)}, "other-signing-key-with-at-least-thirty-two-characters", algorithm="HS256")
    for token in (expired, wrong_key):
        with pytest.raises(HTTPException) as error:
            authenticate_v4(_credentials(token))
        assert error.value.status_code == 401


def test_active_and_inactive_tenant_membership(authorization_session: Session) -> None:
    _principal(authorization_session)
    assert active_tenant_principal(authorization_session, _identity()).subject == "user-a"
    authorization_session.scalar(select(TenantPrincipal)).active = False
    authorization_session.commit()
    with pytest.raises(AuthorizationDeniedError):
        active_tenant_principal(authorization_session, _identity())
    with pytest.raises(AuthorizationDeniedError):
        active_tenant_principal(authorization_session, _identity(subject="unknown"))


def test_authorization_models_are_not_registered_on_legacy_v3_metadata() -> None:
    """Task 36A cannot make current application startup create grant tables."""

    assert {"tenant_principals", "resource_grants", "tenant_permission_grants"}.isdisjoint(Base.metadata.tables)


def test_same_subject_has_independent_tenant_memberships(authorization_session: Session) -> None:
    _principal(authorization_session, "tenant-a", "user-a")
    _principal(authorization_session, "tenant-b", "user-a")
    assert active_tenant_principal(authorization_session, _identity("tenant-a")).tenant_id == "tenant-a"
    assert active_tenant_principal(authorization_session, _identity("tenant-b")).tenant_id == "tenant-b"


def test_resource_grants_require_an_exact_active_match(authorization_session: Session) -> None:
    principal = _principal(authorization_session)
    authorization_session.add(ResourceGrant(tenant_id="tenant-a", principal_id=principal.id, resource_type="customer_account", resource_id="account-1", permission=ResourcePermission.READ_EVENT.value, active=True))
    authorization_session.commit()
    require_resource_grant(authorization_session, _identity(), resource_type="customer_account", resource_id="account-1", permission=ResourcePermission.READ_EVENT)
    for kwargs in (
        {"resource_type": "customer_account", "resource_id": "account-2", "permission": ResourcePermission.READ_EVENT},
        {"resource_type": "other", "resource_id": "account-1", "permission": ResourcePermission.READ_EVENT},
        {"resource_type": "customer_account", "resource_id": "account-1", "permission": ResourcePermission.CREATE_EVENT},
    ):
        with pytest.raises(AuthorizationDeniedError):
            require_resource_grant(authorization_session, _identity(), **kwargs)
    authorization_session.scalar(select(ResourceGrant)).active = False
    authorization_session.commit()
    with pytest.raises(AuthorizationDeniedError):
        require_resource_grant(authorization_session, _identity(), resource_type="customer_account", resource_id="account-1", permission=ResourcePermission.READ_EVENT)


def test_resource_identifier_collision_is_isolated_by_tenant(authorization_session: Session) -> None:
    first = _principal(authorization_session, "tenant-a", "user-a")
    second = _principal(authorization_session, "tenant-b", "user-b")
    authorization_session.add_all([
        ResourceGrant(tenant_id="tenant-a", principal_id=first.id, resource_type="customer_account", resource_id="account-1", permission="READ_EVENT", active=True),
        ResourceGrant(tenant_id="tenant-b", principal_id=second.id, resource_type="customer_account", resource_id="account-1", permission="READ_EVENT", active=True),
    ])
    authorization_session.commit()
    assert authorized_resource_ids(authorization_session, _identity("tenant-a", "user-a"), resource_type="customer_account", permission="READ_EVENT") == frozenset({"account-1"})
    with pytest.raises(AuthorizationDeniedError):
        require_resource_grant(authorization_session, _identity("tenant-a", "user-b"), resource_type="customer_account", resource_id="account-1", permission="READ_EVENT")


def test_grant_foreign_key_prevents_cross_tenant_principal_binding(authorization_session: Session) -> None:
    principal = _principal(authorization_session, "tenant-a", "user-a")
    authorization_session.add(ResourceGrant(tenant_id="tenant-b", principal_id=principal.id, resource_type="customer_account", resource_id="account-1", permission="READ_EVENT", active=True))
    with pytest.raises(IntegrityError):
        authorization_session.commit()
    authorization_session.rollback()


def test_tenant_permissions_are_explicit_and_independent(authorization_session: Session) -> None:
    principal = _principal(authorization_session)
    authorization_session.add(ResourceGrant(tenant_id="tenant-a", principal_id=principal.id, resource_type="customer_account", resource_id="account-1", permission="EXPORT_RESOURCE", active=True))
    authorization_session.commit()
    with pytest.raises(AuthorizationDeniedError):
        require_tenant_grant(authorization_session, _identity(), permission=TenantPermission.EXPORT_TENANT_WITNESS)
    authorization_session.add(TenantPermissionGrant(tenant_id="tenant-a", principal_id=principal.id, permission="EXPORT_TENANT_WITNESS", active=True))
    authorization_session.commit()
    require_tenant_grant(authorization_session, _identity(), permission="EXPORT_TENANT_WITNESS")
    with pytest.raises(AuthorizationDeniedError):
        require_resource_grant(authorization_session, _identity(), resource_type="customer_account", resource_id="account-2", permission="EXPORT_RESOURCE")
    authorization_session.scalar(select(TenantPermissionGrant)).active = False
    authorization_session.commit()
    with pytest.raises(AuthorizationDeniedError):
        require_tenant_grant(authorization_session, _identity(), permission="EXPORT_TENANT_WITNESS")


def test_admin_role_does_not_bypass_missing_resource_grant(authorization_session: Session) -> None:
    _principal(authorization_session)
    admin = TenantAuthenticatedIdentity(subject="user-a", tenant_id="tenant-a", roles=frozenset({"admin"}))
    with pytest.raises(AuthorizationDeniedError):
        require_resource_grant(authorization_session, admin, resource_type="customer_account", resource_id="account-1", permission="READ_EVENT")


def test_invalid_and_duplicate_grants_are_rejected(authorization_session: Session) -> None:
    principal = _principal(authorization_session)
    with pytest.raises(ValueError):
        require_resource_grant(authorization_session, _identity(), resource_type="customer_account", resource_id="account-1", permission="VERIFY_TENANT_CHAIN")
    with pytest.raises(ValueError):
        grant_resource(authorization_session, "tenant-a", "user-a", "*", "account-1", "READ_EVENT")
    with pytest.raises(ValueError):
        require_tenant_grant(authorization_session, _identity(), permission="READ_EVENT")
    authorization_session.add(ResourceGrant(tenant_id="tenant-a", principal_id=principal.id, resource_type="customer_account", resource_id="account-1", permission="READ_EVENT", active=True))
    authorization_session.commit()
    authorization_session.add(ResourceGrant(tenant_id="tenant-a", principal_id=principal.id, resource_type="customer_account", resource_id="account-1", permission="READ_EVENT", active=True))
    with pytest.raises(IntegrityError):
        authorization_session.commit()
    authorization_session.rollback()


def test_grant_administration_provisions_revokes_and_deactivates(tmp_path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "grants.sqlite"
    assert grants_main(["--database", str(path), "principal-add", "--tenant", "tenant-a", "--subject", "user-a"]) == 0
    assert grants_main(["--database", str(path), "resource-grant", "--tenant", "tenant-a", "--subject", "user-a", "--resource-type", "customer_account", "--resource-id", "account-1", "--permission", "READ_EVENT"]) == 0
    assert grants_main(["--database", str(path), "tenant-grant", "--tenant", "tenant-a", "--subject", "user-a", "--permission", "VERIFY_TENANT_CHAIN"]) == 0
    assert grants_main(["--database", str(path), "resource-revoke", "--tenant", "tenant-a", "--subject", "user-a", "--resource-type", "customer_account", "--resource-id", "account-1", "--permission", "READ_EVENT"]) == 0
    assert grants_main(["--database", str(path), "principal-deactivate", "--tenant", "tenant-a", "--subject", "user-a"]) == 0
    assert grants_main(["--database", str(path), "list", "--tenant", "tenant-a", "--subject", "user-a"]) == 0
    assert "resource customer_account account-1 READ_EVENT active=False" in capsys.readouterr().out


def test_grant_cli_rejects_legacy_database_without_mutating_it(tmp_path) -> None:
    path = tmp_path / "legacy.sqlite"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE audit_events (id INTEGER PRIMARY KEY)")
    with pytest.raises(AuthorizationDatabaseError):
        authorization_engine(str(path))
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall() == [("audit_events",)]


def test_administration_helpers_are_transaction_owned(authorization_session: Session) -> None:
    provision_principal(authorization_session, "tenant-a", "user-a")
    authorization_session.rollback()
    assert authorization_session.scalar(select(TenantPrincipal)) is None
    provision_principal(authorization_session, "tenant-a", "user-a")
    authorization_session.commit()
    grant_resource(authorization_session, "tenant-a", "user-a", "customer_account", "account-1", "READ_EVENT")
    authorization_session.rollback()
    assert authorization_session.scalar(select(ResourceGrant)) is None
