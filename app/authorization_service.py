"""Live, deny-by-default V4 authorization policy checks.

Task 36A exposes no HTTP integration.  Future routes must call these helpers
inside their existing transaction boundary rather than caching permissions.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth import TenantAuthenticatedIdentity
from app.authorization_models import ResourceGrant, TenantPermissionGrant, TenantPrincipal
from app.permissions import (
    ResourcePermission,
    TenantPermission,
    require_resource_permission,
    require_tenant_permission,
)


class AuthorizationDeniedError(PermissionError):
    """A deliberately non-disclosing authorization denial for future routes."""


@dataclass(frozen=True)
class ActiveTenantPrincipal:
    """The live membership record matched to a tenant-aware identity."""

    id: int
    tenant_id: str
    subject: str


def _exact_identifier(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip() or value == "*":
        raise ValueError(f"{name} must be an exact nonblank identifier")
    return value


def active_tenant_principal(
    session: Session, identity: TenantAuthenticatedIdentity
) -> ActiveTenantPrincipal:
    """Require the principal's current active tenant membership."""

    principal = session.scalar(
        select(TenantPrincipal).where(
            TenantPrincipal.tenant_id == identity.tenant_id,
            TenantPrincipal.subject == identity.subject,
            TenantPrincipal.active.is_(True),
        )
    )
    if principal is None:
        raise AuthorizationDeniedError("authorization denied")
    return ActiveTenantPrincipal(principal.id, principal.tenant_id, principal.subject)


def require_resource_grant(
    session: Session,
    identity: TenantAuthenticatedIdentity,
    *,
    resource_type: str,
    resource_id: str,
    permission: str | ResourcePermission,
) -> ActiveTenantPrincipal:
    """Require one active, exact resource grant; wildcards never match."""

    principal = active_tenant_principal(session, identity)
    resource_type = _exact_identifier(resource_type, "resource_type")
    resource_id = _exact_identifier(resource_id, "resource_id")
    permission = require_resource_permission(permission)
    grant = session.scalar(
        select(ResourceGrant.id).where(
            ResourceGrant.tenant_id == identity.tenant_id,
            ResourceGrant.principal_id == principal.id,
            ResourceGrant.resource_type == resource_type,
            ResourceGrant.resource_id == resource_id,
            ResourceGrant.permission == permission.value,
            ResourceGrant.active.is_(True),
        )
    )
    if grant is None:
        raise AuthorizationDeniedError("authorization denied")
    return principal


def require_tenant_grant(
    session: Session,
    identity: TenantAuthenticatedIdentity,
    *,
    permission: str | TenantPermission,
) -> ActiveTenantPrincipal:
    """Require an explicit tenant-wide permission, never implied by a role."""

    principal = active_tenant_principal(session, identity)
    permission = require_tenant_permission(permission)
    grant = session.scalar(
        select(TenantPermissionGrant.id).where(
            TenantPermissionGrant.tenant_id == identity.tenant_id,
            TenantPermissionGrant.principal_id == principal.id,
            TenantPermissionGrant.permission == permission.value,
            TenantPermissionGrant.active.is_(True),
        )
    )
    if grant is None:
        raise AuthorizationDeniedError("authorization denied")
    return principal


def authorized_resource_ids(
    session: Session,
    identity: TenantAuthenticatedIdentity,
    *,
    resource_type: str,
    permission: str | ResourcePermission,
) -> frozenset[str]:
    """Return the live exact resource scope for a future scoped query."""

    principal = active_tenant_principal(session, identity)
    resource_type = _exact_identifier(resource_type, "resource_type")
    permission = require_resource_permission(permission)
    resource_ids = session.scalars(
        select(ResourceGrant.resource_id).where(
            ResourceGrant.tenant_id == identity.tenant_id,
            ResourceGrant.principal_id == principal.id,
            ResourceGrant.resource_type == resource_type,
            ResourceGrant.permission == permission.value,
            ResourceGrant.active.is_(True),
        )
    )
    return frozenset(resource_ids)
