"""Trusted offline grant administration for an explicit complete V4 target.

This CLI never uses ``AUDIT_DB_PATH`` and cannot create authorization tables in
a legacy or partially upgraded audit database.
"""

from __future__ import annotations

import argparse
import sys

from sqlalchemy import Engine, select
from sqlalchemy.orm import Session

from app.authorization_models import ResourceGrant, TenantPermissionGrant, TenantPrincipal
from app.auth import validate_tenant_id
from app.permissions import ResourcePermission, TenantPermission, require_resource_permission, require_tenant_permission
from app.v4_database import IncompatibleV4DatabaseError, initialize_v4_database


class AuthorizationDatabaseError(ValueError):
    """Raised when an explicit offline grant target is unsafe or incompatible."""


def authorization_engine(path: str) -> Engine:
    """Open only a fresh or fully compatible V4 authorization target."""

    try:
        return initialize_v4_database(path)
    except IncompatibleV4DatabaseError as error:
        raise AuthorizationDatabaseError(str(error)) from error


def _principal(session: Session, tenant_id: str, subject: str) -> TenantPrincipal:
    principal = session.scalar(select(TenantPrincipal).where(TenantPrincipal.tenant_id == tenant_id, TenantPrincipal.subject == subject))
    if principal is None:
        raise AuthorizationDatabaseError("tenant principal does not exist")
    return principal


def _identifier(value: str, name: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip() or value == "*":
        raise AuthorizationDatabaseError(f"{name} must be an exact nonblank identifier")
    return value


def provision_principal(session: Session, tenant_id: str, subject: str) -> None:
    tenant_id = validate_tenant_id(tenant_id)
    subject = _identifier(subject, "subject")
    if session.scalar(select(TenantPrincipal.id).where(TenantPrincipal.tenant_id == tenant_id, TenantPrincipal.subject == subject)) is not None:
        raise AuthorizationDatabaseError("tenant principal already exists")
    session.add(TenantPrincipal(tenant_id=tenant_id, subject=subject, active=True))


def grant_resource(session: Session, tenant_id: str, subject: str, resource_type: str, resource_id: str, permission: str) -> None:
    tenant_id = validate_tenant_id(tenant_id)
    principal = _principal(session, tenant_id, _identifier(subject, "subject"))
    permission = require_resource_permission(permission)
    resource_type, resource_id = _identifier(resource_type, "resource type"), _identifier(resource_id, "resource ID")
    if session.scalar(select(ResourceGrant.id).where(ResourceGrant.tenant_id == tenant_id, ResourceGrant.principal_id == principal.id, ResourceGrant.resource_type == resource_type, ResourceGrant.resource_id == resource_id, ResourceGrant.permission == permission.value)) is not None:
        raise AuthorizationDatabaseError("resource grant already exists")
    session.add(ResourceGrant(tenant_id=tenant_id, principal_id=principal.id, resource_type=resource_type, resource_id=resource_id, permission=permission.value, active=True))


def grant_tenant(session: Session, tenant_id: str, subject: str, permission: str) -> None:
    tenant_id = validate_tenant_id(tenant_id)
    principal = _principal(session, tenant_id, _identifier(subject, "subject"))
    permission = require_tenant_permission(permission)
    if session.scalar(select(TenantPermissionGrant.id).where(TenantPermissionGrant.tenant_id == tenant_id, TenantPermissionGrant.principal_id == principal.id, TenantPermissionGrant.permission == permission.value)) is not None:
        raise AuthorizationDatabaseError("tenant permission grant already exists")
    session.add(TenantPermissionGrant(tenant_id=tenant_id, principal_id=principal.id, permission=permission.value, active=True))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Manage isolated V4 authorization grants")
    parser.add_argument("--database", required=True, help="explicit isolated authorization database path")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("principal-add", "principal-deactivate", "resource-grant", "resource-revoke", "tenant-grant", "tenant-revoke", "list"):
        command = commands.add_parser(name)
        command.add_argument("--tenant", required=True)
        command.add_argument("--subject", required=True)
        if name.startswith("resource-"):
            command.add_argument("--resource-type", required=True)
            command.add_argument("--resource-id", required=True)
            command.add_argument("--permission", required=True, choices=sorted(item.value for item in ResourcePermission))
        if name.startswith("tenant-"):
            command.add_argument("--permission", required=True, choices=sorted(item.value for item in TenantPermission))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        engine = authorization_engine(args.database)
        with Session(engine) as session:
            if args.command == "principal-add":
                provision_principal(session, args.tenant, args.subject)
            elif args.command == "principal-deactivate":
                _principal(session, validate_tenant_id(args.tenant), _identifier(args.subject, "subject")).active = False
            elif args.command == "resource-grant":
                grant_resource(session, args.tenant, args.subject, args.resource_type, args.resource_id, args.permission)
            elif args.command == "resource-revoke":
                grant = session.scalar(select(ResourceGrant).join(TenantPrincipal).where(TenantPrincipal.tenant_id == validate_tenant_id(args.tenant), TenantPrincipal.subject == _identifier(args.subject, "subject"), ResourceGrant.resource_type == _identifier(args.resource_type, "resource type"), ResourceGrant.resource_id == _identifier(args.resource_id, "resource ID"), ResourceGrant.permission == require_resource_permission(args.permission).value))
                if grant is None:
                    raise AuthorizationDatabaseError("resource grant does not exist")
                grant.active = False
            elif args.command == "tenant-grant":
                grant_tenant(session, args.tenant, args.subject, args.permission)
            elif args.command == "tenant-revoke":
                grant = session.scalar(select(TenantPermissionGrant).join(TenantPrincipal).where(TenantPrincipal.tenant_id == validate_tenant_id(args.tenant), TenantPrincipal.subject == _identifier(args.subject, "subject"), TenantPermissionGrant.permission == require_tenant_permission(args.permission).value))
                if grant is None:
                    raise AuthorizationDatabaseError("tenant permission grant does not exist")
                grant.active = False
            else:
                principal = _principal(session, validate_tenant_id(args.tenant), _identifier(args.subject, "subject"))
                for grant in session.scalars(select(ResourceGrant).where(ResourceGrant.principal_id == principal.id)):
                    print(f"resource {grant.resource_type} {grant.resource_id} {grant.permission} active={grant.active}")
                for grant in session.scalars(select(TenantPermissionGrant).where(TenantPermissionGrant.principal_id == principal.id)):
                    print(f"tenant {grant.permission} active={grant.active}")
                return 0
            session.commit()
        print("grant administration update completed")
        return 0
    except (AuthorizationDatabaseError, ValueError) as error:
        print(f"grant administration failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
