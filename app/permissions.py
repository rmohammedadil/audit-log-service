"""Central permission definitions for the future V4 authorization boundary."""

from __future__ import annotations

from enum import StrEnum


class ResourcePermission(StrEnum):
    """Permissions that apply to one exact tenant resource."""

    CREATE_EVENT = "CREATE_EVENT"
    READ_EVENT = "READ_EVENT"
    EXPORT_RESOURCE = "EXPORT_RESOURCE"
    REDACT_EVENT = "REDACT_EVENT"
    READ_ACCESS_REPORT = "READ_ACCESS_REPORT"


class TenantPermission(StrEnum):
    """Permissions that intentionally reveal or operate on tenant-wide state."""

    VERIFY_TENANT_CHAIN = "VERIFY_TENANT_CHAIN"
    EXPORT_TENANT_WITNESS = "EXPORT_TENANT_WITNESS"
    RUN_RETENTION = "RUN_RETENTION"


RESOURCE_PERMISSION_VALUES = frozenset(permission.value for permission in ResourcePermission)
TENANT_PERMISSION_VALUES = frozenset(permission.value for permission in TenantPermission)


def require_resource_permission(value: str | ResourcePermission) -> ResourcePermission:
    """Return an exact resource permission or reject unsupported values."""

    try:
        return ResourcePermission(value)
    except (TypeError, ValueError) as error:
        raise ValueError("unsupported resource permission") from error


def require_tenant_permission(value: str | TenantPermission) -> TenantPermission:
    """Return an exact tenant permission or reject unsupported values."""

    try:
        return TenantPermission(value)
    except (TypeError, ValueError) as error:
        raise ValueError("unsupported tenant permission") from error
