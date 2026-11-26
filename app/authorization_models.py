"""Isolated V4 authorization metadata models.

These models deliberately use separate metadata.  Task 36A must not register
new tables on the V3 application ``Base`` because legacy startup currently
calls ``Base.metadata.create_all`` after V3 preflight.
"""

from __future__ import annotations

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from app.permissions import RESOURCE_PERMISSION_VALUES, TENANT_PERMISSION_VALUES


def _permission_check(column: str, values: frozenset[str]) -> str:
    """Build a static database check from the centralized permission allowlist."""

    quoted = ", ".join(f"'{value}'" for value in sorted(values))
    return f"{column} IN ({quoted})"


class AuthorizationBase(DeclarativeBase):
    """Metadata used only by the future V4 authorization database."""


class TenantPrincipal(AuthorizationBase):
    """A verified subject's active or inactive membership in one tenant."""

    __tablename__ = "tenant_principals"
    __table_args__ = (
        UniqueConstraint("tenant_id", "subject", name="uq_tenant_principal_subject"),
        # The composite unique key is the parent of tenant-bound grant FKs.
        UniqueConstraint("tenant_id", "id", name="uq_tenant_principal_tenant_id"),
        CheckConstraint("length(trim(tenant_id)) > 0", name="ck_tenant_principal_tenant_nonblank"),
        CheckConstraint("length(trim(subject)) > 0", name="ck_tenant_principal_subject_nonblank"),
        Index("ix_tenant_principals_tenant_subject_active", "tenant_id", "subject", "active"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    subject: Mapped[str] = mapped_column(String(256), nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class ResourceGrant(AuthorizationBase):
    """One explicit resource permission bound to its principal's tenant."""

    __tablename__ = "resource_grants"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "principal_id"],
            ["tenant_principals.tenant_id", "tenant_principals.id"],
            ondelete="RESTRICT",
            name="fk_resource_grant_tenant_principal",
        ),
        UniqueConstraint(
            "tenant_id", "principal_id", "resource_type", "resource_id", "permission",
            name="uq_resource_grant_exact_permission",
        ),
        CheckConstraint("length(trim(tenant_id)) > 0", name="ck_resource_grant_tenant_nonblank"),
        CheckConstraint("length(trim(resource_type)) > 0 AND resource_type <> '*'", name="ck_resource_grant_type_exact"),
        CheckConstraint("length(trim(resource_id)) > 0 AND resource_id <> '*'", name="ck_resource_grant_id_exact"),
        CheckConstraint(_permission_check("permission", RESOURCE_PERMISSION_VALUES), name="ck_resource_grant_permission"),
        Index("ix_resource_grants_scope", "tenant_id", "principal_id", "resource_type", "resource_id", "permission", "active"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    principal_id: Mapped[int] = mapped_column(Integer, nullable=False)
    resource_type: Mapped[str] = mapped_column(String(128), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(256), nullable=False)
    permission: Mapped[str] = mapped_column(String(64), nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class TenantPermissionGrant(AuthorizationBase):
    """One explicit tenant-wide permission; resource grants cannot imply it."""

    __tablename__ = "tenant_permission_grants"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "principal_id"],
            ["tenant_principals.tenant_id", "tenant_principals.id"],
            ondelete="RESTRICT",
            name="fk_tenant_permission_grant_principal",
        ),
        UniqueConstraint("tenant_id", "principal_id", "permission", name="uq_tenant_permission_grant"),
        CheckConstraint("length(trim(tenant_id)) > 0", name="ck_tenant_permission_grant_tenant_nonblank"),
        CheckConstraint(_permission_check("permission", TENANT_PERMISSION_VALUES), name="ck_tenant_permission_grant_permission"),
        Index("ix_tenant_permission_grants_scope", "tenant_id", "principal_id", "permission", "active"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    principal_id: Mapped[int] = mapped_column(Integer, nullable=False)
    permission: Mapped[str] = mapped_column(String(64), nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
