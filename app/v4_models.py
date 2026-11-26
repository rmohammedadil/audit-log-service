"""Fresh V4 tenant-scoped audit persistence models; never registered on V3 Base."""
from __future__ import annotations
from datetime import datetime

from sqlalchemy import CheckConstraint, Column, ForeignKeyConstraint, Integer, JSON, String, Table, UniqueConstraint, Index
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from app.models import UtcDateTime

class V4Base(DeclarativeBase):
    """Metadata isolated from the V3 application schema."""


# SQLAlchemy resolves string foreign keys within one metadata collection.  This
# non-mapped table declaration lets the V4 idempotency table reference the
# separately owned authorization table; ``AuthorizationBase.create_all`` runs
# first and owns its actual definition.
Table(
    "tenant_principals", V4Base.metadata,
    Column("tenant_id", String(128)), Column("subject", String(256)),
)

class V4SchemaState(V4Base):
    __tablename__ = "v4_schema_state"
    singleton_id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    schema_version: Mapped[str] = mapped_column(String(32), nullable=False)
    __table_args__ = (CheckConstraint("singleton_id = 1", name="ck_v4_schema_singleton"),)

class V4AuditEvent(V4Base):
    __tablename__ = "v4_audit_events"
    __table_args__ = (
        UniqueConstraint("tenant_id", "tenant_sequence", name="uq_v4_event_tenant_sequence"),
        UniqueConstraint("tenant_id", "id", name="uq_v4_event_tenant_internal"),
        UniqueConstraint("event_ref", name="uq_v4_event_ref"),
        CheckConstraint("tenant_sequence > 0", name="ck_v4_event_sequence_positive"),
        CheckConstraint("length(trim(tenant_id)) > 0", name="ck_v4_event_tenant_nonblank"),
        Index("ix_v4_event_tenant_resource", "tenant_id", "resource_type", "resource_id"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    event_ref: Mapped[str] = mapped_column(String(36), nullable=False)
    tenant_sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    event_type: Mapped[str] = mapped_column(String(128), nullable=False)
    actor_id: Mapped[str] = mapped_column(String(256), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(128), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(256), nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(UtcDateTime(), nullable=False)
    previous_content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    hash_scheme_version: Mapped[str] = mapped_column(String(32), nullable=False)
    previous_chain_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    chain_hash: Mapped[str] = mapped_column(String(64), nullable=False)

class V4TenantChainState(V4Base):
    __tablename__ = "v4_tenant_chain_state"
    __table_args__ = (CheckConstraint("event_count >= 0", name="ck_v4_state_count"), CheckConstraint("(event_count = 0 AND head_sequence IS NULL AND head_chain_hash IS NULL) OR (event_count > 0 AND head_sequence IS NOT NULL AND head_chain_hash IS NOT NULL)", name="ck_v4_state_shape"))
    tenant_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    hash_scheme_version: Mapped[str] = mapped_column(String(32), nullable=False)
    event_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    head_sequence: Mapped[int | None] = mapped_column(Integer)
    head_chain_hash: Mapped[str | None] = mapped_column(String(64))

class V4AuditEventArchive(V4Base):
    __tablename__ = "v4_audit_event_archives"
    __table_args__ = (ForeignKeyConstraint(["tenant_id","target_event_id"],["v4_audit_events.tenant_id","v4_audit_events.id"], ondelete="RESTRICT"), ForeignKeyConstraint(["tenant_id","archive_action_event_id"],["v4_audit_events.tenant_id","v4_audit_events.id"], ondelete="RESTRICT"), UniqueConstraint("tenant_id","target_event_id", name="uq_v4_archive_target"), CheckConstraint("target_event_id != archive_action_event_id", name="ck_v4_archive_distinct"))
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    target_event_id: Mapped[int] = mapped_column(Integer, nullable=False)
    archive_action_event_id: Mapped[int] = mapped_column(Integer, nullable=False)
    archived_at: Mapped[datetime] = mapped_column(UtcDateTime(), nullable=False)

class V4AuditEventRedaction(V4Base):
    __tablename__ = "v4_audit_event_redactions"
    __table_args__ = (ForeignKeyConstraint(["tenant_id","target_event_id"],["v4_audit_events.tenant_id","v4_audit_events.id"], ondelete="RESTRICT"), ForeignKeyConstraint(["tenant_id","redaction_action_event_id"],["v4_audit_events.tenant_id","v4_audit_events.id"], ondelete="RESTRICT"), UniqueConstraint("tenant_id","target_event_id","json_pointer", name="uq_v4_redaction_target_path"), CheckConstraint("target_event_id != redaction_action_event_id", name="ck_v4_redaction_distinct"))
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    target_event_id: Mapped[int] = mapped_column(Integer, nullable=False)
    json_pointer: Mapped[str] = mapped_column(String(1024), nullable=False)
    redaction_action_event_id: Mapped[int] = mapped_column(Integer, nullable=False)
    redacted_at: Mapped[datetime] = mapped_column(UtcDateTime(), nullable=False)
    redaction_reason: Mapped[str] = mapped_column(String(128), nullable=False)

class V4AuditEventIdempotency(V4Base):
    __tablename__ = "v4_audit_event_idempotency"
    __table_args__ = (ForeignKeyConstraint(["tenant_id","writer_subject"],["tenant_principals.tenant_id","tenant_principals.subject"], ondelete="RESTRICT"), ForeignKeyConstraint(["tenant_id","event_id"],["v4_audit_events.tenant_id","v4_audit_events.id"], ondelete="RESTRICT"), UniqueConstraint("tenant_id","writer_subject","idempotency_key", name="uq_v4_idempotency_key"), UniqueConstraint("tenant_id","event_id", name="uq_v4_idempotency_event"))
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    writer_subject: Mapped[str] = mapped_column(String(256), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    request_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    event_id: Mapped[int] = mapped_column(Integer, nullable=False)
