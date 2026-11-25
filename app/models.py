
"""Database models for the audit log service."""

from datetime import datetime, timezone

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    JSON,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import TypeDecorator

from app.database import Base


def utc_now() -> datetime:
    """Return the server's current UTC timestamp for a new audit event."""

    return datetime.now(timezone.utc)


class UtcDateTime(TypeDecorator[datetime]):
    """Persist timezone-aware values as UTC and restore UTC on retrieval.

    SQLite stores ``DateTime`` values without timezone metadata, even when
    SQLAlchemy is configured with ``timezone=True``. The service invariant is
    that audit timestamps are UTC, so SQLite values are stored as UTC-naive
    text and re-attached to ``timezone.utc`` when read. This preserves the
    exact instant and microseconds required to reproduce a content hash.
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(
        self, value: datetime | None, dialect: object
    ) -> datetime | None:
        """Reject ambiguous values and normalize aware values before storage."""

        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must include timezone information")

        utc_value = value.astimezone(timezone.utc)
        if getattr(dialect, "name", None) == "sqlite":
            # SQLite cannot retain offset data, so persist UTC without it.
            return utc_value.replace(tzinfo=None)
        return utc_value

    def process_result_value(
        self, value: datetime | None, dialect: object
    ) -> datetime | None:
        """Restore the UTC invariant after SQLite returns a naive datetime."""

        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)


class AuditEvent(Base):
    """One immutable audit event with content and linked-chain evidence.

    ``previous_hash`` retains its original predecessor-content meaning. The
    separate chain fields make ordering cryptographically transitive without
    changing the canonical event-content hash contract.
    """

    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_type: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    actor_id: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    resource_type: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    resource_id: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(
        UtcDateTime(), nullable=False, default=utc_now, index=True
    )
    previous_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    hash_scheme_version: Mapped[str] = mapped_column(String(32), nullable=False)
    previous_chain_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    chain_hash: Mapped[str] = mapped_column(String(64), nullable=False)


class AuditEventArchive(Base):
    """Logical-archive metadata for one retained audit event.

    The target event remains untouched so its original content and linked
    hashes stay verifiable. ``archive_action_event_id`` will later identify a
    normal chained lifecycle event created in the same transaction; Task 15
    intentionally adds only the persistence foundation for that future rule.
    """

    __tablename__ = "audit_event_archives"
    __table_args__ = (
        UniqueConstraint(
            "target_event_id", name="uq_audit_event_archives_target_event"
        ),
        CheckConstraint(
            "target_event_id != archive_action_event_id",
            name="ck_audit_event_archives_distinct_action",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # Unique target rows make repeated archival idempotent at the database level.
    target_event_id: Mapped[int] = mapped_column(
        ForeignKey("audit_events.id", ondelete="RESTRICT"), nullable=False
    )
    archived_at: Mapped[datetime] = mapped_column(UtcDateTime(), nullable=False)
    archive_action_event_id: Mapped[int] = mapped_column(
        ForeignKey("audit_events.id", ondelete="RESTRICT"), nullable=False
    )


class AuditEventRedaction(Base):
    """Non-destructive JSON Pointer overlay metadata for one event payload.

    Original values are deliberately absent from this table. A future
    projection service will apply the canonical pointer only to a copied
    payload, while the stored event and its hashes remain original evidence.
    """

    __tablename__ = "audit_event_redactions"
    __table_args__ = (
        UniqueConstraint(
            "target_event_id",
            "json_pointer",
            name="uq_audit_event_redactions_target_pointer",
        ),
        CheckConstraint(
            "target_event_id != redaction_action_event_id",
            name="ck_audit_event_redactions_distinct_action",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_event_id: Mapped[int] = mapped_column(
        ForeignKey("audit_events.id", ondelete="RESTRICT"), nullable=False
    )
    # JSON Pointer syntax and path existence are future service-layer rules.
    json_pointer: Mapped[str] = mapped_column(String(1024), nullable=False)
    redacted_at: Mapped[datetime] = mapped_column(UtcDateTime(), nullable=False)
    redaction_reason: Mapped[str] = mapped_column(String(256), nullable=False)
    redaction_action_event_id: Mapped[int] = mapped_column(
        ForeignKey("audit_events.id", ondelete="RESTRICT"), nullable=False
    )


class AuditEventIdempotency(Base):
    """Writer-scoped replay mapping; request content is never stored here."""

    __tablename__ = "audit_event_idempotency"
    __table_args__ = (UniqueConstraint("writer_subject", "idempotency_key", name="uq_audit_event_idempotency_writer_key"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    writer_subject: Mapped[str] = mapped_column(String(256), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    request_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    event_id: Mapped[int] = mapped_column(ForeignKey("audit_events.id", ondelete="RESTRICT"), nullable=False, unique=True)


class AuditChainState(Base):
    """Singleton checkpoint for the expected end of the audit chain.

    Empty chains are valid with no state row before the first append, or with
    this row set to count zero and null head fields. Once events exist, the
    state must record their count, final event identity, and linked-chain head.
    This detects a deleted trailing event that predecessor references alone
    cannot reveal.
    """

    __tablename__ = "audit_chain_state"
    __table_args__ = (
        CheckConstraint("singleton_id = 1", name="ck_audit_chain_state_singleton"),
        CheckConstraint("event_count >= 0", name="ck_audit_chain_state_nonnegative"),
        CheckConstraint(
            "(event_count = 0 AND head_event_id IS NULL AND head_chain_hash IS NULL) "
            "OR (event_count > 0 AND head_event_id IS NOT NULL "
            "AND head_chain_hash IS NOT NULL)",
            name="ck_audit_chain_state_head_shape",
        ),
    )

    singleton_id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    hash_scheme_version: Mapped[str] = mapped_column(String(32), nullable=False)
    event_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    head_event_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    head_chain_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
