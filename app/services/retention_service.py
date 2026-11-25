"""Server-configured logical archival for retained audit evidence."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import os
import re

from sqlalchemy import exists, select
from sqlalchemy.orm import Session

from app.models import AuditEvent, AuditEventArchive, utc_now
from app.services.audit_service import (
    AUDIT_RETENTION_APPLIED,
    RESERVED_LIFECYCLE_EVENT_TYPES,
    AuditChainIntegrityError,
    append_lifecycle_audit_event,
    normalize_timestamp,
    verify_audit_chain,
)


DEFAULT_AUDIT_RETENTION_DAYS = 90
MAX_AUDIT_RETENTION_DAYS = 36_500
_POSITIVE_INTEGER = re.compile(r"[1-9][0-9]*")


class RetentionConfigurationError(ValueError):
    """Raised when an explicit retention configuration is unsafe or invalid."""


@dataclass(frozen=True)
class RetentionRunResult:
    """Outcome of one caller-owned logical archival transaction."""

    retention_days: int
    cutoff: datetime
    archived_event_ids: tuple[int, ...]
    action_event_id: int | None


def parse_retention_days(configured_value: str | None) -> int:
    """Return the documented default or a bounded explicit positive integer."""

    if configured_value is None:
        return DEFAULT_AUDIT_RETENTION_DAYS
    if not configured_value.strip():
        raise RetentionConfigurationError(
            "AUDIT_RETENTION_DAYS must not be empty or whitespace-only"
        )
    if _POSITIVE_INTEGER.fullmatch(configured_value) is None:
        raise RetentionConfigurationError(
            "AUDIT_RETENTION_DAYS must be a positive integer"
        )
    retention_days = int(configured_value)
    if retention_days > MAX_AUDIT_RETENTION_DAYS:
        raise RetentionConfigurationError(
            f"AUDIT_RETENTION_DAYS must not exceed {MAX_AUDIT_RETENTION_DAYS}"
        )
    return retention_days


def configured_retention_days() -> int:
    """Read the process policy without accepting caller-controlled overrides."""

    return parse_retention_days(os.environ.get("AUDIT_RETENTION_DAYS"))


def _normalized_now(now: datetime | None) -> datetime:
    """Use the service clock, while allowing deterministic internal tests."""

    current_time = utc_now() if now is None else now
    if current_time.tzinfo is None or current_time.utcoffset() is None:
        raise ValueError("retention current time must include timezone information")
    return current_time.astimezone(timezone.utc)


def run_retention(session: Session, *, now: datetime | None = None) -> RetentionRunResult:
    """Logically archive eligible business events without committing.

    A full read-only verification precedes every write. One internal action
    event records the exact cutoff, duration, target IDs, count, and timestamp
    used by every new metadata row. This makes the later verifier able to
    reconstruct the expected archive state without copying business payloads.
    """

    retention_days = configured_retention_days()
    action_timestamp = _normalized_now(now)
    cutoff = action_timestamp - timedelta(days=retention_days)

    verification = verify_audit_chain(session)
    if not verification.is_intact:
        raise AuditChainIntegrityError(
            "retention requires an intact audit chain and lifecycle metadata"
        )

    statement = (
        select(AuditEvent)
        .where(AuditEvent.timestamp < cutoff)
        .where(AuditEvent.event_type.not_in(RESERVED_LIFECYCLE_EVENT_TYPES))
        .where(
            ~exists(
                select(AuditEventArchive.id).where(
                    AuditEventArchive.target_event_id == AuditEvent.id
                )
            )
        )
        .order_by(AuditEvent.id.asc())
    )
    with session.no_autoflush:
        targets = list(session.scalars(statement))
    target_ids = tuple(event.id for event in targets)
    if not target_ids:
        return RetentionRunResult(
            retention_days=retention_days,
            cutoff=cutoff,
            archived_event_ids=(),
            action_event_id=None,
        )

    action_payload = {
        "archivedAt": normalize_timestamp(action_timestamp),
        "archivedEventCount": len(target_ids),
        "archivedEventIds": list(target_ids),
        "cutoff": normalize_timestamp(cutoff),
        "retentionDays": retention_days,
    }
    action_event = append_lifecycle_audit_event(
        session,
        event_type=AUDIT_RETENTION_APPLIED,
        actor_id="audit-retention-service",
        resource_type="audit_log",
        resource_id="configured-retention-policy",
        payload=action_payload,
        timestamp=action_timestamp,
    )
    session.add_all(
        [
            AuditEventArchive(
                target_event_id=target_id,
                archived_at=action_event.timestamp,
                archive_action_event_id=action_event.id,
            )
            for target_id in target_ids
        ]
    )
    # The caller owns commit/rollback; flushing makes the action and metadata
    # visible together in the current transaction without ending it.
    session.flush()
    return RetentionRunResult(
        retention_days=retention_days,
        cutoff=cutoff,
        archived_event_ids=target_ids,
        action_event_id=action_event.id,
    )
