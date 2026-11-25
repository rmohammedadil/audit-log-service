"""Non-destructive audit-payload redaction overlays."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AuditEvent, AuditEventRedaction, utc_now
from app.services.audit_service import (
    AUDIT_REDACTION_APPLIED,
    REDACTION_REASON_CODES,
    RESERVED_LIFECYCLE_EVENT_TYPES,
    MAX_REDACTION_PATHS,
    AuditChainIntegrityError,
    append_lifecycle_audit_event,
    normalize_timestamp,
    pointers_overlap,
    validate_json_pointer,
    verify_audit_chain,
)


@dataclass(frozen=True)
class RedactionResult:
    target_event_id: int
    newly_redacted_paths: tuple[str, ...]
    action_event_id: int | None


class RedactionNotFoundError(ValueError):
    """Raised when the requested event does not exist."""


def validate_redaction_request(
    payload: dict, paths: list[str], reason: str
) -> tuple[str, ...]:
    """Validate all paths before a lifecycle event or metadata is written."""

    if type(reason) is not str or reason not in REDACTION_REASON_CODES:
        raise ValueError("redaction reason code is invalid")
    if not isinstance(paths, list) or not paths or len(paths) > MAX_REDACTION_PATHS:
        raise ValueError("redaction paths must contain between 1 and 50 entries")
    if any(type(path) is not str for path in paths) or len(set(paths)) != len(paths):
        raise ValueError("redaction paths must be unique strings")
    ordered_paths = tuple(sorted(paths))
    if pointers_overlap(ordered_paths):
        raise ValueError("overlapping redaction paths are not allowed")
    for path in ordered_paths:
        validate_json_pointer(payload, path)
    return ordered_paths


def redact_audit_event(
    session: Session,
    *,
    event_id: int,
    paths: list[str],
    reason: str,
    now: datetime | None = None,
) -> RedactionResult:
    """Create immutable redaction overlays and one matching chain action."""

    if type(event_id) is not int or event_id <= 0:
        raise ValueError("event_id must be a positive integer")
    verification = verify_audit_chain(session)
    if not verification.is_intact:
        raise AuditChainIntegrityError("redaction requires intact audit evidence")
    target = session.get(AuditEvent, event_id)
    if target is None:
        raise RedactionNotFoundError("audit event does not exist")
    if target.event_type in RESERVED_LIFECYCLE_EVENT_TYPES:
        raise ValueError("internal lifecycle events cannot be redacted")
    ordered_paths = validate_redaction_request(target.payload, paths, reason)
    existing = set(
        session.scalars(
            select(AuditEventRedaction.json_pointer).where(
                AuditEventRedaction.target_event_id == event_id
            )
        )
    )
    newly_redacted_paths = tuple(path for path in ordered_paths if path not in existing)
    if not newly_redacted_paths:
        return RedactionResult(event_id, (), None)
    timestamp = utc_now() if now is None else now
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("redaction timestamp must include timezone information")
    timestamp = timestamp.astimezone(timezone.utc)
    action = append_lifecycle_audit_event(
        session,
        event_type=AUDIT_REDACTION_APPLIED,
        actor_id="audit-redaction-service",
        resource_type="audit_event",
        resource_id=str(event_id),
        payload={
            "redactedAt": normalize_timestamp(timestamp),
            "redactedPathCount": len(newly_redacted_paths),
            "redactedPaths": list(newly_redacted_paths),
            "reason": reason,
            "targetEventId": event_id,
        },
        timestamp=timestamp,
    )
    session.add_all(
        [
            AuditEventRedaction(
                target_event_id=event_id,
                json_pointer=path,
                redacted_at=action.timestamp,
                redaction_reason=reason,
                redaction_action_event_id=action.id,
            )
            for path in newly_redacted_paths
        ]
    )
    session.flush()
    return RedactionResult(event_id, newly_redacted_paths, action.id)
