
"""Audit-event hashing, append, and query service operations.

Provides deterministic content hashing, hash-linked event creation,
and filtered, paginated retrieval. Transaction ownership remains
with the caller.
"""

from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AuditEvent, utc_now


GENESIS_HASH = "AUDIT_LOG_GENESIS_V1"
DEFAULT_QUERY_LIMIT = 100
MAX_QUERY_LIMIT = 1000


def normalize_timestamp(timestamp: datetime) -> str:
    """Return an unambiguous, fixed-precision UTC representation.

    Naive datetimes are rejected rather than silently treating a local clock
    value as UTC. This prevents the same real-world event from hashing
    differently depending on the machine that constructs it.
    """

    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("timestamp must include timezone information")

    return (
        timestamp.astimezone(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def canonicalize_event_content(
    *,
    event_type: str,
    actor_id: str,
    resource_type: str,
    resource_id: str,
    payload: dict[str, Any],
    timestamp: datetime,
) -> bytes:
    """Serialize the immutable event content into the one hashable byte form.

    Field names mirror the public API contract. Sorted keys and compact JSON
    separators remove formatting and dictionary-insertion-order differences;
    UTF-8 preserves non-ASCII payload values consistently. ``previous_hash``
    is deliberately excluded because it is the separate link to the prior
    event, not part of this event's business content.
    """

    event_content = {
        "eventType": event_type,
        "actorId": actor_id,
        "resourceType": resource_type,
        "resourceId": resource_id,
        "payload": payload,
        "timestamp": normalize_timestamp(timestamp),
    }
    canonical_json = json.dumps(
        event_content,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return canonical_json.encode("utf-8")


def calculate_content_hash(
    *,
    event_type: str,
    actor_id: str,
    resource_type: str,
    resource_id: str,
    payload: dict[str, Any],
    timestamp: datetime,
) -> str:
    """Return the lowercase SHA-256 digest of canonical audit-event content."""

    canonical_content = canonicalize_event_content(
        event_type=event_type,
        actor_id=actor_id,
        resource_type=resource_type,
        resource_id=resource_id,
        payload=payload,
        timestamp=timestamp,
    )
    return sha256(canonical_content).hexdigest()


def append_audit_event(
    session: Session,
    *,
    event_type: str,
    actor_id: str,
    resource_type: str,
    resource_id: str,
    payload: dict[str, Any],
) -> AuditEvent:
    """Append one hash-linked event to the caller's active transaction.

    The timestamp is chosen here rather than accepted from a caller, ensuring
    the value used for persistence is also the value hashed. ``flush`` assigns
    the database ID and makes this event visible to a later append in the same
    transaction, while leaving commit or rollback under the caller's control.

    This prototype intentionally has no concurrent-writer coordination yet;
    a later production-oriented task must serialize tail selection and insert.
    """

    latest_event = session.scalar(
        select(AuditEvent).order_by(AuditEvent.id.desc()).limit(1)
    )
    previous_hash = (
        latest_event.content_hash if latest_event is not None else GENESIS_HASH
    )
    timestamp = utc_now()
    content_hash = calculate_content_hash(
        event_type=event_type,
        actor_id=actor_id,
        resource_type=resource_type,
        resource_id=resource_id,
        payload=payload,
        timestamp=timestamp,
    )

    event = AuditEvent(
        event_type=event_type,
        actor_id=actor_id,
        resource_type=resource_type,
        resource_id=resource_id,
        payload=payload,
        timestamp=timestamp,
        previous_hash=previous_hash,
        content_hash=content_hash,
    )
    session.add(event)
    session.flush()
    return event


def _normalize_query_timestamp(timestamp: datetime, parameter_name: str) -> datetime:
    """Reject ambiguous query bounds and compare all valid bounds in UTC."""

    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError(f"{parameter_name} must include timezone information")
    return timestamp.astimezone(timezone.utc)


def query_audit_events(
    session: Session,
    *,
    actor_id: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    event_type: str | None = None,
    from_timestamp: datetime | None = None,
    to_timestamp: datetime | None = None,
    limit: int = DEFAULT_QUERY_LIMIT,
    offset: int = 0,
) -> list[AuditEvent]:
    """Return matching audit events in deterministic order without mutations.

    SQLAlchemy builds parameterized predicates for each supplied filter. This
    keeps the filters composable with AND semantics and avoids manually built
    SQL. Filtering precedes ascending-ID pagination so equal inputs always
    produce the same page.
    """

    if not 1 <= limit <= MAX_QUERY_LIMIT:
        raise ValueError(f"limit must be between 1 and {MAX_QUERY_LIMIT}")
    if offset < 0:
        raise ValueError("offset must be greater than or equal to 0")

    normalized_from = (
        _normalize_query_timestamp(from_timestamp, "from_timestamp")
        if from_timestamp is not None
        else None
    )
    normalized_to = (
        _normalize_query_timestamp(to_timestamp, "to_timestamp")
        if to_timestamp is not None
        else None
    )
    if normalized_from is not None and normalized_to is not None:
        if normalized_from > normalized_to:
            raise ValueError("from_timestamp must not be after to_timestamp")

    statement = select(AuditEvent)
    if actor_id is not None:
        statement = statement.where(AuditEvent.actor_id == actor_id)
    if resource_type is not None:
        statement = statement.where(AuditEvent.resource_type == resource_type)
    if resource_id is not None:
        statement = statement.where(AuditEvent.resource_id == resource_id)
    if event_type is not None:
        statement = statement.where(AuditEvent.event_type == event_type)
    if normalized_from is not None:
        statement = statement.where(AuditEvent.timestamp >= normalized_from)
    if normalized_to is not None:
        statement = statement.where(AuditEvent.timestamp <= normalized_to)

    statement = statement.order_by(AuditEvent.id.asc()).limit(limit).offset(offset)

    # Suppressing autoflush keeps this helper read-only even for caller sessions
    # that contain unrelated pending objects.
    with session.no_autoflush:
        return list(session.scalars(statement))
