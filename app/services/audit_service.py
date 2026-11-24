
"""Pure audit-event hashing primitives.

Database writes and predecessor selection intentionally belong to a later
service task. Keeping this module free of persistence concerns makes the
exact bytes covered by a content hash straightforward to test and explain.
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
