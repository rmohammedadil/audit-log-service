
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
