
"""Audit-event hashing, append, and query service operations.

Provides deterministic content hashing, hash-linked event creation,
and filtered, paginated retrieval. Transaction ownership remains
with the caller.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
from json import JSONDecodeError
from typing import Any

from sqlalchemy import String, cast, func, select
from sqlalchemy.orm import Session

from app.models import AuditChainState, AuditEvent, utc_now


GENESIS_HASH = "AUDIT_LOG_GENESIS_V1"
DEFAULT_QUERY_LIMIT = 100
MAX_QUERY_LIMIT = 1000

VIOLATION_CHECKPOINT_MISSING = "CHECKPOINT_MISSING"
VIOLATION_CONTENT_HASH_MISMATCH = "CONTENT_HASH_MISMATCH"
VIOLATION_PREVIOUS_HASH_MISMATCH = "PREVIOUS_HASH_MISMATCH"
VIOLATION_MALFORMED_EVENT_CONTENT = "MALFORMED_EVENT_CONTENT"
VIOLATION_CHECKPOINT_COUNT_MISMATCH = "CHECKPOINT_COUNT_MISMATCH"
VIOLATION_CHECKPOINT_HEAD_ID_MISMATCH = "CHECKPOINT_HEAD_ID_MISMATCH"
VIOLATION_CHECKPOINT_HEAD_HASH_MISMATCH = "CHECKPOINT_HEAD_HASH_MISMATCH"


@dataclass(frozen=True)
class ChainVerificationResult:
    """A safe, structured explanation of the first detected inconsistency."""

    is_intact: bool
    checked_record_count: int
    first_inconsistency_id: int | None
    violation_type: str | None
    detail: str


class AuditChainIntegrityError(Exception):
    """Raised when an untrusted checkpoint prevents a safe chain append.

    This remains a domain exception in the service layer. HTTP status mapping
    belongs to the verification API task so non-HTTP callers retain the same
    transaction ownership and error semantics.
    """


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
    existing_event_count = session.scalar(
        select(func.count()).select_from(AuditEvent)
    ) or 0
    checkpoint = session.get(AuditChainState, 1)
    _validate_checkpoint_for_append(
        checkpoint=checkpoint,
        event_count=existing_event_count,
        latest_event=latest_event,
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

    if checkpoint is None:
        checkpoint = AuditChainState(
            event_count=1,
            head_event_id=event.id,
            head_content_hash=event.content_hash,
        )
        session.add(checkpoint)
    else:
        checkpoint.event_count = existing_event_count + 1
        checkpoint.head_event_id = event.id
        checkpoint.head_content_hash = event.content_hash
    # Flush the checkpoint with the event, but leave commit/rollback to callers.
    session.flush()
    return event


def _validate_checkpoint_for_append(
    *,
    checkpoint: AuditChainState | None,
    event_count: int,
    latest_event: AuditEvent | None,
) -> None:
    """Refuse to extend an untrusted nonempty chain without repairing it."""

    if checkpoint is None:
        if event_count:
            raise AuditChainIntegrityError(
                "checkpoint state missing for nonempty chain"
            )
        return

    if checkpoint.event_count != event_count:
        raise AuditChainIntegrityError(
            "checkpoint event count is inconsistent with audit events"
        )
    if event_count == 0:
        if checkpoint.head_event_id is not None or checkpoint.head_content_hash is not None:
            raise AuditChainIntegrityError(
                "empty checkpoint state must not contain a chain head"
            )
        return
    if latest_event is None:
        raise AuditChainIntegrityError("checkpoint has events but no audit-chain head")
    if checkpoint.head_event_id != latest_event.id:
        raise AuditChainIntegrityError(
            "checkpoint head ID is inconsistent with audit events"
        )
    if checkpoint.head_content_hash != latest_event.content_hash:
        raise AuditChainIntegrityError(
            "checkpoint head hash is inconsistent with audit events"
        )


def _verification_failure(
    *,
    checked_record_count: int,
    first_inconsistency_id: int | None,
    violation_type: str,
    detail: str,
) -> ChainVerificationResult:
    return ChainVerificationResult(
        is_intact=False,
        checked_record_count=checked_record_count,
        first_inconsistency_id=first_inconsistency_id,
        violation_type=violation_type,
        detail=detail,
    )


def _decode_persisted_payload(raw_payload: object) -> dict[str, Any]:
    """Decode one stored JSON object without involving ORM JSON coercion."""

    if not isinstance(raw_payload, str):
        raise ValueError("persisted payload is not JSON text")
    payload = json.loads(raw_payload)
    if not isinstance(payload, dict):
        raise ValueError("persisted payload is not a JSON object")
    return payload


def _decode_persisted_timestamp(raw_timestamp: object) -> datetime:
    """Recreate the documented SQLite UTC timestamp representation per row."""

    if isinstance(raw_timestamp, datetime):
        timestamp = raw_timestamp
    elif isinstance(raw_timestamp, str):
        timestamp = datetime.fromisoformat(raw_timestamp.replace("Z", "+00:00"))
    else:
        raise ValueError("persisted timestamp is not datetime text")

    # This mirrors UtcDateTime: SQLite stores service-origin timestamps as
    # UTC-naive text, which is restored as UTC only after successful parsing.
    if timestamp.tzinfo is None:
        return timestamp.replace(tzinfo=timezone.utc)
    return timestamp.astimezone(timezone.utc)


def verify_audit_chain(session: Session) -> ChainVerificationResult:
    """Verify persisted events and checkpoint state without changing either.

    Violation precedence is deterministic: missing checkpoint for a nonempty
    chain; then, by ascending ID, malformed content, content-hash mismatch,
    and predecessor mismatch; finally checkpoint count, head ID, and head hash
    mismatches. ``checked_record_count`` includes an event when that event is
    examined and fails. Database IDs are ordered but need not be consecutive.
    """

    event_statement = select(
        AuditEvent.id,
        AuditEvent.event_type,
        AuditEvent.actor_id,
        AuditEvent.resource_type,
        AuditEvent.resource_id,
        cast(AuditEvent.payload, String).label("payload_raw"),
        cast(AuditEvent.timestamp, String).label("timestamp_raw"),
        AuditEvent.previous_hash,
        AuditEvent.content_hash,
    ).order_by(AuditEvent.id.asc())
    checkpoint_statement = select(
        AuditChainState.event_count,
        AuditChainState.head_event_id,
        AuditChainState.head_content_hash,
    ).where(AuditChainState.singleton_id == 1)
    # Column mappings come from the database result, not the session's identity
    # map, and no_autoflush preserves unrelated local changes. Selecting raw
    # text keeps JSON/timestamp parsing under the per-event loop below, where a
    # malformed later row cannot mask an earlier verification failure. Database
    # execution errors intentionally propagate as operational failures.
    with session.no_autoflush:
        events = list(session.execute(event_statement).mappings())
        checkpoint = session.execute(checkpoint_statement).mappings().one_or_none()

    if events and checkpoint is None:
        return _verification_failure(
            checked_record_count=0,
            first_inconsistency_id=None,
            violation_type=VIOLATION_CHECKPOINT_MISSING,
            detail="nonempty audit chain has no trusted checkpoint state",
        )

    expected_previous_hash = GENESIS_HASH
    for checked_record_count, event in enumerate(events, start=1):
        try:
            payload = _decode_persisted_payload(event["payload_raw"])
            timestamp = _decode_persisted_timestamp(event["timestamp_raw"])
        except (JSONDecodeError, TypeError, ValueError, UnicodeDecodeError, OverflowError):
            return _verification_failure(
                checked_record_count=checked_record_count,
                first_inconsistency_id=event["id"],
                violation_type=VIOLATION_MALFORMED_EVENT_CONTENT,
                detail="event content cannot be canonicalized for verification",
            )
        if not all(
            isinstance(event[field], str)
            for field in (
                "event_type",
                "actor_id",
                "resource_type",
                "resource_id",
                "previous_hash",
                "content_hash",
            )
        ):
            return _verification_failure(
                checked_record_count=checked_record_count,
                first_inconsistency_id=event["id"],
                violation_type=VIOLATION_MALFORMED_EVENT_CONTENT,
                detail="event content cannot be canonicalized for verification",
            )
        try:
            recalculated_hash = calculate_content_hash(
                event_type=event["event_type"],
                actor_id=event["actor_id"],
                resource_type=event["resource_type"],
                resource_id=event["resource_id"],
                payload=payload,
                timestamp=timestamp,
            )
        except (TypeError, ValueError, OverflowError):
            return _verification_failure(
                checked_record_count=checked_record_count,
                first_inconsistency_id=event["id"],
                violation_type=VIOLATION_MALFORMED_EVENT_CONTENT,
                detail="event content cannot be canonicalized for verification",
            )
        if event["content_hash"] != recalculated_hash:
            return _verification_failure(
                checked_record_count=checked_record_count,
                first_inconsistency_id=event["id"],
                violation_type=VIOLATION_CONTENT_HASH_MISMATCH,
                detail="stored content hash does not match persisted event content",
            )
        if event["previous_hash"] != expected_previous_hash:
            return _verification_failure(
                checked_record_count=checked_record_count,
                first_inconsistency_id=event["id"],
                violation_type=VIOLATION_PREVIOUS_HASH_MISMATCH,
                detail="stored predecessor hash does not match the prior event",
            )
        expected_previous_hash = event["content_hash"]

    actual_count = len(events)
    actual_head = events[-1] if events else None
    if checkpoint is None:
        return ChainVerificationResult(
            is_intact=True,
            checked_record_count=0,
            first_inconsistency_id=None,
            violation_type=None,
            detail="empty audit chain has no checkpoint state yet",
        )
    if checkpoint["event_count"] != actual_count:
        return _verification_failure(
            checked_record_count=actual_count,
            first_inconsistency_id=None,
            violation_type=VIOLATION_CHECKPOINT_COUNT_MISMATCH,
            detail="checkpoint event count does not match persisted audit events",
        )
    expected_head_id = actual_head["id"] if actual_head else None
    if checkpoint["head_event_id"] != expected_head_id:
        return _verification_failure(
            checked_record_count=actual_count,
            first_inconsistency_id=None,
            violation_type=VIOLATION_CHECKPOINT_HEAD_ID_MISMATCH,
            detail="checkpoint head ID does not match the persisted chain head",
        )
    expected_head_hash = actual_head["content_hash"] if actual_head else None
    if checkpoint["head_content_hash"] != expected_head_hash:
        return _verification_failure(
            checked_record_count=actual_count,
            first_inconsistency_id=None,
            violation_type=VIOLATION_CHECKPOINT_HEAD_HASH_MISMATCH,
            detail="checkpoint head hash does not match the persisted chain head",
        )
    return ChainVerificationResult(
        is_intact=True,
        checked_record_count=actual_count,
        first_inconsistency_id=None,
        violation_type=None,
        detail="audit chain and checkpoint are intact",
    )


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

    # ``bool`` is a subclass of ``int`` in Python, so an exact type check is
    # needed to keep direct service callers from treating True as page size 1.
    if type(limit) is not int:
        raise ValueError("limit must be an integer")
    if type(offset) is not int:
        raise ValueError("offset must be an integer")
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
