
"""Audit-event hashing, append, and query service operations.

Provides deterministic content hashing, hash-linked event creation,
and filtered, paginated retrieval. Transaction ownership remains
with the caller.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from json import JSONDecodeError
import re
from typing import Any

from sqlalchemy import String, cast, exists, func, select
from sqlalchemy.orm import Session

from app.models import (
    AuditChainState,
    AuditEvent,
    AuditEventArchive,
    AuditEventRedaction,
    utc_now,
)


GENESIS_HASH = "AUDIT_LOG_GENESIS_V1"
HASH_SCHEME_VERSION = "audit-chain-v1"
CHAIN_HASH_DOMAIN = "audit-log-chain-hash"
GENESIS_CHAIN_HASH = sha256(b"audit-log-chain-genesis-v1").hexdigest()
DEFAULT_QUERY_LIMIT = 100
MAX_QUERY_LIMIT = 1000
_DIGEST_PATTERN = re.compile(r"[0-9a-f]{64}")
_MAX_ARCHIVE_RETENTION_DAYS = 36_500
AUDIT_RETENTION_APPLIED = "AUDIT_RETENTION_APPLIED"
AUDIT_REDACTION_APPLIED = "AUDIT_REDACTION_APPLIED"
RESERVED_LIFECYCLE_EVENT_TYPES = frozenset(
    {AUDIT_RETENTION_APPLIED, AUDIT_REDACTION_APPLIED}
)

VIOLATION_CHECKPOINT_MISSING = "CHECKPOINT_MISSING"
VIOLATION_CONTENT_HASH_MISMATCH = "CONTENT_HASH_MISMATCH"
VIOLATION_PREVIOUS_HASH_MISMATCH = "PREVIOUS_HASH_MISMATCH"
VIOLATION_MALFORMED_EVENT_CONTENT = "MALFORMED_EVENT_CONTENT"
VIOLATION_MALFORMED_HASH = "MALFORMED_HASH"
VIOLATION_UNSUPPORTED_HASH_SCHEME = "UNSUPPORTED_HASH_SCHEME"
VIOLATION_PREVIOUS_CHAIN_HASH_MISMATCH = "PREVIOUS_CHAIN_HASH_MISMATCH"
VIOLATION_CHAIN_HASH_MISMATCH = "CHAIN_HASH_MISMATCH"
VIOLATION_CHECKPOINT_VERSION_MISMATCH = "CHECKPOINT_VERSION_MISMATCH"
VIOLATION_CHECKPOINT_COUNT_MISMATCH = "CHECKPOINT_COUNT_MISMATCH"
VIOLATION_CHECKPOINT_HEAD_ID_MISMATCH = "CHECKPOINT_HEAD_ID_MISMATCH"
VIOLATION_CHECKPOINT_HEAD_CHAIN_HASH_MISMATCH = "CHECKPOINT_HEAD_CHAIN_HASH_MISMATCH"
VIOLATION_ARCHIVE_MALFORMED_ACTION = "ARCHIVE_MALFORMED_ACTION"
VIOLATION_ARCHIVE_METADATA_MISMATCH = "ARCHIVE_METADATA_MISMATCH"
VIOLATION_REDACTION_MALFORMED_ACTION = "REDACTION_MALFORMED_ACTION"
VIOLATION_REDACTION_METADATA_MISMATCH = "REDACTION_METADATA_MISMATCH"
REDACTION_REASON_CODES = frozenset(
    {"SENSITIVE_DATA", "PRIVACY_REQUEST", "POLICY_REQUIREMENT"}
)
REDACTION_MARKER = "[REDACTED]"
MAX_REDACTION_PATHS = 50


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


class ReservedLifecycleEventTypeError(ValueError):
    """Raised when ordinary callers attempt to create an internal event type."""


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


def _validate_digest(value: object, field_name: str) -> str:
    """Require the lowercase SHA-256 representation used by chain evidence."""

    if not isinstance(value, str) or _DIGEST_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{field_name} must be a lowercase SHA-256 digest")
    return value


def canonicalize_chain_link(
    *,
    hash_scheme_version: str,
    content_hash: str,
    previous_chain_hash: str,
) -> bytes:
    """Serialize a domain-separated, versioned cryptographic chain link.

    The independent event-content hash contract is intentionally unchanged.
    Including the predecessor chain hash makes each chain digest depend on all
    earlier linked records without redefining what event content means.
    """

    if hash_scheme_version != HASH_SCHEME_VERSION:
        raise ValueError("unsupported hash scheme version")
    chain_link = {
        "contentHash": _validate_digest(content_hash, "content_hash"),
        "domain": CHAIN_HASH_DOMAIN,
        "hashSchemeVersion": hash_scheme_version,
        "previousChainHash": _validate_digest(
            previous_chain_hash, "previous_chain_hash"
        ),
    }
    canonical_json = json.dumps(
        chain_link,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return canonical_json.encode("utf-8")


def calculate_chain_hash(
    *,
    hash_scheme_version: str,
    content_hash: str,
    previous_chain_hash: str,
) -> str:
    """Return the lowercase SHA-256 digest for one linked chain record."""

    return sha256(
        canonicalize_chain_link(
            hash_scheme_version=hash_scheme_version,
            content_hash=content_hash,
            previous_chain_hash=previous_chain_hash,
        )
    ).hexdigest()


def append_audit_event(
    session: Session,
    *,
    event_type: str,
    actor_id: str,
    resource_type: str,
    resource_id: str,
    payload: dict[str, Any],
) -> AuditEvent:
    """Append one event and checkpoint update without committing.

    Tail validation is deliberately bounded. It prevents extending obviously
    corrupt tail evidence without claiming to replace full-chain verification.
    """

    if event_type in RESERVED_LIFECYCLE_EVENT_TYPES:
        raise ReservedLifecycleEventTypeError(
            "reserved lifecycle event types require the internal append path"
        )
    return _append_event(
        session,
        event_type=event_type,
        actor_id=actor_id,
        resource_type=resource_type,
        resource_id=resource_id,
        payload=payload,
        timestamp=None,
    )


def append_lifecycle_audit_event(
    session: Session,
    *,
    event_type: str,
    actor_id: str,
    resource_type: str,
    resource_id: str,
    payload: dict[str, Any],
    timestamp: datetime,
) -> AuditEvent:
    """Append a server-controlled lifecycle event through the normal chain.

    This narrow internal path exists so retention can bind the action event's
    server timestamp to metadata without allowing the public creation path to
    select lifecycle event types or timestamps.
    """

    if event_type not in RESERVED_LIFECYCLE_EVENT_TYPES:
        raise ValueError("internal append requires a reserved lifecycle event type")
    return _append_event(
        session,
        event_type=event_type,
        actor_id=actor_id,
        resource_type=resource_type,
        resource_id=resource_id,
        payload=payload,
        timestamp=timestamp,
    )


def _append_event(
    session: Session,
    *,
    event_type: str,
    actor_id: str,
    resource_type: str,
    resource_id: str,
    payload: dict[str, Any],
    timestamp: datetime | None,
) -> AuditEvent:
    """Perform the shared append/checkpoint operation without committing."""

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
    _validate_tail_integrity(session, latest_event)

    previous_hash = latest_event.content_hash if latest_event is not None else GENESIS_HASH
    previous_chain_hash = (
        latest_event.chain_hash if latest_event is not None else GENESIS_CHAIN_HASH
    )
    assigned_timestamp = utc_now() if timestamp is None else timestamp
    content_hash = calculate_content_hash(
        event_type=event_type,
        actor_id=actor_id,
        resource_type=resource_type,
        resource_id=resource_id,
        payload=payload,
        timestamp=assigned_timestamp,
    )
    chain_hash = calculate_chain_hash(
        hash_scheme_version=HASH_SCHEME_VERSION,
        content_hash=content_hash,
        previous_chain_hash=previous_chain_hash,
    )
    event = AuditEvent(
        event_type=event_type,
        actor_id=actor_id,
        resource_type=resource_type,
        resource_id=resource_id,
        payload=payload,
        timestamp=assigned_timestamp,
        previous_hash=previous_hash,
        content_hash=content_hash,
        hash_scheme_version=HASH_SCHEME_VERSION,
        previous_chain_hash=previous_chain_hash,
        chain_hash=chain_hash,
    )
    session.add(event)
    session.flush()

    if checkpoint is None:
        checkpoint = AuditChainState(
            hash_scheme_version=HASH_SCHEME_VERSION,
            event_count=1,
            head_event_id=event.id,
            head_chain_hash=event.chain_hash,
        )
        session.add(checkpoint)
    else:
        checkpoint.event_count = existing_event_count + 1
        checkpoint.head_event_id = event.id
        checkpoint.head_chain_hash = event.chain_hash
    session.flush()
    return event


def _validate_checkpoint_for_append(
    *,
    checkpoint: AuditChainState | None,
    event_count: int,
    latest_event: AuditEvent | None,
) -> None:
    """Refuse to extend an untrusted nonempty checkpoint without repairing it."""

    if checkpoint is None:
        if event_count:
            raise AuditChainIntegrityError(
                "checkpoint state missing for nonempty chain"
            )
        return

    if checkpoint.hash_scheme_version != HASH_SCHEME_VERSION:
        raise AuditChainIntegrityError("checkpoint hash scheme version is unsupported")
    if checkpoint.event_count != event_count:
        raise AuditChainIntegrityError(
            "checkpoint event count is inconsistent with audit events"
        )
    if event_count == 0:
        if checkpoint.head_event_id is not None or checkpoint.head_chain_hash is not None:
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
    if checkpoint.head_chain_hash != latest_event.chain_hash:
        raise AuditChainIntegrityError(
            "checkpoint head chain hash is inconsistent with audit events"
        )


def _validate_tail_integrity(session: Session, tail: AuditEvent | None) -> None:
    """Recalculate only the persisted tail before extending the chain."""

    if tail is None:
        return
    predecessor = session.scalar(
        select(AuditEvent)
        .where(AuditEvent.id < tail.id)
        .order_by(AuditEvent.id.desc())
        .limit(1)
    )
    expected_previous_hash = predecessor.content_hash if predecessor else GENESIS_HASH
    expected_previous_chain_hash = (
        predecessor.chain_hash if predecessor else GENESIS_CHAIN_HASH
    )
    try:
        if tail.hash_scheme_version != HASH_SCHEME_VERSION:
            raise ValueError("unsupported hash scheme version")
        recalculated_content_hash = calculate_content_hash(
            event_type=tail.event_type,
            actor_id=tail.actor_id,
            resource_type=tail.resource_type,
            resource_id=tail.resource_id,
            payload=tail.payload,
            timestamp=tail.timestamp,
        )
        recalculated_chain_hash = calculate_chain_hash(
            hash_scheme_version=tail.hash_scheme_version,
            content_hash=tail.content_hash,
            previous_chain_hash=tail.previous_chain_hash,
        )
    except (TypeError, ValueError, OverflowError) as error:
        raise AuditChainIntegrityError("tail evidence cannot be validated") from error
    if tail.content_hash != recalculated_content_hash:
        raise AuditChainIntegrityError("tail content hash is inconsistent with event content")
    if tail.previous_hash != expected_previous_hash:
        raise AuditChainIntegrityError("tail predecessor content hash is inconsistent")
    if tail.previous_chain_hash != expected_previous_chain_hash:
        raise AuditChainIntegrityError("tail predecessor chain hash is inconsistent")
    if tail.chain_hash != recalculated_chain_hash:
        raise AuditChainIntegrityError("tail chain hash is inconsistent")


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


def parse_json_pointer(pointer: str) -> tuple[str, ...]:
    """Parse a non-root RFC 6901 pointer without accepting invalid escapes."""

    if not isinstance(pointer, str) or not pointer or len(pointer) > 1024 or not pointer.startswith("/"):
        raise ValueError("JSON Pointer must be a non-root path of at most 1024 characters")
    parts: list[str] = []
    for raw_part in pointer[1:].split("/"):
        part = ""
        index = 0
        while index < len(raw_part):
            if raw_part[index] == "~":
                if index + 1 >= len(raw_part) or raw_part[index + 1] not in "01":
                    raise ValueError("JSON Pointer contains an invalid escape")
                part += "~" if raw_part[index + 1] == "0" else "/"
                index += 2
            else:
                part += raw_part[index]
                index += 1
        parts.append(part)
    return tuple(parts)


def _pointer_parent(payload: object, pointer: str) -> tuple[dict[str, Any] | list[Any], str]:
    """Locate a pointer parent and reject absent/object-vs-array ambiguity."""

    parts = parse_json_pointer(pointer)
    current = payload
    for part in parts[:-1]:
        if isinstance(current, dict):
            if part not in current:
                raise ValueError("JSON Pointer does not exist in payload")
            current = current[part]
        elif isinstance(current, list):
            if not part.isdigit() or (len(part) > 1 and part.startswith("0")):
                raise ValueError("JSON Pointer array index is invalid")
            index = int(part)
            if index >= len(current):
                raise ValueError("JSON Pointer array index is out of range")
            current = current[index]
        else:
            raise ValueError("JSON Pointer does not exist in payload")
    return current, parts[-1]


def validate_json_pointer(payload: dict[str, Any], pointer: str) -> None:
    """Validate a pointer against an original object payload without mutation."""

    parent, final = _pointer_parent(payload, pointer)
    if isinstance(parent, dict):
        if final not in parent:
            raise ValueError("JSON Pointer does not exist in payload")
    elif isinstance(parent, list):
        if final == "-" or not final.isdigit() or (len(final) > 1 and final.startswith("0")):
            raise ValueError("JSON Pointer array index is invalid")
        if int(final) >= len(parent):
            raise ValueError("JSON Pointer array index is out of range")
    else:
        raise ValueError("JSON Pointer does not exist in payload")


def pointers_overlap(pointers: list[str] | tuple[str, ...]) -> bool:
    """Reject ancestor/descendant masking because it has ambiguous evidence."""

    parsed = [parse_json_pointer(pointer) for pointer in pointers]
    return any(
        left != right and (left[: len(right)] == right or right[: len(left)] == left)
        for left in parsed
        for right in parsed
    )


def masked_payload(payload: dict[str, Any], pointers: list[str]) -> dict[str, Any]:
    """Return a deep-copied payload with validated paths replaced by a marker."""

    copied = json.loads(json.dumps(payload, ensure_ascii=False, allow_nan=False))
    for pointer in pointers:
        parent, final = _pointer_parent(copied, pointer)
        if isinstance(parent, dict):
            parent[final] = REDACTION_MARKER
        else:
            parent[int(final)] = REDACTION_MARKER
    return copied


def _parse_archive_action_payload(
    payload: dict[str, Any], action_timestamp: datetime
) -> tuple[tuple[int, ...], datetime, datetime]:
    """Validate the deterministic evidence emitted by retention execution."""

    expected_fields = {
        "archivedAt",
        "archivedEventCount",
        "archivedEventIds",
        "cutoff",
        "retentionDays",
    }
    if set(payload) != expected_fields:
        raise ValueError("archive action payload fields are invalid")
    target_ids = payload["archivedEventIds"]
    if not isinstance(target_ids, list) or not target_ids:
        raise ValueError("archive action targets are invalid")
    if any(type(target_id) is not int for target_id in target_ids):
        raise ValueError("archive action targets are invalid")
    if target_ids != sorted(target_ids) or len(set(target_ids)) != len(target_ids):
        raise ValueError("archive action targets are not deterministic")
    if (
        type(payload["archivedEventCount"]) is not int
        or payload["archivedEventCount"] != len(target_ids)
    ):
        raise ValueError("archive action count does not match targets")
    if (
        type(payload["retentionDays"]) is not int
        or not 0 < payload["retentionDays"] <= _MAX_ARCHIVE_RETENTION_DAYS
    ):
        raise ValueError("archive action retention duration is invalid")
    cutoff = _decode_persisted_timestamp(payload["cutoff"])
    archived_at = _decode_persisted_timestamp(payload["archivedAt"])
    if normalize_timestamp(archived_at) != normalize_timestamp(action_timestamp):
        raise ValueError("archive action timestamp is inconsistent")
    if cutoff != archived_at - timedelta(days=payload["retentionDays"]):
        raise ValueError("archive action cutoff is inconsistent with retention duration")
    return tuple(target_ids), cutoff, archived_at


def _verify_archive_metadata(
    events: list[Any], archives: list[Any], checked_record_count: int
) -> ChainVerificationResult | None:
    """Compare logical-archive rows with their chained action evidence.

    This runs only after the original event chain and checkpoint pass, so it
    cannot change established Scenario A precedence. It reads no ORM entities
    and never repairs inconsistent lifecycle evidence.
    """

    events_by_id = {event["id"]: event for event in events}
    declared_targets: dict[int, int] = {}
    for action in events:
        if action["event_type"] != AUDIT_RETENTION_APPLIED:
            continue
        try:
            payload = _decode_persisted_payload(action["payload_raw"])
            action_timestamp = _decode_persisted_timestamp(action["timestamp_raw"])
            target_ids, cutoff, archived_at = _parse_archive_action_payload(
                payload, action_timestamp
            )
        except (JSONDecodeError, TypeError, ValueError, UnicodeDecodeError, OverflowError):
            return _verification_failure(
                checked_record_count=checked_record_count,
                first_inconsistency_id=action["id"],
                violation_type=VIOLATION_ARCHIVE_MALFORMED_ACTION,
                detail="archival lifecycle action evidence is malformed",
            )
        for target_id in target_ids:
            target = events_by_id.get(target_id)
            if (
                target is None
                or target_id >= action["id"]
                or target["event_type"] in RESERVED_LIFECYCLE_EVENT_TYPES
            ):
                return _verification_failure(
                    checked_record_count=checked_record_count,
                    first_inconsistency_id=action["id"],
                    violation_type=VIOLATION_ARCHIVE_METADATA_MISMATCH,
                    detail="archival action declares an invalid target event",
                )
            try:
                target_timestamp = _decode_persisted_timestamp(target["timestamp_raw"])
            except (TypeError, ValueError, OverflowError):
                return _verification_failure(
                    checked_record_count=checked_record_count,
                    first_inconsistency_id=target_id,
                    violation_type=VIOLATION_ARCHIVE_METADATA_MISMATCH,
                    detail="archival target timestamp cannot be validated",
                )
            if target_timestamp >= cutoff or target_id in declared_targets:
                return _verification_failure(
                    checked_record_count=checked_record_count,
                    first_inconsistency_id=action["id"],
                    violation_type=VIOLATION_ARCHIVE_METADATA_MISMATCH,
                    detail="archival action declares inconsistent targets",
                )
            declared_targets[target_id] = action["id"]

    metadata_by_target: dict[int, Any] = {}
    for archive in archives:
        target_id = archive["target_event_id"]
        if target_id in metadata_by_target:
            return _verification_failure(
                checked_record_count=checked_record_count,
                first_inconsistency_id=archive["archive_action_event_id"],
                violation_type=VIOLATION_ARCHIVE_METADATA_MISMATCH,
                detail="duplicate archive metadata targets exist",
            )
        metadata_by_target[target_id] = archive
        expected_action_id = declared_targets.get(target_id)
        if expected_action_id != archive["archive_action_event_id"]:
            return _verification_failure(
                checked_record_count=checked_record_count,
                first_inconsistency_id=archive["archive_action_event_id"],
                violation_type=VIOLATION_ARCHIVE_METADATA_MISMATCH,
                detail="archive metadata does not match lifecycle action evidence",
            )
        action = events_by_id.get(expected_action_id)
        if action is None:
            return _verification_failure(
                checked_record_count=checked_record_count,
                first_inconsistency_id=target_id,
                violation_type=VIOLATION_ARCHIVE_METADATA_MISMATCH,
                detail="archive metadata references a missing lifecycle action",
            )
        try:
            payload = _decode_persisted_payload(action["payload_raw"])
            action_timestamp = _decode_persisted_timestamp(action["timestamp_raw"])
            _, _, archived_at = _parse_archive_action_payload(payload, action_timestamp)
            metadata_timestamp = _decode_persisted_timestamp(archive["archived_at_raw"])
        except (JSONDecodeError, TypeError, ValueError, UnicodeDecodeError, OverflowError):
            return _verification_failure(
                checked_record_count=checked_record_count,
                first_inconsistency_id=expected_action_id,
                violation_type=VIOLATION_ARCHIVE_METADATA_MISMATCH,
                detail="archive metadata timestamp cannot be validated",
            )
        if normalize_timestamp(metadata_timestamp) != normalize_timestamp(archived_at):
            return _verification_failure(
                checked_record_count=checked_record_count,
                first_inconsistency_id=expected_action_id,
                violation_type=VIOLATION_ARCHIVE_METADATA_MISMATCH,
                detail="archive metadata timestamp does not match lifecycle action",
            )

    for target_id, action_id in declared_targets.items():
        if target_id not in metadata_by_target:
            return _verification_failure(
                checked_record_count=checked_record_count,
                first_inconsistency_id=action_id,
                violation_type=VIOLATION_ARCHIVE_METADATA_MISMATCH,
                detail="lifecycle action is missing archive metadata",
            )
    return None


def _verify_redaction_metadata(
    events: list[Any], redactions: list[Any], checked_record_count: int
) -> ChainVerificationResult | None:
    """Validate redaction overlays against their chained action declarations."""

    events_by_id = {event["id"]: event for event in events}
    declared: dict[tuple[int, str], int] = {}
    for action in events:
        if action["event_type"] != AUDIT_REDACTION_APPLIED:
            continue
        try:
            payload = _decode_persisted_payload(action["payload_raw"])
            timestamp = _decode_persisted_timestamp(action["timestamp_raw"])
            fields = {"targetEventId", "redactedPaths", "redactedPathCount", "reason", "redactedAt"}
            if set(payload) != fields or type(payload["targetEventId"]) is not int:
                raise ValueError
            target = events_by_id.get(payload["targetEventId"])
            paths = payload["redactedPaths"]
            if (
                target is None
                or target["id"] >= action["id"]
                or target["event_type"] in RESERVED_LIFECYCLE_EVENT_TYPES
                or not isinstance(paths, list)
                or not paths
                or payload["redactedPathCount"] != len(paths)
                or payload["reason"] not in REDACTION_REASON_CODES
                or len(set(paths)) != len(paths)
                or paths != sorted(paths)
                or pointers_overlap(paths)
                or normalize_timestamp(_decode_persisted_timestamp(payload["redactedAt"])) != normalize_timestamp(timestamp)
            ):
                raise ValueError
            target_payload = _decode_persisted_payload(target["payload_raw"])
            for path in paths:
                validate_json_pointer(target_payload, path)
                key = (target["id"], path)
                if key in declared:
                    raise ValueError
                declared[key] = action["id"]
        except (TypeError, ValueError, JSONDecodeError, UnicodeDecodeError, OverflowError):
            return _verification_failure(
                checked_record_count=checked_record_count,
                first_inconsistency_id=action["id"],
                violation_type=VIOLATION_REDACTION_MALFORMED_ACTION,
                detail="redaction lifecycle action evidence is malformed",
            )
    seen: set[tuple[int, str]] = set()
    for metadata in redactions:
        key = (metadata["target_event_id"], metadata["json_pointer"])
        if key in seen or declared.get(key) != metadata["redaction_action_event_id"]:
            return _verification_failure(
                checked_record_count=checked_record_count,
                first_inconsistency_id=metadata["redaction_action_event_id"],
                violation_type=VIOLATION_REDACTION_METADATA_MISMATCH,
                detail="redaction metadata does not match lifecycle action evidence",
            )
        seen.add(key)
        action = events_by_id.get(metadata["redaction_action_event_id"])
        try:
            action_payload = _decode_persisted_payload(action["payload_raw"])
            action_timestamp = _decode_persisted_timestamp(action["timestamp_raw"])
            metadata_timestamp = _decode_persisted_timestamp(metadata["redacted_at_raw"])
            if (
                metadata["redaction_reason"] != action_payload["reason"]
                or normalize_timestamp(metadata_timestamp) != normalize_timestamp(action_timestamp)
            ):
                raise ValueError
        except (TypeError, ValueError, KeyError, JSONDecodeError, UnicodeDecodeError, OverflowError):
            return _verification_failure(
                checked_record_count=checked_record_count,
                first_inconsistency_id=metadata["redaction_action_event_id"],
                violation_type=VIOLATION_REDACTION_METADATA_MISMATCH,
                detail="redaction metadata timestamp or reason is inconsistent",
            )
    for key, action_id in declared.items():
        if key not in seen:
            return _verification_failure(
                checked_record_count=checked_record_count,
                first_inconsistency_id=action_id,
                violation_type=VIOLATION_REDACTION_METADATA_MISMATCH,
                detail="redaction lifecycle action is missing metadata",
            )
    return None


def verify_audit_chain(session: Session) -> ChainVerificationResult:
    """Verify persisted events and checkpoint state without changing either.

    Violation precedence is deterministic: ``CHECKPOINT_MISSING`` for a
    nonempty chain; then, by ascending ID, ``MALFORMED_EVENT_CONTENT``,
    ``UNSUPPORTED_HASH_SCHEME``, ``MALFORMED_HASH``,
    ``CONTENT_HASH_MISMATCH``, ``PREVIOUS_HASH_MISMATCH``,
    ``PREVIOUS_CHAIN_HASH_MISMATCH``, and ``CHAIN_HASH_MISMATCH``; finally
    checkpoint-only ``CHECKPOINT_VERSION_MISMATCH``,
    ``CHECKPOINT_COUNT_MISMATCH``, ``CHECKPOINT_HEAD_ID_MISMATCH``, and
    ``CHECKPOINT_HEAD_CHAIN_HASH_MISMATCH``. ``checked_record_count`` includes
    an event when that event is examined and fails. Database IDs are ordered
    but need not be consecutive.
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
        AuditEvent.hash_scheme_version,
        AuditEvent.previous_chain_hash,
        AuditEvent.chain_hash,
    ).order_by(AuditEvent.id.asc())
    checkpoint_statement = select(
        AuditChainState.hash_scheme_version,
        AuditChainState.event_count,
        AuditChainState.head_event_id,
        AuditChainState.head_chain_hash,
    ).where(AuditChainState.singleton_id == 1)
    archive_statement = select(
        AuditEventArchive.target_event_id,
        cast(AuditEventArchive.archived_at, String).label("archived_at_raw"),
        AuditEventArchive.archive_action_event_id,
    ).order_by(AuditEventArchive.target_event_id.asc())
    redaction_statement = select(
        AuditEventRedaction.target_event_id,
        AuditEventRedaction.json_pointer,
        cast(AuditEventRedaction.redacted_at, String).label("redacted_at_raw"),
        AuditEventRedaction.redaction_reason,
        AuditEventRedaction.redaction_action_event_id,
    ).order_by(AuditEventRedaction.target_event_id.asc(), AuditEventRedaction.json_pointer.asc())
    # Column mappings come from the database result, not the session's identity
    # map, and no_autoflush preserves unrelated local changes. Selecting raw
    # text keeps JSON/timestamp parsing under the per-event loop below, where a
    # malformed later row cannot mask an earlier verification failure. Database
    # execution errors intentionally propagate as operational failures.
    with session.no_autoflush:
        events = list(session.execute(event_statement).mappings())
        checkpoint = session.execute(checkpoint_statement).mappings().one_or_none()
        archives = list(session.execute(archive_statement).mappings())
        redactions = list(session.execute(redaction_statement).mappings())

    if events and checkpoint is None:
        return _verification_failure(
            checked_record_count=0,
            first_inconsistency_id=None,
            violation_type=VIOLATION_CHECKPOINT_MISSING,
            detail="nonempty audit chain has no trusted checkpoint state",
        )

    expected_previous_hash = GENESIS_HASH
    expected_previous_chain_hash = GENESIS_CHAIN_HASH
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
            )
        ):
            return _verification_failure(
                checked_record_count=checked_record_count,
                first_inconsistency_id=event["id"],
                violation_type=VIOLATION_MALFORMED_EVENT_CONTENT,
                detail="event content cannot be canonicalized for verification",
            )
        if event["hash_scheme_version"] != HASH_SCHEME_VERSION:
            return _verification_failure(
                checked_record_count=checked_record_count,
                first_inconsistency_id=event["id"],
                violation_type=VIOLATION_UNSUPPORTED_HASH_SCHEME,
                detail="event uses an unsupported hash scheme version",
            )
        try:
            _validate_digest(event["content_hash"], "content_hash")
            _validate_digest(event["previous_chain_hash"], "previous_chain_hash")
            _validate_digest(event["chain_hash"], "chain_hash")
            if event["previous_hash"] != GENESIS_HASH:
                _validate_digest(event["previous_hash"], "previous_hash")
        except ValueError:
            return _verification_failure(
                checked_record_count=checked_record_count,
                first_inconsistency_id=event["id"],
                violation_type=VIOLATION_MALFORMED_HASH,
                detail="event hash evidence is malformed",
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
                detail="stored predecessor content hash does not match the prior event",
            )
        if event["previous_chain_hash"] != expected_previous_chain_hash:
            return _verification_failure(
                checked_record_count=checked_record_count,
                first_inconsistency_id=event["id"],
                violation_type=VIOLATION_PREVIOUS_CHAIN_HASH_MISMATCH,
                detail="stored predecessor chain hash does not match the prior event",
            )
        try:
            recalculated_chain_hash = calculate_chain_hash(
                hash_scheme_version=event["hash_scheme_version"],
                content_hash=event["content_hash"],
                previous_chain_hash=event["previous_chain_hash"],
            )
        except ValueError:
            return _verification_failure(
                checked_record_count=checked_record_count,
                first_inconsistency_id=event["id"],
                violation_type=VIOLATION_MALFORMED_HASH,
                detail="event hash evidence is malformed",
            )
        if event["chain_hash"] != recalculated_chain_hash:
            return _verification_failure(
                checked_record_count=checked_record_count,
                first_inconsistency_id=event["id"],
                violation_type=VIOLATION_CHAIN_HASH_MISMATCH,
                detail="stored chain hash does not match linked event evidence",
            )
        expected_previous_hash = event["content_hash"]
        expected_previous_chain_hash = event["chain_hash"]

    actual_count = len(events)
    actual_head = events[-1] if events else None
    if checkpoint is None:
        archive_failure = _verify_archive_metadata(events, archives, actual_count)
        if archive_failure is not None:
            return archive_failure
        redaction_failure = _verify_redaction_metadata(events, redactions, actual_count)
        if redaction_failure is not None:
            return redaction_failure
        return ChainVerificationResult(
            is_intact=True,
            checked_record_count=0,
            first_inconsistency_id=None,
            violation_type=None,
            detail="empty audit chain has no checkpoint state yet",
        )
    if checkpoint["hash_scheme_version"] != HASH_SCHEME_VERSION:
        return _verification_failure(
            checked_record_count=actual_count,
            first_inconsistency_id=None,
            violation_type=VIOLATION_CHECKPOINT_VERSION_MISMATCH,
            detail="checkpoint uses an unsupported hash scheme version",
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
    expected_head_chain_hash = actual_head["chain_hash"] if actual_head else None
    if checkpoint["head_chain_hash"] != expected_head_chain_hash:
        return _verification_failure(
            checked_record_count=actual_count,
            first_inconsistency_id=None,
            violation_type=VIOLATION_CHECKPOINT_HEAD_CHAIN_HASH_MISMATCH,
            detail="checkpoint head chain hash does not match the persisted chain head",
        )
    archive_failure = _verify_archive_metadata(events, archives, actual_count)
    if archive_failure is not None:
        return archive_failure
    redaction_failure = _verify_redaction_metadata(events, redactions, actual_count)
    if redaction_failure is not None:
        return redaction_failure
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


def verify_lifecycle_metadata(session: Session) -> ChainVerificationResult:
    """Validate lifecycle overlays without hiding ordinary evidence tampering.

    Query projection uses this narrower read-only boundary: lifecycle metadata
    must be trustworthy before it can mask a response, while Task 12 callers
    can still inspect persisted strings when an unrelated content hash fails.
    """

    event_statement = select(
        AuditEvent.id,
        AuditEvent.event_type,
        cast(AuditEvent.payload, String).label("payload_raw"),
        cast(AuditEvent.timestamp, String).label("timestamp_raw"),
    ).order_by(AuditEvent.id.asc())
    archive_statement = select(
        AuditEventArchive.target_event_id,
        cast(AuditEventArchive.archived_at, String).label("archived_at_raw"),
        AuditEventArchive.archive_action_event_id,
    )
    redaction_statement = select(
        AuditEventRedaction.target_event_id,
        AuditEventRedaction.json_pointer,
        cast(AuditEventRedaction.redacted_at, String).label("redacted_at_raw"),
        AuditEventRedaction.redaction_reason,
        AuditEventRedaction.redaction_action_event_id,
    )
    with session.no_autoflush:
        events = list(session.execute(event_statement).mappings())
        archives = list(session.execute(archive_statement).mappings())
        redactions = list(session.execute(redaction_statement).mappings())
    failure = _verify_archive_metadata(events, archives, len(events))
    if failure is not None:
        return failure
    failure = _verify_redaction_metadata(events, redactions, len(events))
    if failure is not None:
        return failure
    return ChainVerificationResult(True, len(events), None, None, "lifecycle metadata is intact")


def query_audit_events(
    session: Session,
    *,
    actor_id: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    event_type: str | None = None,
    from_timestamp: datetime | None = None,
    to_timestamp: datetime | None = None,
    include_archived: bool = False,
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
    if type(include_archived) is not bool:
        raise ValueError("include_archived must be a boolean")
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

    lifecycle_result = verify_lifecycle_metadata(session)
    if not lifecycle_result.is_intact:
        raise AuditChainIntegrityError("lifecycle metadata cannot be trusted for retrieval")

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
    if not include_archived:
        # Keep archival filtering in SQL so pagination applies to visible rows.
        statement = statement.where(
            ~exists(
                select(AuditEventArchive.id).where(
                    AuditEventArchive.target_event_id == AuditEvent.id
                )
            )
        )

    statement = statement.order_by(AuditEvent.id.asc()).limit(limit).offset(offset)

    # Suppressing autoflush keeps this helper read-only even for caller sessions
    # that contain unrelated pending objects.
    with session.no_autoflush:
        return list(session.scalars(statement))
