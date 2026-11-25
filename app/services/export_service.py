"""Self-contained audit export bundle construction.

Exports are a read-only view of an already verified source database.  They do
not claim that the bundle is an external trust anchor: the optional verifier
digest must be retained independently to provide that assurance.
"""

from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AuditChainState, AuditEvent, AuditEventArchive, AuditEventRedaction
from app.services.audit_service import (
    CHAIN_HASH_DOMAIN,
    GENESIS_CHAIN_HASH,
    GENESIS_HASH,
    HASH_SCHEME_VERSION,
    AuditChainIntegrityError,
    masked_payload,
    normalize_timestamp,
    verify_audit_chain,
)


BUNDLE_SCHEMA_VERSION = "audit-export-v1"


def canonical_bundle_bytes(bundle: dict[str, Any]) -> bytes:
    """Return deterministic UTF-8 JSON for the bundle digest.

    Callers remove ``bundleDigest`` before invoking this function.  Sorting and
    compact separators make the digest independent of pretty-printing or key
    insertion order.
    """

    return json.dumps(
        bundle, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def calculate_bundle_digest(bundle_without_digest: dict[str, Any]) -> str:
    return sha256(canonical_bundle_bytes(bundle_without_digest)).hexdigest()


def _event_record(event: AuditEvent, paths: list[str]) -> dict[str, Any]:
    """Project one selected record without exposing values hidden by overlays."""

    payload = masked_payload(event.payload, paths) if paths else event.payload
    return {
        "id": event.id,
        "eventType": event.event_type,
        "actorId": event.actor_id,
        "resourceType": event.resource_type,
        "resourceId": event.resource_id,
        "payload": payload,
        "timestamp": normalize_timestamp(event.timestamp),
        "previousHash": event.previous_hash,
        "contentHash": event.content_hash,
        "hashSchemeVersion": event.hash_scheme_version,
        "previousChainHash": event.previous_chain_hash,
        "chainHash": event.chain_hash,
        "redactedPaths": paths,
    }


def _witness_record(event: AuditEvent) -> dict[str, Any]:
    """Keep full chain evidence available without exporting unrelated payloads."""

    return {
        "id": event.id,
        "previousHash": event.previous_hash,
        "contentHash": event.content_hash,
        "hashSchemeVersion": event.hash_scheme_version,
        "previousChainHash": event.previous_chain_hash,
        "chainHash": event.chain_hash,
    }


def create_audit_export(
    session: Session,
    *,
    actor_id: str | None,
    resource_id: str | None,
    include_archived: bool,
    exported_at: datetime | None = None,
) -> dict[str, Any]:
    """Build a verified, read-only bundle for exactly one business selector."""

    if (actor_id is None) == (resource_id is None):
        raise ValueError("exactly one of actorId or resourceId is required")
    if type(include_archived) is not bool:
        raise ValueError("includeArchived must be a boolean")

    # Verification reads persisted values directly.  It must succeed before a
    # potentially misleading subset is released as an export.
    verification = verify_audit_chain(session)
    if not verification.is_intact:
        raise AuditChainIntegrityError("audit source integrity check failed")

    with session.no_autoflush:
        all_events = list(session.scalars(select(AuditEvent).order_by(AuditEvent.id.asc())))
        archives = list(session.scalars(select(AuditEventArchive)))
        redactions = list(session.scalars(select(AuditEventRedaction)))
        checkpoint = session.get(AuditChainState, 1)

    archived_ids = {archive.target_event_id for archive in archives}
    selected_events = [
        event
        for event in all_events
        if (event.actor_id == actor_id if actor_id is not None else event.resource_id == resource_id)
        and (include_archived or event.id not in archived_ids)
    ]
    paths_by_target: dict[int, list[str]] = {}
    for redaction in redactions:
        paths_by_target.setdefault(redaction.target_event_id, []).append(redaction.json_pointer)
    for paths in paths_by_target.values():
        paths.sort()

    selected_ids = {event.id for event in selected_events}
    archive_records = [
        {
            "targetEventId": archive.target_event_id,
            "archivedAt": normalize_timestamp(archive.archived_at),
            "archiveActionEventId": archive.archive_action_event_id,
        }
        for archive in archives
        if archive.target_event_id in selected_ids
    ]
    redaction_records = [
        {
            "targetEventId": redaction.target_event_id,
            "jsonPointer": redaction.json_pointer,
            "redactedAt": normalize_timestamp(redaction.redacted_at),
            "reason": redaction.redaction_reason,
            "redactionActionEventId": redaction.redaction_action_event_id,
        }
        for redaction in redactions
        if redaction.target_event_id in selected_ids
    ]
    archive_records.sort(key=lambda item: (item["targetEventId"], item["archiveActionEventId"]))
    redaction_records.sort(key=lambda item: (item["targetEventId"], item["jsonPointer"]))

    timestamp = datetime.now(timezone.utc) if exported_at is None else exported_at
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("export timestamp must include timezone information")
    if checkpoint is None:  # An intact empty chain may have no explicit row.
        checkpoint_snapshot: dict[str, Any] = {
            "hashSchemeVersion": HASH_SCHEME_VERSION,
            "eventCount": 0,
            "headEventId": None,
            "headChainHash": None,
        }
    else:
        checkpoint_snapshot = {
            "hashSchemeVersion": checkpoint.hash_scheme_version,
            "eventCount": checkpoint.event_count,
            "headEventId": checkpoint.head_event_id,
            "headChainHash": checkpoint.head_chain_hash,
        }
    selector = {"actorId": actor_id} if actor_id is not None else {"resourceId": resource_id}
    bundle: dict[str, Any] = {
        "bundleSchemaVersion": BUNDLE_SCHEMA_VERSION,
        "exportedAt": normalize_timestamp(timestamp),
        "selector": selector,
        "options": {"includeArchived": include_archived},
        "hashScheme": {
            "version": HASH_SCHEME_VERSION,
            "chainDomain": CHAIN_HASH_DOMAIN,
            "contentGenesis": GENESIS_HASH,
            "chainGenesis": GENESIS_CHAIN_HASH,
        },
        "records": [_event_record(event, paths_by_target.get(event.id, [])) for event in selected_events],
        "archives": archive_records,
        "redactions": redaction_records,
        "chainWitness": [_witness_record(event) for event in all_events],
        "checkpoint": checkpoint_snapshot,
    }
    bundle["bundleDigest"] = calculate_bundle_digest(bundle)
    return bundle
