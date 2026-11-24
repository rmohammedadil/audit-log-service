"""Tests for deterministic audit-event content hashing."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import re

import pytest

from app.services.audit_service import (
    calculate_content_hash,
    canonicalize_event_content,
)


BASE_EVENT = {
    "event_type": "RECORD_UPDATED",
    "actor_id": "advisor-42",
    "resource_type": "client_account",
    "resource_id": "account-123",
    "payload": {"changed_fields": ["address"], "source": "portal"},
    "timestamp": datetime(2026, 11, 24, 9, 30, 0, 123456, tzinfo=timezone.utc),
}


def event_hash(event: dict) -> str:
    """Keep field variation tests focused on one deliberate change at a time."""

    return calculate_content_hash(**event)


def test_canonical_serialization_is_deterministic_and_normalizes_utc() -> None:
    equivalent_timestamp = datetime(
        2026,
        11,
        24,
        15,
        0,
        0,
        123456,
        tzinfo=timezone(timedelta(hours=5, minutes=30)),
    )
    equivalent_event = {**BASE_EVENT, "timestamp": equivalent_timestamp}

    canonical_content = canonicalize_event_content(**BASE_EVENT)

    assert canonical_content == canonicalize_event_content(**BASE_EVENT)
    assert canonical_content == canonicalize_event_content(**equivalent_event)
    assert b'"timestamp":"2026-11-24T09:30:00.123456Z"' in canonical_content


def test_payload_dictionary_key_order_does_not_change_hash() -> None:
    reordered_payload = {"source": "portal", "changed_fields": ["address"]}
    reordered_event = {**BASE_EVENT, "payload": reordered_payload}

    assert event_hash(BASE_EVENT) == event_hash(reordered_event)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("event_type", "PERMISSION_GRANTED"),
        ("actor_id", "advisor-43"),
        ("resource_type", "client_profile"),
        ("resource_id", "account-124"),
        ("payload", {"changed_fields": ["email"], "source": "portal"}),
        (
            "timestamp",
            datetime(2026, 11, 24, 9, 30, 1, 123456, tzinfo=timezone.utc),
        ),
    ],
)
def test_changing_each_hashed_field_changes_hash(field: str, replacement: object) -> None:
    changed_event = deepcopy(BASE_EVENT)
    changed_event[field] = replacement

    assert event_hash(BASE_EVENT) != event_hash(changed_event)


def test_content_hash_is_a_lowercase_sha256_hex_digest() -> None:
    content_hash = event_hash(BASE_EVENT)

    assert re.fullmatch(r"[0-9a-f]{64}", content_hash)
