"""Tests for deterministic audit-event content hashing."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import re

import pytest

from app.services.audit_service import (
    CHAIN_HASH_DOMAIN,
    GENESIS_CHAIN_HASH,
    HASH_SCHEME_VERSION,
    calculate_chain_hash,
    calculate_content_hash,
    canonicalize_chain_link,
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


def test_chain_hash_fixed_vectors_and_canonical_encoding() -> None:
    """Lock the approved V2 genesis and three-record chain test vector."""

    first_content_hash = "6a88112332240d73d3414148f566d9e4dae4ede04fa7a73ec0c5de97fbc22260"
    second_content_hash = "979ee9065131e646692c48d6a7375aaf7839b34f19ab654e5ee70c106fc9a950"
    third_content_hash = "fab86758314bf23b95a23886e04bb70c64e448eddff28a27fec721e8b317df34"

    assert GENESIS_CHAIN_HASH == "94b2b6e724b970e59619f09368e52502b69328607d9dddccc304eb2e0ae30753"
    assert CHAIN_HASH_DOMAIN == "audit-log-chain-hash"
    assert HASH_SCHEME_VERSION == "audit-chain-v1"
    assert canonicalize_chain_link(
        hash_scheme_version=HASH_SCHEME_VERSION,
        content_hash=first_content_hash,
        previous_chain_hash=GENESIS_CHAIN_HASH,
    ) == (
        b'{"contentHash":"6a88112332240d73d3414148f566d9e4dae4ede04fa7a73ec0c5de97fbc22260",'
        b'"domain":"audit-log-chain-hash","hashSchemeVersion":"audit-chain-v1",'
        b'"previousChainHash":"94b2b6e724b970e59619f09368e52502b69328607d9dddccc304eb2e0ae30753"}'
    )
    first_chain_hash = calculate_chain_hash(
        hash_scheme_version=HASH_SCHEME_VERSION,
        content_hash=first_content_hash,
        previous_chain_hash=GENESIS_CHAIN_HASH,
    )
    second_chain_hash = calculate_chain_hash(
        hash_scheme_version=HASH_SCHEME_VERSION,
        content_hash=second_content_hash,
        previous_chain_hash=first_chain_hash,
    )
    third_chain_hash = calculate_chain_hash(
        hash_scheme_version=HASH_SCHEME_VERSION,
        content_hash=third_content_hash,
        previous_chain_hash=second_chain_hash,
    )

    assert first_chain_hash == "3ac182d576929f2ab1207198669c59c5516d05213dc36a095dab50337fa7d88c"
    assert second_chain_hash == "363745b4adc0e4ceb1cf9408ad94f72e1cec3e91f4fcf410ad852e9419b643a4"
    assert third_chain_hash == "e36a9da67fad20f72e2a2ce0f4188eb9f280a0057cdee19b1e79768fbd7d0359"


@pytest.mark.parametrize(
    ("version", "content_hash", "previous_chain_hash"),
    [
        ("unsupported", "a" * 64, "b" * 64),
        (HASH_SCHEME_VERSION, "A" * 64, "b" * 64),
        (HASH_SCHEME_VERSION, "a" * 63, "b" * 64),
        (HASH_SCHEME_VERSION, "a" * 64, "not-a-digest"),
    ],
)
def test_chain_hash_rejects_unsupported_or_malformed_inputs(
    version: str, content_hash: str, previous_chain_hash: str
) -> None:
    with pytest.raises(ValueError):
        calculate_chain_hash(
            hash_scheme_version=version,
            content_hash=content_hash,
            previous_chain_hash=previous_chain_hash,
        )
