"""Tests for the audit-event API validation contract."""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.models import AuditEvent
from app.schemas import AuditEventCreate, AuditEventRead


VALID_EVENT = {
    "eventType": "RECORD_UPDATED",
    "actorId": "advisor-42",
    "resourceType": "client_account",
    "resourceId": "account-123",
    "payload": {"changed_fields": ["address"]},
}

STRING_FIELD_SPECS = [
    ("eventType", "event_type", 128),
    ("actorId", "actor_id", 256),
    ("resourceType", "resource_type", 128),
    ("resourceId", "resource_id", 256),
]


def _persisted_string_value(case: str, maximum_length: int) -> str:
    """Return one direct-database evidence value for read-schema coverage."""

    values = {
        "normal": "stored-value",
        "leading": "  stored-value",
        "trailing": "stored-value  ",
        "surrounding": "  stored-value  ",
        "whitespace": "   ",
        "empty": "",
        "overlength": "x" * (maximum_length + 1),
    }
    return values[case]


def test_create_schema_parses_public_fields_into_python_names() -> None:
    event = AuditEventCreate.model_validate(VALID_EVENT)

    assert event.event_type == "RECORD_UPDATED"
    assert event.actor_id == "advisor-42"
    assert event.resource_type == "client_account"
    assert event.resource_id == "account-123"
    assert event.payload == {"changed_fields": ["address"]}
    assert event.model_dump(by_alias=True) == VALID_EVENT


def test_create_schema_rejects_normalized_reserved_lifecycle_event_type() -> None:
    with pytest.raises(ValidationError):
        AuditEventCreate.model_validate(
            {**VALID_EVENT, "eventType": " AUDIT_RETENTION_APPLIED "}
        )


@pytest.mark.parametrize(("public_name", "python_name", "maximum_length"), STRING_FIELD_SPECS)
def test_create_schema_trims_valid_string_fields(
    public_name: str, python_name: str, maximum_length: int
) -> None:
    event_input = {**VALID_EVENT, public_name: "  normalized-value  "}

    event = AuditEventCreate.model_validate(event_input)

    assert getattr(event, python_name) == "normalized-value"


@pytest.mark.parametrize(("public_name", "python_name", "maximum_length"), STRING_FIELD_SPECS)
def test_create_schema_accepts_values_at_string_limits(
    public_name: str, python_name: str, maximum_length: int
) -> None:
    event_input = {**VALID_EVENT, public_name: "x" * maximum_length}

    event = AuditEventCreate.model_validate(event_input)

    assert getattr(event, python_name) == "x" * maximum_length


@pytest.mark.parametrize(("public_name", "python_name", "maximum_length"), STRING_FIELD_SPECS)
def test_create_schema_rejects_empty_string_fields(
    public_name: str, python_name: str, maximum_length: int
) -> None:
    event_input = {**VALID_EVENT, public_name: ""}

    with pytest.raises(ValidationError):
        AuditEventCreate.model_validate(event_input)


@pytest.mark.parametrize("field", VALID_EVENT)
def test_create_schema_requires_each_client_field(field: str) -> None:
    incomplete_event = {key: value for key, value in VALID_EVENT.items() if key != field}

    with pytest.raises(ValidationError):
        AuditEventCreate.model_validate(incomplete_event)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("eventType", "   "),
        ("actorId", "   "),
        ("resourceType", "   "),
        ("resourceId", "   "),
        ("eventType", "a" * 129),
        ("actorId", "a" * 257),
        ("resourceType", "a" * 129),
        ("resourceId", "a" * 257),
    ],
)
def test_create_schema_rejects_blank_and_oversized_strings(field: str, value: str) -> None:
    invalid_event = {**VALID_EVENT, field: value}

    with pytest.raises(ValidationError):
        AuditEventCreate.model_validate(invalid_event)


@pytest.mark.parametrize("payload", [[], "not-an-object", 42, None])
def test_create_schema_requires_an_object_payload(payload: object) -> None:
    invalid_event = {**VALID_EVENT, "payload": payload}

    with pytest.raises(ValidationError):
        AuditEventCreate.model_validate(invalid_event)


@pytest.mark.parametrize(
    "server_owned_field",
    [
        "timestamp",
        "id",
        "previous_hash",
        "content_hash",
        "hashSchemeVersion",
        "previousChainHash",
        "chainHash",
        "unexpected",
    ],
)
def test_create_schema_rejects_server_owned_and_unexpected_fields(
    server_owned_field: str,
) -> None:
    invalid_event = {**VALID_EVENT, server_owned_field: "caller-value"}

    with pytest.raises(ValidationError):
        AuditEventCreate.model_validate(invalid_event)


def test_read_schema_serializes_model_with_public_field_names() -> None:
    model = AuditEvent(
        id=7,
        event_type="RECORD_UPDATED",
        actor_id="advisor-42",
        resource_type="client_account",
        resource_id="account-123",
        payload={"changed_fields": ["address"]},
        timestamp=datetime(2026, 11, 24, 9, 30, tzinfo=timezone.utc),
        previous_hash="AUDIT_LOG_GENESIS_V1",
        content_hash="a" * 64,
        hash_scheme_version="audit-chain-v1",
        previous_chain_hash="b" * 64,
        chain_hash="c" * 64,
    )

    event = AuditEventRead.model_validate(model)
    response = event.model_dump(by_alias=True)

    assert response["eventType"] == "RECORD_UPDATED"
    assert response["actorId"] == "advisor-42"
    assert response["resourceType"] == "client_account"
    assert response["resourceId"] == "account-123"
    assert response["previousHash"] == "AUDIT_LOG_GENESIS_V1"
    assert response["contentHash"] == "a" * 64
    assert response["hashSchemeVersion"] == "audit-chain-v1"
    assert response["previousChainHash"] == "b" * 64
    assert response["chainHash"] == "c" * 64
    assert "event_type" not in response
    assert "previous_hash" not in response


@pytest.mark.parametrize(("public_name", "python_name", "maximum_length"), STRING_FIELD_SPECS)
@pytest.mark.parametrize(
    "case",
    ["normal", "leading", "trailing", "surrounding", "whitespace", "empty", "overlength"],
)
def test_read_schema_preserves_persisted_string_evidence(
    public_name: str, python_name: str, maximum_length: int, case: str
) -> None:
    persisted_value = _persisted_string_value(case, maximum_length)
    model = AuditEvent(
        id=7,
        event_type="RECORD_UPDATED",
        actor_id="advisor-42",
        resource_type="client_account",
        resource_id="account-123",
        payload={"changed_fields": ["address"]},
        timestamp=datetime(2026, 11, 24, 9, 30, tzinfo=timezone.utc),
        previous_hash="AUDIT_LOG_GENESIS_V1",
        content_hash="a" * 64,
        hash_scheme_version="audit-chain-v1",
        previous_chain_hash="b" * 64,
        chain_hash="c" * 64,
    )
    setattr(model, python_name, persisted_value)

    response = AuditEventRead.model_validate(model).model_dump(by_alias=True)

    assert response[public_name] == persisted_value
