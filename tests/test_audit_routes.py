"""Integration tests for the audit-event write endpoint."""

from collections.abc import Generator
from datetime import datetime, timedelta, timezone
import logging
from pathlib import Path
import re

import pytest
import jwt
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.exc import OperationalError, SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from app.database import Base, get_db
from app.api import audit_routes
from app.main import app
from app.models import AuditChainState, AuditEvent, AuditEventArchive, AuditEventRedaction
from app.services import audit_service, retention_service
from app.services.audit_service import (
    GENESIS_CHAIN_HASH,
    GENESIS_HASH,
    HASH_SCHEME_VERSION,
    VIOLATION_CHECKPOINT_COUNT_MISMATCH,
    VIOLATION_CHECKPOINT_MISSING,
    VIOLATION_CONTENT_HASH_MISMATCH,
    VIOLATION_MALFORMED_EVENT_CONTENT,
    calculate_content_hash,
    append_audit_event,
)


VALID_EVENT = {
    "eventType": "RECORD_UPDATED",
    "actorId": "advisor-42",
    "resourceType": "client_account",
    "resourceId": "account-123",
    "payload": {"changed_fields": ["address"]},
}

EVIDENCE_STRING_FIELD_SPECS = [
    ("event_type", "eventType", 128),
    ("actor_id", "actorId", 256),
    ("resource_type", "resourceType", 128),
    ("resource_id", "resourceId", 256),
]


def persisted_string_value(case: str, maximum_length: int) -> str:
    """Return a direct-SQL modification value for evidence-preservation tests."""

    values = {
        "normal": "tampered-value",
        "leading": "  tampered-value",
        "trailing": "tampered-value  ",
        "surrounding": "  tampered-value  ",
        "whitespace": "   ",
        "empty": "",
        "overlength": "x" * (maximum_length + 1),
    }
    return values[case]


@pytest.fixture()
def api_client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[tuple[TestClient, sessionmaker[Session]], None, None]:
    """Run the API against a temporary database and override startup safely."""

    test_engine = create_engine(
        f"sqlite:///{tmp_path / 'audit-api-test.db'}",
        connect_args={"check_same_thread": False},
    )
    test_session_factory = sessionmaker(
        autocommit=False, autoflush=False, bind=test_engine
    )
    Base.metadata.create_all(test_engine)

    def override_get_db() -> Generator[Session, None, None]:
        database_session = test_session_factory()
        try:
            yield database_session
        finally:
            database_session.close()

    original_initializer = app.state.database_initializer
    monkeypatch.setenv("AUDIT_JWT_SIGNING_KEY", "test-signing-key-with-at-least-thirty-two-characters")
    monkeypatch.setenv("AUDIT_JWT_ISSUER", "audit-test")
    monkeypatch.setenv("AUDIT_JWT_AUDIENCE", "audit-api")
    app.state.database_initializer = lambda: None
    app.dependency_overrides[get_db] = override_get_db

    try:
        with TestClient(app) as client:
            from app.auth import create_development_token
            client.headers.update({"Authorization": f"Bearer {create_development_token('test-admin', ['admin', 'writer', 'auditor', 'regulator'])}"})
            yield client, test_session_factory
    finally:
        app.dependency_overrides.clear()
        app.state.database_initializer = original_initializer
        Base.metadata.drop_all(test_engine)
        test_engine.dispose()


def event_count(session_factory: sessionmaker[Session]) -> int:
    with session_factory() as database_session:
        return database_session.scalar(select(func.count()).select_from(AuditEvent)) or 0


def persisted_chain_evidence(
    session_factory: sessionmaker[Session],
) -> tuple[list[tuple], tuple | None]:
    """Capture persisted evidence so verification can be proven read-only."""

    with session_factory() as database_session:
        events = list(database_session.scalars(select(AuditEvent).order_by(AuditEvent.id)))
        checkpoint = database_session.get(AuditChainState, 1)
        event_evidence = [
            (
                event.id,
                event.event_type,
                event.actor_id,
                event.resource_type,
                event.resource_id,
                event.payload,
                event.timestamp,
                event.previous_hash,
                event.content_hash,
                event.hash_scheme_version,
                event.previous_chain_hash,
                event.chain_hash,
            )
            for event in events
        ]
        checkpoint_evidence = (
            None
            if checkpoint is None
            else (
                checkpoint.hash_scheme_version,
                checkpoint.event_count,
                checkpoint.head_event_id,
                checkpoint.head_chain_hash,
            )
        )
    return event_evidence, checkpoint_evidence


def test_retention_api_archives_and_hides_old_events(
    api_client: tuple[TestClient, sessionmaker[Session]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, session_factory = api_client
    monkeypatch.setenv("AUDIT_RETENTION_DAYS", "1")
    created = client.post("/audit/events", json=VALID_EVENT)
    assert created.status_code == 201
    future = datetime.now(timezone.utc) + timedelta(days=2)
    monkeypatch.setattr(
        audit_routes,
        "run_retention",
        lambda session: retention_service.run_retention(session, now=future),
    )

    response = client.post("/audit/retention/run")

    assert response.status_code == 200
    body = response.json()
    assert body["retentionDays"] == 1
    assert body["archivedEventIds"] == [created.json()["id"]]
    assert body["actionEventId"] is not None
    assert client.get("/audit/events").json() == [
        response for response in client.get("/audit/events").json()
        if response["eventType"] == "AUDIT_RETENTION_APPLIED"
    ]
    included = client.get("/audit/events?includeArchived=true")
    assert included.status_code == 200
    assert [event["id"] for event in included.json()] == [1, 2]
    with session_factory() as database_session:
        assert database_session.scalar(select(AuditEventArchive)) is not None


def test_retention_api_noop_and_rejects_client_policy_override(
    api_client: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, _ = api_client

    assert client.post("/audit/retention/run").json()["actionEventId"] is None
    override = client.post("/audit/retention/run", json={"retentionDays": 1})
    assert override.status_code == 422


def test_ordinary_api_rejects_reserved_lifecycle_event_type(
    api_client: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, _ = api_client

    response = client.post(
        "/audit/events", json={**VALID_EVENT, "eventType": " AUDIT_RETENTION_APPLIED "}
    )

    assert response.status_code == 422


def test_retention_api_rejects_corrupt_evidence_without_writes(
    api_client: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, session_factory = api_client
    created = client.post("/audit/events", json=VALID_EVENT)
    assert created.status_code == 201
    with session_factory() as database_session:
        database_session.execute(
            text("UPDATE audit_events SET payload = :payload WHERE id = :event_id"),
            {"payload": '{"tampered":true}', "event_id": created.json()["id"]},
        )
        database_session.commit()

    response = client.post("/audit/retention/run")

    assert response.status_code == 409
    with session_factory() as database_session:
        assert database_session.scalar(select(func.count()).select_from(AuditEvent)) == 1
        assert database_session.scalar(select(AuditEventArchive)) is None


def test_retention_api_returns_sanitized_operational_failure(
    api_client: tuple[TestClient, sessionmaker[Session]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _ = api_client

    def unavailable_retention(*args: object, **kwargs: object) -> object:
        raise OperationalError("INSERT", {}, RuntimeError("database unavailable"))

    monkeypatch.setattr(audit_routes, "run_retention", unavailable_retention)
    response = client.post("/audit/retention/run")

    assert response.status_code == 500
    assert response.json() == {"detail": "Unable to apply retention policy"}


def test_redaction_api_projects_payload_without_changing_hash_evidence(
    api_client: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, session_factory = api_client
    created = client.post(
        "/audit/events", json={**VALID_EVENT, "payload": {"profile": {"phone": "555", "name": "Ada"}}}
    )
    assert created.status_code == 201
    event_id = created.json()["id"]
    original_hash = created.json()["contentHash"]

    redacted = client.post(
        f"/audit/events/{event_id}/redact",
        json={"paths": ["/profile/phone"], "reason": "SENSITIVE_DATA"},
    )
    assert redacted.status_code == 200
    listed = client.get("/audit/events")
    business = next(event for event in listed.json() if event["id"] == event_id)
    assert business["payload"] == {"profile": {"phone": "[REDACTED]", "name": "Ada"}}
    assert business["redactedPaths"] == ["/profile/phone"]
    assert business["contentHash"] == original_hash
    with session_factory() as database_session:
        stored = database_session.get(AuditEvent, event_id)
        assert stored is not None and stored.payload["profile"]["phone"] == "555"


def test_query_fails_closed_when_redaction_metadata_is_tampered(
    api_client: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, session_factory = api_client
    created = client.post("/audit/events", json={**VALID_EVENT, "payload": {"secret": "value"}})
    event_id = created.json()["id"]
    assert client.post(
        f"/audit/events/{event_id}/redact",
        json={"paths": ["/secret"], "reason": "SENSITIVE_DATA"},
    ).status_code == 200
    with session_factory() as database_session:
        metadata = database_session.scalar(select(AuditEventRedaction))
        assert metadata is not None
        database_session.delete(metadata)
        database_session.commit()
    assert client.get("/audit/events").status_code == 409


def test_post_event_returns_created_event_and_persists_it(
    api_client: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, session_factory = api_client

    response = client.post("/audit/events", json=VALID_EVENT)

    assert response.status_code == 201
    body = response.json()
    assert body["id"] == 1
    assert body["eventType"] == "RECORD_UPDATED"
    assert body["actorId"] == "advisor-42"
    assert body["resourceType"] == "client_account"
    assert body["resourceId"] == "account-123"
    assert body["payload"] == {"changed_fields": ["address"]}
    assert body["timestamp"]
    assert body["previousHash"] == GENESIS_HASH
    assert re.fullmatch(r"[0-9a-f]{64}", body["contentHash"])
    assert body["hashSchemeVersion"] == HASH_SCHEME_VERSION
    assert body["previousChainHash"] == GENESIS_CHAIN_HASH
    assert re.fullmatch(r"[0-9a-f]{64}", body["chainHash"])
    assert event_count(session_factory) == 1


def test_two_api_writes_link_to_the_previous_content_hash(
    api_client: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, _ = api_client

    first_response = client.post("/audit/events", json=VALID_EVENT)
    second_response = client.post(
        "/audit/events",
        json={**VALID_EVENT, "eventType": "PERMISSION_GRANTED"},
    )

    assert first_response.status_code == 201
    assert second_response.status_code == 201
    assert second_response.json()["previousHash"] == first_response.json()["contentHash"]
    assert second_response.json()["previousChainHash"] == first_response.json()["chainHash"]


@pytest.mark.parametrize("field", VALID_EVENT)
def test_missing_required_fields_return_422_without_persistence(
    api_client: tuple[TestClient, sessionmaker[Session]], field: str
) -> None:
    client, session_factory = api_client
    invalid_event = {key: value for key, value in VALID_EVENT.items() if key != field}

    response = client.post("/audit/events", json=invalid_event)

    assert response.status_code == 422
    assert event_count(session_factory) == 0


@pytest.mark.parametrize(
    "invalid_event",
    [
        {**VALID_EVENT, "eventType": "   "},
        {**VALID_EVENT, "payload": []},
        {**VALID_EVENT, "payload": "not-an-object"},
    ],
)
def test_invalid_values_return_422_without_persistence(
    api_client: tuple[TestClient, sessionmaker[Session]], invalid_event: dict
) -> None:
    client, session_factory = api_client

    response = client.post("/audit/events", json=invalid_event)

    assert response.status_code == 422
    assert event_count(session_factory) == 0


@pytest.mark.parametrize(
    "server_owned_or_unexpected_field",
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
def test_server_owned_and_unexpected_fields_return_422_without_persistence(
    api_client: tuple[TestClient, sessionmaker[Session]],
    server_owned_or_unexpected_field: str,
) -> None:
    client, session_factory = api_client
    invalid_event = {**VALID_EVENT, server_owned_or_unexpected_field: "caller-value"}

    response = client.post("/audit/events", json=invalid_event)

    assert response.status_code == 422
    assert event_count(session_factory) == 0


def test_persistence_failure_rolls_back_and_returns_generic_server_error(
    api_client: tuple[TestClient, sessionmaker[Session]], monkeypatch: pytest.MonkeyPatch
) -> None:
    client, session_factory = api_client
    from app.api import audit_routes

    original_append = audit_routes.append_audit_event

    def fail_after_flush(*args: object, **kwargs: object) -> AuditEvent:
        original_append(*args, **kwargs)
        raise SQLAlchemyError("simulated persistence failure")

    monkeypatch.setattr(audit_routes, "append_audit_event", fail_after_flush)

    response = client.post("/audit/events", json=VALID_EVENT)

    assert response.status_code == 500
    assert response.json() == {"detail": "Unable to persist audit event"}
    assert event_count(session_factory) == 0


def test_reloaded_api_event_timestamp_reproduces_content_hash(
    api_client: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, session_factory = api_client

    response = client.post("/audit/events", json=VALID_EVENT)

    assert response.status_code == 201
    with session_factory() as database_session:
        stored_event = database_session.scalar(select(AuditEvent))

    assert stored_event is not None
    assert calculate_content_hash(
        event_type=stored_event.event_type,
        actor_id=stored_event.actor_id,
        resource_type=stored_event.resource_type,
        resource_id=stored_event.resource_id,
        payload=stored_event.payload,
        timestamp=stored_event.timestamp,
    ) == stored_event.content_hash


def create_query_fixture_events(client: TestClient) -> list[dict]:
    """Create distinct persisted events for public query-parameter tests."""

    event_inputs = [
        {
            "eventType": "USER_LOGIN",
            "actorId": "actor-a",
            "resourceType": "client_account",
            "resourceId": "account-1",
            "payload": {},
        },
        {
            "eventType": "RECORD_UPDATED",
            "actorId": "actor-b",
            "resourceType": "client_account",
            "resourceId": "account-2",
            "payload": {},
        },
        {
            "eventType": "USER_LOGIN",
            "actorId": "actor-a",
            "resourceType": "session",
            "resourceId": "session-1",
            "payload": {},
        },
        {
            "eventType": "PERMISSION_GRANTED",
            "actorId": "actor-b",
            "resourceType": "client_account",
            "resourceId": "account-1",
            "payload": {},
        },
    ]
    responses = [client.post("/audit/events", json=event) for event in event_inputs]

    assert all(response.status_code == 201 for response in responses)
    return [response.json() for response in responses]


def test_get_events_returns_camel_case_records_in_ascending_id_order(
    api_client: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, _ = api_client
    created_events = create_query_fixture_events(client)

    response = client.get("/audit/events")

    assert response.status_code == 200
    body = response.json()
    assert [event["id"] for event in body] == [event["id"] for event in created_events]
    assert body[0]["eventType"] == "USER_LOGIN"
    assert body[0]["previousHash"] == GENESIS_HASH
    assert "event_type" not in body[0]


@pytest.mark.parametrize(
    ("params", "expected_ids"),
    [
        ({"actorId": "actor-a"}, [1, 3]),
        ({"resourceType": "client_account"}, [1, 2, 4]),
        ({"resourceId": "account-1"}, [1, 4]),
        ({"eventType": "USER_LOGIN"}, [1, 3]),
        (
            {
                "actorId": "actor-b",
                "resourceType": "client_account",
                "resourceId": "account-1",
                "eventType": "PERMISSION_GRANTED",
            },
            [4],
        ),
    ],
)
def test_get_events_applies_public_filter_combinations(
    api_client: tuple[TestClient, sessionmaker[Session]],
    params: dict[str, str],
    expected_ids: list[int],
) -> None:
    client, _ = api_client
    create_query_fixture_events(client)

    response = client.get("/audit/events", params=params)

    assert response.status_code == 200
    assert [event["id"] for event in response.json()] == expected_ids


def test_get_events_uses_inclusive_utc_normalized_time_bounds(
    api_client: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, _ = api_client
    created_events = create_query_fixture_events(client)
    first_timestamp = datetime.fromisoformat(created_events[0]["timestamp"])
    india_time = timezone(timedelta(hours=5, minutes=30))
    normalized_timestamp = first_timestamp.astimezone(india_time).isoformat()

    response = client.get(
        "/audit/events",
        params={"from": normalized_timestamp, "to": normalized_timestamp},
    )

    assert response.status_code == 200
    assert [event["id"] for event in response.json()] == [created_events[0]["id"]]


def test_get_events_returns_empty_array_when_no_events_match(
    api_client: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, _ = api_client
    create_query_fixture_events(client)

    response = client.get("/audit/events", params={"actorId": "missing-actor"})

    assert response.status_code == 200
    assert response.json() == []


@pytest.mark.parametrize(
    "params",
    [
        {"actorId": "   "},
        {"actorId": "a" * 257},
        {"resourceType": "r" * 129},
        {"from": "2026-11-24T09:00:00"},
        {"from": "2026-11-24T12:00:00Z", "to": "2026-11-24T09:00:00Z"},
        {"limit": "1.5"},
        {"limit": "true"},
        {"limit": "0"},
        {"limit": "1001"},
        {"offset": "-1"},
        {"offset": "1.5"},
        {"offset": "true"},
    ],
)
def test_get_events_rejects_invalid_client_query_input(
    api_client: tuple[TestClient, sessionmaker[Session]], params: dict[str, str]
) -> None:
    client, session_factory = api_client
    created_events = create_query_fixture_events(client)

    response = client.get("/audit/events", params=params)

    assert response.status_code == 422
    assert event_count(session_factory) == len(created_events)


def test_get_events_does_not_modify_persisted_audit_evidence(
    api_client: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, session_factory = api_client
    created_events = create_query_fixture_events(client)

    with session_factory() as database_session:
        before = database_session.scalar(select(AuditEvent).where(AuditEvent.id == 1))
        assert before is not None
        evidence_before = (
            before.timestamp,
            before.previous_hash,
            before.content_hash,
        )

    response = client.get("/audit/events", params={"actorId": "actor-a"})

    assert response.status_code == 200
    with session_factory() as database_session:
        after = database_session.scalar(select(AuditEvent).where(AuditEvent.id == 1))
        assert after is not None
        evidence_after = (after.timestamp, after.previous_hash, after.content_hash)
    assert evidence_after == evidence_before
    assert event_count(session_factory) == len(created_events)


def test_get_events_returns_generic_error_when_database_read_fails(
    api_client: tuple[TestClient, sessionmaker[Session]], monkeypatch: pytest.MonkeyPatch
) -> None:
    client, session_factory = api_client
    created_events = create_query_fixture_events(client)
    from app.api import audit_routes

    def fail_query(*args: object, **kwargs: object) -> list[AuditEvent]:
        raise SQLAlchemyError("simulated database read failure")

    monkeypatch.setattr(audit_routes, "query_audit_events", fail_query)

    response = client.get("/audit/events")

    assert response.status_code == 500
    assert response.json() == {"detail": "Unable to retrieve audit events"}
    assert event_count(session_factory) == len(created_events)


def test_verify_returns_camel_case_result_for_an_empty_chain(
    api_client: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, _ = api_client

    response = client.get("/audit/verify")

    assert response.status_code == 200
    assert response.json() == {
        "isIntact": True,
        "checkedRecordCount": 0,
        "firstInconsistencyId": None,
        "violationType": None,
        "detail": "empty audit chain has no checkpoint state yet",
    }


def test_verify_returns_intact_camel_case_result_for_persisted_events(
    api_client: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, _ = api_client
    created_events = create_query_fixture_events(client)

    response = client.get("/audit/verify")

    assert response.status_code == 200
    body = response.json()
    assert body["isIntact"] is True
    assert body["checkedRecordCount"] == len(created_events)
    assert body["firstInconsistencyId"] is None
    assert body["violationType"] is None
    assert "is_intact" not in body


def test_verify_reports_direct_content_modification(
    api_client: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, session_factory = api_client
    created_events = create_query_fixture_events(client)

    with session_factory() as database_session:
        database_session.execute(
            text("UPDATE audit_events SET payload = :payload WHERE id = :event_id"),
            {"payload": '{"tampered":true}', "event_id": created_events[0]["id"]},
        )
        database_session.commit()

    response = client.get("/audit/verify")

    assert response.status_code == 200
    assert response.json() == {
        "isIntact": False,
        "checkedRecordCount": 1,
        "firstInconsistencyId": created_events[0]["id"],
        "violationType": VIOLATION_CONTENT_HASH_MISMATCH,
        "detail": "stored content hash does not match persisted event content",
    }


def test_verify_reports_trailing_deletion_as_checkpoint_inconsistency(
    api_client: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, session_factory = api_client
    created_events = create_query_fixture_events(client)

    with session_factory() as database_session:
        database_session.execute(
            text("DELETE FROM audit_events WHERE id = :event_id"),
            {"event_id": created_events[-1]["id"]},
        )
        database_session.commit()

    response = client.get("/audit/verify")

    assert response.status_code == 200
    assert response.json()["isIntact"] is False
    assert response.json()["checkedRecordCount"] == len(created_events) - 1
    assert response.json()["firstInconsistencyId"] is None
    assert response.json()["violationType"] == VIOLATION_CHECKPOINT_COUNT_MISMATCH


def test_verify_reports_missing_checkpoint_for_existing_events(
    api_client: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, session_factory = api_client
    create_query_fixture_events(client)

    with session_factory() as database_session:
        database_session.execute(text("DELETE FROM audit_chain_state WHERE singleton_id = 1"))
        database_session.commit()

    response = client.get("/audit/verify")

    assert response.status_code == 200
    assert response.json()["isIntact"] is False
    assert response.json()["checkedRecordCount"] == 0
    assert response.json()["firstInconsistencyId"] is None
    assert response.json()["violationType"] == VIOLATION_CHECKPOINT_MISSING


@pytest.mark.parametrize(
    ("column", "invalid_value"),
    [
        ("payload", "{not valid JSON"),
        ("timestamp", "not-a-timestamp"),
    ],
)
def test_verify_reports_malformed_persisted_values(
    api_client: tuple[TestClient, sessionmaker[Session]],
    column: str,
    invalid_value: str,
) -> None:
    client, session_factory = api_client
    created_events = create_query_fixture_events(client)

    # Values are intentionally corrupted through direct SQL to exercise the
    # verifier's persisted-evidence path rather than application validation.
    with session_factory() as database_session:
        database_session.execute(
            text(f"UPDATE audit_events SET {column} = :value WHERE id = :event_id"),
            {"value": invalid_value, "event_id": created_events[1]["id"]},
        )
        database_session.commit()

    response = client.get("/audit/verify")

    assert response.status_code == 200
    assert response.json()["isIntact"] is False
    assert response.json()["checkedRecordCount"] == 2
    assert response.json()["firstInconsistencyId"] == created_events[1]["id"]
    assert response.json()["violationType"] == VIOLATION_MALFORMED_EVENT_CONTENT


def test_verify_does_not_modify_persisted_events_or_checkpoint(
    api_client: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, session_factory = api_client
    create_query_fixture_events(client)
    evidence_before = persisted_chain_evidence(session_factory)

    response = client.get("/audit/verify")

    assert response.status_code == 200
    assert response.json()["isIntact"] is True
    assert persisted_chain_evidence(session_factory) == evidence_before


def test_blocked_append_returns_conflict_and_preserves_evidence(
    api_client: tuple[TestClient, sessionmaker[Session]], caplog: pytest.LogCaptureFixture
) -> None:
    client, session_factory = api_client
    first_response = client.post("/audit/events", json=VALID_EVENT)
    assert first_response.status_code == 201

    with session_factory() as database_session:
        database_session.execute(
            text("UPDATE audit_chain_state SET event_count = 99 WHERE singleton_id = 1")
        )
        database_session.commit()
    evidence_before = persisted_chain_evidence(session_factory)

    caplog.set_level(logging.WARNING, logger="app.api.audit_routes")
    response = client.post(
        "/audit/events",
        json={**VALID_EVENT, "eventType": "PERMISSION_GRANTED"},
    )

    assert response.status_code == 409
    assert response.json() == {
        "detail": "Audit chain integrity check failed; event was not appended"
    }
    assert persisted_chain_evidence(session_factory) == evidence_before
    assert "account-123" not in caplog.text


def test_verify_returns_sanitized_server_error_for_database_failure(
    api_client: tuple[TestClient, sessionmaker[Session]],
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    client, session_factory = api_client
    created_events = create_query_fixture_events(client)
    from app.api import audit_routes

    def fail_verification(*args: object, **kwargs: object) -> object:
        raise SQLAlchemyError("SELECT confidential database details")

    monkeypatch.setattr(audit_routes, "verify_audit_chain", fail_verification)
    caplog.set_level(logging.ERROR, logger="app.api.audit_routes")

    response = client.get("/audit/verify")

    assert response.status_code == 500
    assert response.json() == {"detail": "Unable to verify audit chain"}
    assert event_count(session_factory) == len(created_events)
    assert "confidential database details" not in caplog.text


@pytest.mark.parametrize(
    ("column_name", "public_name", "maximum_length"),
    EVIDENCE_STRING_FIELD_SPECS,
)
@pytest.mark.parametrize(
    "case",
    ["normal", "leading", "trailing", "surrounding", "whitespace", "empty", "overlength"],
)
def test_get_events_preserves_directly_modified_string_evidence(
    api_client: tuple[TestClient, sessionmaker[Session]],
    column_name: str,
    public_name: str,
    maximum_length: int,
    case: str,
) -> None:
    client, session_factory = api_client
    created_response = client.post("/audit/events", json=VALID_EVENT)
    assert created_response.status_code == 201
    created_event = created_response.json()
    tampered_value = persisted_string_value(case, maximum_length)

    # Column names come from the fixed parameter list above, never client input.
    with session_factory() as database_session:
        database_session.execute(
            text(f"UPDATE audit_events SET {column_name} = :value WHERE id = :event_id"),
            {"value": tampered_value, "event_id": created_event["id"]},
        )
        database_session.commit()
    evidence_before_get = persisted_chain_evidence(session_factory)

    get_response = client.get("/audit/events")

    assert get_response.status_code == 200
    returned_event = get_response.json()[0]
    assert returned_event[public_name] == tampered_value
    assert "event_type" not in returned_event
    assert returned_event["contentHash"] == created_event["contentHash"]
    assert returned_event["previousHash"] == created_event["previousHash"]
    assert persisted_chain_evidence(session_factory) == evidence_before_get

    verify_response = client.get("/audit/verify")

    assert verify_response.status_code == 200
    assert verify_response.json()["isIntact"] is False
    assert verify_response.json()["violationType"] == VIOLATION_CONTENT_HASH_MISMATCH
    assert verify_response.json()["firstInconsistencyId"] == created_event["id"]


def test_export_api_returns_verified_actor_bundle(
    api_client: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, _ = api_client
    first = client.post("/audit/events", json=VALID_EVENT)
    other = client.post("/audit/events", json={**VALID_EVENT, "actorId": "other-actor"})
    assert first.status_code == other.status_code == 201

    response = client.post("/audit/exports", json={"actorId": VALID_EVENT["actorId"]})
    assert response.status_code == 200
    bundle = response.json()
    assert [record["id"] for record in bundle["records"]] == [first.json()["id"]]
    assert [item["id"] for item in bundle["chainWitness"]] == [first.json()["id"], other.json()["id"]]
    assert bundle["bundleDigest"]


@pytest.mark.parametrize(
    "body",
    [{}, {"actorId": "actor", "resourceId": "resource"}, {"actorId": "   "}, {"unexpected": "field"}],
)
def test_export_api_rejects_invalid_selector_input(
    api_client: tuple[TestClient, sessionmaker[Session]], body: dict
) -> None:
    client, session_factory = api_client
    response = client.post("/audit/exports", json=body)
    assert response.status_code == 422
    assert event_count(session_factory) == 0


def access_event(account: str, actor: str, operation: str, outcome: str = "SUCCESS") -> dict:
    return {
        "eventType": "CLIENT_ACCOUNT_ACCESS",
        "actorId": actor,
        "resourceType": "customer_account",
        "resourceId": account,
        "payload": {"operation": operation, "outcome": outcome, "details": {"contact": "private@example.test"}},
    }


def test_access_report_filters_orders_paginates_and_masks_redaction(
    api_client: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, _ = api_client
    first = client.post("/audit/events", json=access_event("account-1", "advisor-a", "READ"))
    second = client.post("/audit/events", json=access_event("account-1", "advisor-a", "UPDATE", "DENIED"))
    client.post("/audit/events", json=VALID_EVENT)
    assert first.status_code == second.status_code == 201
    redaction = client.post(f"/audit/events/{first.json()['id']}/redact", json={"paths": ["/details/contact"], "reason": "SENSITIVE_DATA"})
    assert redaction.status_code == 200

    params = {"from": "2020-01-01T00:00:00Z", "to": "2030-01-01T00:00:00Z", "accountId": "account-1", "actorId": "advisor-a", "limit": 1}
    response = client.get("/audit/access-reports", params=params)
    assert response.status_code == 200
    assert response.json()[0]["id"] == first.json()["id"]
    assert response.json()[0]["operation"] == "READ"
    assert response.json()[0]["payload"]["details"]["contact"] == "[REDACTED]"
    next_page = client.get("/audit/access-reports", params={**params, "offset": 1, "operation": "UPDATE", "outcome": "DENIED"})
    assert [record["id"] for record in next_page.json()] == []


@pytest.mark.parametrize(
    "payload",
    [
        {**VALID_EVENT, "eventType": "CLIENT_ACCOUNT_ACCESS"},
        {**access_event("account-1", "actor", "READ"), "resourceType": "other"},
        {**access_event("account-1", "actor", "READ"), "payload": {"operation": "READ", "outcome": "MAYBE"}},
    ],
)
def test_access_event_contract_rejects_ambiguous_input(
    api_client: tuple[TestClient, sessionmaker[Session]], payload: dict
) -> None:
    client, _ = api_client
    assert client.post("/audit/events", json=payload).status_code == 422


@pytest.mark.parametrize(
    "params",
    [
        {"to": "2030-01-01T00:00:00Z"},
        {"from": "2026-01-01T00:00:00", "to": "2030-01-01T00:00:00Z"},
        {"from": "2030-01-01T00:00:00Z", "to": "2020-01-01T00:00:00Z"},
        {"from": "2020-01-01T00:00:00Z", "to": "2030-01-01T00:00:00Z", "operation": "PRINT"},
    ],
)
def test_access_report_rejects_invalid_requests(
    api_client: tuple[TestClient, sessionmaker[Session]], params: dict[str, str]
) -> None:
    client, _ = api_client
    assert client.get("/audit/access-reports", params=params).status_code == 422


def test_access_report_rejects_corrupt_source(
    api_client: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, session_factory = api_client
    created = client.post("/audit/events", json=access_event("account-1", "actor", "READ"))
    with session_factory() as database_session:
        database_session.execute(text("UPDATE audit_events SET payload = :payload WHERE id = :id"), {"payload": '{""bad"":true}', "id": created.json()["id"]})
        database_session.commit()
    response = client.get("/audit/access-reports", params={"from": "2020-01-01T00:00:00Z", "to": "2030-01-01T00:00:00Z"})
    assert response.status_code == 409


def test_access_report_includes_archived_records_by_default(
    api_client: tuple[TestClient, sessionmaker[Session]], monkeypatch: pytest.MonkeyPatch
) -> None:
    client, session_factory = api_client
    now = datetime(2026, 11, 25, tzinfo=timezone.utc)
    monkeypatch.setenv("AUDIT_RETENTION_DAYS", "30")
    monkeypatch.setattr(audit_service, "utc_now", lambda: now - timedelta(days=31))
    with session_factory() as database_session:
        event = append_audit_event(
            database_session, event_type="CLIENT_ACCOUNT_ACCESS", actor_id="archived-actor",
            resource_type="customer_account", resource_id="archived-account",
            payload={"operation": "READ", "outcome": "SUCCESS"},
        )
        event_id = event.id
        database_session.commit()
        retention_service.run_retention(database_session, now=now)
        database_session.commit()
    response = client.get("/audit/access-reports", params={
        "from": "2026-01-01T00:00:00Z", "to": "2026-12-31T00:00:00Z",
        "accountId": "archived-account",
    })
    assert response.status_code == 200
    assert [record["id"] for record in response.json()] == [event_id]


def role_token(role: str, **overrides: object) -> str:
    claims = {
        "sub": "test-user", "roles": [role], "iss": "audit-test", "aud": "audit-api",
        "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
    }
    claims.update(overrides)
    return jwt.encode(claims, "test-signing-key-with-at-least-thirty-two-characters", algorithm="HS256")


@pytest.mark.parametrize(
    "headers",
    [
        {"Authorization": ""},
        {"Authorization": "Bearer malformed"},
        {"Authorization": f"Bearer {role_token('auditor', exp=datetime.now(timezone.utc) - timedelta(minutes=1))}"},
        {"Authorization": f"Bearer {role_token('auditor', iss='wrong')}"},
        {"Authorization": f"Bearer {role_token('auditor', aud='wrong')}"},
        {"Authorization": f"Bearer {role_token('auditor', roles=['unknown'])}"},
    ],
)
def test_audit_endpoints_reject_invalid_tokens(
    api_client: tuple[TestClient, sessionmaker[Session]], headers: dict[str, str]
) -> None:
    client, session_factory = api_client
    response = client.get("/audit/events", headers=headers)
    assert response.status_code == 401
    assert event_count(session_factory) == 0


def test_rbac_enforces_role_matrix_and_rejects_unauthorized_writes(
    api_client: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, session_factory = api_client
    writer = {"Authorization": f"Bearer {role_token('writer')}"}
    auditor = {"Authorization": f"Bearer {role_token('auditor')}"}
    regulator = {"Authorization": f"Bearer {role_token('regulator')}"}
    assert client.post("/audit/events", json=VALID_EVENT, headers=writer).status_code == 201
    assert client.get("/audit/events", headers=writer).status_code == 403
    assert client.get("/audit/events", headers=auditor).status_code == 200
    assert client.get("/audit/verify", headers=regulator).status_code == 200
    assert client.post("/audit/exports", json={"actorId": "advisor-42"}, headers=regulator).status_code == 403
    rejected = client.post("/audit/events", json={**VALID_EVENT, "resourceId": "forbidden"}, headers=auditor)
    assert rejected.status_code == 403
    assert event_count(session_factory) == 1
