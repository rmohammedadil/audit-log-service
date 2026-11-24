"""Integration tests for the audit-event write endpoint."""

from collections.abc import Generator
from datetime import datetime, timedelta, timezone
import logging
from pathlib import Path
import re

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from app.database import Base, get_db
from app.main import app
from app.models import AuditChainState, AuditEvent
from app.services.audit_service import (
    GENESIS_HASH,
    VIOLATION_CHECKPOINT_COUNT_MISMATCH,
    VIOLATION_CHECKPOINT_MISSING,
    VIOLATION_CONTENT_HASH_MISMATCH,
    VIOLATION_MALFORMED_EVENT_CONTENT,
    calculate_content_hash,
)


VALID_EVENT = {
    "eventType": "RECORD_UPDATED",
    "actorId": "advisor-42",
    "resourceType": "client_account",
    "resourceId": "account-123",
    "payload": {"changed_fields": ["address"]},
}


@pytest.fixture()
def api_client(
    tmp_path: Path,
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
    app.state.database_initializer = lambda: None
    app.dependency_overrides[get_db] = override_get_db

    try:
        with TestClient(app) as client:
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
            )
            for event in events
        ]
        checkpoint_evidence = (
            None
            if checkpoint is None
            else (
                checkpoint.event_count,
                checkpoint.head_event_id,
                checkpoint.head_content_hash,
            )
        )
    return event_evidence, checkpoint_evidence


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
    ["timestamp", "id", "previous_hash", "content_hash", "unexpected"],
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
