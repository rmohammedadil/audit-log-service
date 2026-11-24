"""Tests for service-level, append-only audit-event creation."""

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from app.database import Base
from app.models import AuditEvent
from app.services.audit_service import (
    GENESIS_HASH,
    append_audit_event,
    calculate_content_hash,
    query_audit_events,
)


@pytest.fixture()
def session() -> Session:
    """Provide an isolated database while preserving transaction behavior."""

    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)

    with Session(engine) as database_session:
        yield database_session

    Base.metadata.drop_all(engine)
    engine.dispose()


def append_login_event(session: Session) -> AuditEvent:
    """Create a representative event without duplicating test input data."""

    return append_audit_event(
        session,
        event_type="USER_LOGIN",
        actor_id="user-1",
        resource_type="session",
        resource_id="session-1",
        payload={"ip_address": "203.0.113.10"},
    )


def test_first_event_uses_genesis_hash_and_canonical_content_hash(
    session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    assigned_timestamp = datetime(2026, 11, 24, 9, 30, tzinfo=timezone.utc)
    monkeypatch.setattr("app.services.audit_service.utc_now", lambda: assigned_timestamp)

    event = append_login_event(session)

    assert event.id == 1
    assert event.timestamp == assigned_timestamp
    assert event.previous_hash == GENESIS_HASH
    assert event.content_hash == calculate_content_hash(
        event_type="USER_LOGIN",
        actor_id="user-1",
        resource_type="session",
        resource_id="session-1",
        payload={"ip_address": "203.0.113.10"},
        timestamp=assigned_timestamp,
    )


def test_second_event_references_the_first_event_content_hash(session: Session) -> None:
    first_event = append_login_event(session)
    second_event = append_audit_event(
        session,
        event_type="RECORD_UPDATED",
        actor_id="advisor-42",
        resource_type="client_account",
        resource_id="account-123",
        payload={"changed_fields": ["address"]},
    )

    assert second_event.id == first_event.id + 1
    assert second_event.previous_hash == first_event.content_hash


def test_append_uses_service_timestamp_and_does_not_accept_caller_timestamp(
    session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    assigned_timestamp = datetime(2026, 11, 24, 9, 30, tzinfo=timezone.utc)
    monkeypatch.setattr("app.services.audit_service.utc_now", lambda: assigned_timestamp)

    event = append_login_event(session)

    assert event.timestamp == assigned_timestamp
    with pytest.raises(TypeError, match="timestamp"):
        append_audit_event(
            session,
            event_type="USER_LOGIN",
            actor_id="user-1",
            resource_type="session",
            resource_id="session-2",
            payload={},
            timestamp=datetime(2020, 1, 1, tzinfo=timezone.utc),
        )


def test_append_flushes_without_committing(session: Session) -> None:
    event = append_login_event(session)

    assert event.id is not None
    session.rollback()

    persisted_count = session.scalar(select(func.count()).select_from(AuditEvent))
    assert persisted_count == 0


@pytest.fixture()
def seeded_events(session: Session) -> list[AuditEvent]:
    """Persist varied records so query tests exercise independent filters."""

    timestamps = [
        datetime(2026, 11, 24, 9, 0, tzinfo=timezone.utc),
        datetime(2026, 11, 24, 10, 0, tzinfo=timezone.utc),
        datetime(2026, 11, 24, 11, 0, tzinfo=timezone.utc),
        datetime(2026, 11, 24, 12, 0, tzinfo=timezone.utc),
    ]
    events = [
        AuditEvent(
            event_type="USER_LOGIN",
            actor_id="actor-a",
            resource_type="client_account",
            resource_id="account-1",
            payload={},
            timestamp=timestamps[0],
            previous_hash="AUDIT_LOG_GENESIS_V1",
            content_hash="a" * 64,
        ),
        AuditEvent(
            event_type="RECORD_UPDATED",
            actor_id="actor-b",
            resource_type="client_account",
            resource_id="account-2",
            payload={},
            timestamp=timestamps[1],
            previous_hash="a" * 64,
            content_hash="b" * 64,
        ),
        AuditEvent(
            event_type="USER_LOGIN",
            actor_id="actor-a",
            resource_type="session",
            resource_id="session-1",
            payload={},
            timestamp=timestamps[2],
            previous_hash="b" * 64,
            content_hash="c" * 64,
        ),
        AuditEvent(
            event_type="PERMISSION_GRANTED",
            actor_id="actor-b",
            resource_type="client_account",
            resource_id="account-1",
            payload={},
            timestamp=timestamps[3],
            previous_hash="c" * 64,
            content_hash="d" * 64,
        ),
    ]
    session.add_all(events)
    session.commit()
    return events


def event_ids(events: list[AuditEvent]) -> list[int]:
    return [event.id for event in events]


def test_query_without_filters_returns_persisted_events_in_id_order(
    session: Session, seeded_events: list[AuditEvent]
) -> None:
    events = query_audit_events(session)

    assert event_ids(events) == event_ids(seeded_events)
    assert all(isinstance(event, AuditEvent) for event in events)


@pytest.mark.parametrize(
    ("filters", "expected_ids"),
    [
        ({"actor_id": "actor-a"}, [1, 3]),
        ({"resource_type": "client_account"}, [1, 2, 4]),
        ({"resource_id": "account-1"}, [1, 4]),
        ({"event_type": "USER_LOGIN"}, [1, 3]),
        (
            {
                "actor_id": "actor-b",
                "resource_type": "client_account",
                "resource_id": "account-1",
                "event_type": "PERMISSION_GRANTED",
            },
            [4],
        ),
    ],
)
def test_query_filters_individually_and_in_combination(
    session: Session,
    seeded_events: list[AuditEvent],
    filters: dict[str, str],
    expected_ids: list[int],
) -> None:
    events = query_audit_events(session, **filters)

    assert event_ids(events) == expected_ids


def test_query_time_range_is_inclusive_and_normalizes_timezones(
    session: Session, seeded_events: list[AuditEvent]
) -> None:
    india_time = timezone(timedelta(hours=5, minutes=30))
    events = query_audit_events(
        session,
        from_timestamp=datetime(2026, 11, 24, 15, 30, tzinfo=india_time),
        to_timestamp=datetime(2026, 11, 24, 16, 30, tzinfo=india_time),
    )

    assert event_ids(events) == [2, 3]


@pytest.mark.parametrize(
    ("from_timestamp", "to_timestamp", "message"),
    [
        (datetime(2026, 11, 24, 9, 0), None, "from_timestamp"),
        (None, datetime(2026, 11, 24, 9, 0), "to_timestamp"),
        (
            datetime(2026, 11, 24, 12, 0, tzinfo=timezone.utc),
            datetime(2026, 11, 24, 9, 0, tzinfo=timezone.utc),
            "must not be after",
        ),
    ],
)
def test_query_rejects_invalid_time_bounds(
    session: Session,
    from_timestamp: datetime | None,
    to_timestamp: datetime | None,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        query_audit_events(
            session,
            from_timestamp=from_timestamp,
            to_timestamp=to_timestamp,
        )


def test_query_applies_pagination_after_filtering(
    session: Session, seeded_events: list[AuditEvent]
) -> None:
    events = query_audit_events(session, resource_type="client_account", limit=2, offset=1)
    empty_page = query_audit_events(session, limit=2, offset=10)

    assert event_ids(events) == [2, 4]
    assert empty_page == []


@pytest.mark.parametrize(
    ("limit", "offset", "message"),
    [(0, 0, "limit"), (1001, 0, "limit"), (1, -1, "offset")],
)
def test_query_rejects_invalid_pagination(
    session: Session, limit: int, offset: int, message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        query_audit_events(session, limit=limit, offset=offset)


def test_query_returns_empty_list_when_no_records_match(
    session: Session, seeded_events: list[AuditEvent]
) -> None:
    assert query_audit_events(session, actor_id="missing-actor") == []
