"""Tests for service-level, append-only audit-event creation."""

from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from app.database import Base
from app.models import AuditEvent
from app.services.audit_service import (
    GENESIS_HASH,
    append_audit_event,
    calculate_content_hash,
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
