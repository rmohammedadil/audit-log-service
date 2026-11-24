"""Tests for audit-event persistence metadata."""

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.exc import IntegrityError, StatementError
from sqlalchemy.orm import Session

from app.database import Base
from app.models import AuditChainState, AuditEvent
from app.services.audit_service import calculate_content_hash


@pytest.fixture()
def session() -> Session:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)

    with Session(engine) as database_session:
        yield database_session

    Base.metadata.drop_all(engine)
    engine.dispose()


def test_audit_event_persists_all_required_fields(session: Session) -> None:
    event = AuditEvent(
        event_type="RECORD_UPDATED",
        actor_id="advisor-42",
        resource_type="client_account",
        resource_id="account-123",
        payload={"changed_fields": ["address"]},
        previous_hash="AUDIT_LOG_GENESIS_V1",
        content_hash="a" * 64,
    )

    session.add(event)
    session.commit()
    event_id = event.id
    session.expunge_all()

    stored_event = session.scalar(select(AuditEvent).where(AuditEvent.id == event_id))

    assert stored_event is not None
    assert stored_event.id == 1
    assert stored_event.event_type == "RECORD_UPDATED"
    assert stored_event.actor_id == "advisor-42"
    assert stored_event.resource_type == "client_account"
    assert stored_event.resource_id == "account-123"
    assert stored_event.payload == {"changed_fields": ["address"]}
    assert stored_event.timestamp is not None
    assert stored_event.timestamp.tzinfo == timezone.utc
    assert stored_event.previous_hash == "AUDIT_LOG_GENESIS_V1"
    assert stored_event.content_hash == "a" * 64


def test_audit_event_uses_server_assigned_utc_timestamp(session: Session) -> None:
    event = AuditEvent(
        event_type="USER_LOGIN",
        actor_id="user-1",
        resource_type="session",
        resource_id="session-1",
        payload={},
        previous_hash="AUDIT_LOG_GENESIS_V1",
        content_hash="b" * 64,
    )

    session.add(event)
    session.commit()
    event_id = event.id
    session.expunge_all()

    stored_event = session.scalar(select(AuditEvent).where(AuditEvent.id == event_id))

    assert stored_event is not None
    assert stored_event.timestamp.tzinfo == timezone.utc
    assert stored_event.timestamp <= datetime.now(timezone.utc)


def test_audit_event_requires_chain_hashes(session: Session) -> None:
    event = AuditEvent(
        event_type="USER_LOGIN",
        actor_id="user-1",
        resource_type="session",
        resource_id="session-1",
        payload={},
        previous_hash="AUDIT_LOG_GENESIS_V1",
    )

    session.add(event)

    with pytest.raises(IntegrityError):
        session.commit()

    session.rollback()


def test_non_utc_timestamp_is_normalized_with_microseconds_preserved(
    session: Session,
) -> None:
    source_timestamp = datetime(
        2026,
        11,
        24,
        15,
        0,
        0,
        987654,
        tzinfo=timezone(timedelta(hours=5, minutes=30)),
    )
    event = AuditEvent(
        event_type="USER_LOGIN",
        actor_id="user-1",
        resource_type="session",
        resource_id="session-1",
        payload={},
        timestamp=source_timestamp,
        previous_hash="AUDIT_LOG_GENESIS_V1",
        content_hash="c" * 64,
    )

    session.add(event)
    session.commit()
    event_id = event.id
    session.expunge_all()
    stored_event = session.scalar(select(AuditEvent).where(AuditEvent.id == event_id))

    assert stored_event is not None
    assert stored_event.timestamp == datetime(
        2026, 11, 24, 9, 30, 0, 987654, tzinfo=timezone.utc
    )


def test_naive_timestamp_is_rejected_before_persistence(session: Session) -> None:
    event = AuditEvent(
        event_type="USER_LOGIN",
        actor_id="user-1",
        resource_type="session",
        resource_id="session-1",
        payload={},
        timestamp=datetime(2026, 11, 24, 9, 30),
        previous_hash="AUDIT_LOG_GENESIS_V1",
        content_hash="d" * 64,
    )

    session.add(event)

    with pytest.raises(StatementError, match="timezone information"):
        session.commit()

    session.rollback()


def test_reloaded_timestamp_reproduces_the_original_content_hash(session: Session) -> None:
    timestamp = datetime(2026, 11, 24, 9, 30, 0, 123456, tzinfo=timezone.utc)
    event_fields = {
        "event_type": "RECORD_UPDATED",
        "actor_id": "advisor-42",
        "resource_type": "client_account",
        "resource_id": "account-123",
        "payload": {"changed_fields": ["address"]},
        "timestamp": timestamp,
    }
    original_hash = calculate_content_hash(**event_fields)
    event = AuditEvent(
        **event_fields,
        previous_hash="AUDIT_LOG_GENESIS_V1",
        content_hash=original_hash,
    )

    session.add(event)
    session.commit()
    event_id = event.id
    session.expunge_all()
    stored_event = session.scalar(select(AuditEvent).where(AuditEvent.id == event_id))

    assert stored_event is not None
    reloaded_hash = calculate_content_hash(
        event_type=stored_event.event_type,
        actor_id=stored_event.actor_id,
        resource_type=stored_event.resource_type,
        resource_id=stored_event.resource_id,
        payload=stored_event.payload,
        timestamp=stored_event.timestamp,
    )
    assert reloaded_hash == original_hash


def test_checkpoint_enforces_singleton_identity_and_empty_shape(session: Session) -> None:
    invalid_checkpoint = AuditChainState(
        singleton_id=2,
        event_count=0,
        head_event_id=None,
        head_content_hash=None,
    )
    session.add(invalid_checkpoint)

    with pytest.raises(IntegrityError):
        session.commit()

    session.rollback()
