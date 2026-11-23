"""Tests for audit-event persistence metadata."""

from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database import Base
from app.models import AuditEvent


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

    stored_event = session.scalar(select(AuditEvent).where(AuditEvent.id == event.id))

    assert stored_event is not None
    assert stored_event.id == 1
    assert stored_event.event_type == "RECORD_UPDATED"
    assert stored_event.actor_id == "advisor-42"
    assert stored_event.resource_type == "client_account"
    assert stored_event.resource_id == "account-123"
    assert stored_event.payload == {"changed_fields": ["address"]}
    assert stored_event.timestamp is not None
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

    assert event.timestamp is not None
    assert event.timestamp <= datetime.now(timezone.utc).replace(tzinfo=None)


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
