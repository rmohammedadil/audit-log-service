"""Tests for audit-event persistence metadata."""

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.exc import IntegrityError, StatementError
from sqlalchemy.orm import Session

from app.database import Base
from app.models import AuditChainState, AuditEvent, AuditEventArchive, AuditEventRedaction
from app.services.audit_service import (
    GENESIS_CHAIN_HASH,
    GENESIS_HASH,
    HASH_SCHEME_VERSION,
    calculate_chain_hash,
    calculate_content_hash,
)


@pytest.fixture()
def session() -> Session:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)

    with Session(engine) as database_session:
        yield database_session

    Base.metadata.drop_all(engine)
    engine.dispose()


def chain_fields(content_hash: str) -> dict[str, str]:
    """Build valid V2 chain fields for direct persistence-model tests."""

    return {
        "previous_hash": GENESIS_HASH,
        "content_hash": content_hash,
        "hash_scheme_version": HASH_SCHEME_VERSION,
        "previous_chain_hash": GENESIS_CHAIN_HASH,
        "chain_hash": calculate_chain_hash(
            hash_scheme_version=HASH_SCHEME_VERSION,
            content_hash=content_hash,
            previous_chain_hash=GENESIS_CHAIN_HASH,
        ),
    }


def persisted_event(session: Session, content_hash: str) -> AuditEvent:
    """Store one syntactically valid event for metadata-constraint tests."""

    event = AuditEvent(
        event_type="SYSTEM_EVENT",
        actor_id="system-1",
        resource_type="audit_log",
        resource_id=f"event-{content_hash[:8]}",
        payload={},
        **chain_fields(content_hash),
    )
    session.add(event)
    session.flush()
    return event


def test_audit_event_persists_all_required_fields(session: Session) -> None:
    event = AuditEvent(
        event_type="RECORD_UPDATED",
        actor_id="advisor-42",
        resource_type="client_account",
        resource_id="account-123",
        payload={"changed_fields": ["address"]},
        **chain_fields("a" * 64),
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
    assert stored_event.previous_hash == GENESIS_HASH
    assert stored_event.content_hash == "a" * 64
    assert stored_event.hash_scheme_version == HASH_SCHEME_VERSION
    assert stored_event.previous_chain_hash == GENESIS_CHAIN_HASH


def test_audit_event_uses_server_assigned_utc_timestamp(session: Session) -> None:
    event = AuditEvent(
        event_type="USER_LOGIN",
        actor_id="user-1",
        resource_type="session",
        resource_id="session-1",
        payload={},
        **chain_fields("b" * 64),
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
        previous_hash=GENESIS_HASH,
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
        **chain_fields("c" * 64),
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
        **chain_fields("d" * 64),
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
        **chain_fields(original_hash),
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
        hash_scheme_version=HASH_SCHEME_VERSION,
        event_count=0,
        head_event_id=None,
        head_chain_hash=None,
    )
    session.add(invalid_checkpoint)

    with pytest.raises(IntegrityError):
        session.commit()

    session.rollback()


def test_archive_metadata_persists_utc_timestamp_and_event_references(
    session: Session,
) -> None:
    target_event = persisted_event(session, "e" * 64)
    action_event = persisted_event(session, "f" * 64)
    archived_at = datetime(
        2026,
        11,
        25,
        12,
        0,
        0,
        123456,
        tzinfo=timezone(timedelta(hours=5, minutes=30)),
    )
    archive = AuditEventArchive(
        target_event_id=target_event.id,
        archived_at=archived_at,
        archive_action_event_id=action_event.id,
    )
    session.add(archive)
    session.commit()
    archive_id = archive.id
    target_event_id = target_event.id
    action_event_id = action_event.id
    session.expunge_all()

    stored_archive = session.get(AuditEventArchive, archive_id)

    assert stored_archive is not None
    assert stored_archive.target_event_id == target_event_id
    assert stored_archive.archive_action_event_id == action_event_id
    assert stored_archive.archived_at == datetime(
        2026, 11, 25, 6, 30, 0, 123456, tzinfo=timezone.utc
    )


def test_redaction_metadata_persists_without_original_payload_values(
    session: Session,
) -> None:
    target_event = persisted_event(session, "1" * 64)
    action_event = persisted_event(session, "2" * 64)
    redaction = AuditEventRedaction(
        target_event_id=target_event.id,
        json_pointer="/client/contact/phone",
        redacted_at=datetime(2026, 11, 25, 12, 0, tzinfo=timezone.utc),
        redaction_reason="PII",
        redaction_action_event_id=action_event.id,
    )
    session.add(redaction)
    session.commit()
    redaction_id = redaction.id
    target_event_id = target_event.id
    session.expunge_all()

    stored_redaction = session.get(AuditEventRedaction, redaction_id)

    assert stored_redaction is not None
    assert stored_redaction.target_event_id == target_event_id
    assert stored_redaction.json_pointer == "/client/contact/phone"
    assert stored_redaction.redaction_reason == "PII"
    assert not hasattr(stored_redaction, "original_value")


@pytest.mark.parametrize(
    "metadata_factory",
    [
        pytest.param(
            lambda target_id, action_id: AuditEventArchive(
                archived_at=datetime(2026, 11, 25, 12, 0, tzinfo=timezone.utc),
                archive_action_event_id=action_id,
            ),
            id="archive-target",
        ),
        pytest.param(
            lambda target_id, action_id: AuditEventArchive(
                target_event_id=target_id,
                archive_action_event_id=action_id,
            ),
            id="archive-timestamp",
        ),
        pytest.param(
            lambda target_id, action_id: AuditEventArchive(
                target_event_id=target_id,
                archived_at=datetime(2026, 11, 25, 12, 0, tzinfo=timezone.utc),
            ),
            id="archive-action",
        ),
        pytest.param(
            lambda target_id, action_id: AuditEventRedaction(
                json_pointer="/client/ssn",
                redacted_at=datetime(2026, 11, 25, 12, 0, tzinfo=timezone.utc),
                redaction_reason="PII",
                redaction_action_event_id=action_id,
            ),
            id="redaction-target",
        ),
        pytest.param(
            lambda target_id, action_id: AuditEventRedaction(
                target_event_id=target_id,
                redacted_at=datetime(2026, 11, 25, 12, 0, tzinfo=timezone.utc),
                redaction_reason="PII",
                redaction_action_event_id=action_id,
            ),
            id="redaction-pointer",
        ),
        pytest.param(
            lambda target_id, action_id: AuditEventRedaction(
                target_event_id=target_id,
                json_pointer="/client/ssn",
                redaction_reason="PII",
                redaction_action_event_id=action_id,
            ),
            id="redaction-timestamp",
        ),
        pytest.param(
            lambda target_id, action_id: AuditEventRedaction(
                target_event_id=target_id,
                json_pointer="/client/ssn",
                redacted_at=datetime(2026, 11, 25, 12, 0, tzinfo=timezone.utc),
                redaction_action_event_id=action_id,
            ),
            id="redaction-reason",
        ),
        pytest.param(
            lambda target_id, action_id: AuditEventRedaction(
                target_event_id=target_id,
                json_pointer="/client/ssn",
                redacted_at=datetime(2026, 11, 25, 12, 0, tzinfo=timezone.utc),
                redaction_reason="PII",
            ),
            id="redaction-action",
        ),
    ],
)
def test_metadata_required_fields_are_enforced(
    session: Session, metadata_factory: object
) -> None:
    target_event = persisted_event(session, "3" * 64)
    action_event = persisted_event(session, "4" * 64)
    metadata = metadata_factory(target_event.id, action_event.id)  # type: ignore[operator]
    session.add(metadata)

    with pytest.raises(IntegrityError):
        session.commit()

    session.rollback()


def test_metadata_uniqueness_and_references_are_enforced(session: Session) -> None:
    target_event = persisted_event(session, "5" * 64)
    action_event = persisted_event(session, "6" * 64)
    other_action_event = persisted_event(session, "7" * 64)
    session.add(
        AuditEventArchive(
            target_event_id=target_event.id,
            archived_at=datetime.now(timezone.utc),
            archive_action_event_id=action_event.id,
        )
    )
    session.add(
        AuditEventRedaction(
            target_event_id=target_event.id,
            json_pointer="/client/phone",
            redacted_at=datetime.now(timezone.utc),
            redaction_reason="PII",
            redaction_action_event_id=action_event.id,
        )
    )
    session.commit()

    referenced_event = session.get(AuditEvent, target_event.id)
    assert referenced_event is not None
    session.delete(referenced_event)
    with pytest.raises(IntegrityError):
        session.commit()
    session.rollback()

    session.add(
        AuditEventArchive(
            target_event_id=target_event.id,
            archived_at=datetime.now(timezone.utc),
            archive_action_event_id=other_action_event.id,
        )
    )
    with pytest.raises(IntegrityError):
        session.commit()
    session.rollback()

    session.add(
        AuditEventRedaction(
            target_event_id=target_event.id,
            json_pointer="/client/phone",
            redacted_at=datetime.now(timezone.utc),
            redaction_reason="PII",
            redaction_action_event_id=other_action_event.id,
        )
    )
    with pytest.raises(IntegrityError):
        session.commit()
    session.rollback()

    session.add(
        AuditEventArchive(
            target_event_id=target_event.id,
            archived_at=datetime.now(timezone.utc),
            archive_action_event_id=99999,
        )
    )
    with pytest.raises(IntegrityError):
        session.commit()
    session.rollback()

    session.add(
        AuditEventRedaction(
            target_event_id=99999,
            json_pointer="/client/address",
            redacted_at=datetime.now(timezone.utc),
            redaction_reason="PII",
            redaction_action_event_id=action_event.id,
        )
    )
    with pytest.raises(IntegrityError):
        session.commit()
    session.rollback()
