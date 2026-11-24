"""Tests for checkpoint-backed, read-only audit-chain verification."""

from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, delete, select, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from app.database import Base
from app.models import AuditChainState, AuditEvent
from app.services.audit_service import (
    AuditChainIntegrityError,
    GENESIS_CHAIN_HASH,
    GENESIS_HASH,
    HASH_SCHEME_VERSION,
    VIOLATION_CHECKPOINT_COUNT_MISMATCH,
    VIOLATION_CHECKPOINT_HEAD_CHAIN_HASH_MISMATCH,
    VIOLATION_CHECKPOINT_HEAD_ID_MISMATCH,
    VIOLATION_CHECKPOINT_MISSING,
    VIOLATION_CHECKPOINT_VERSION_MISMATCH,
    VIOLATION_CONTENT_HASH_MISMATCH,
    VIOLATION_MALFORMED_EVENT_CONTENT,
    VIOLATION_MALFORMED_HASH,
    VIOLATION_CHAIN_HASH_MISMATCH,
    VIOLATION_PREVIOUS_CHAIN_HASH_MISMATCH,
    VIOLATION_PREVIOUS_HASH_MISMATCH,
    VIOLATION_UNSUPPORTED_HASH_SCHEME,
    append_audit_event,
    calculate_chain_hash,
    calculate_content_hash,
    verify_audit_chain,
)


@pytest.fixture()
def session() -> Session:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as database_session:
        yield database_session
    Base.metadata.drop_all(engine)
    engine.dispose()


def append_events(session: Session, count: int) -> list[AuditEvent]:
    events = []
    for index in range(count):
        events.append(
            append_audit_event(
                session,
                event_type=f"EVENT_{index}",
                actor_id="actor-1",
                resource_type="client_account",
                resource_id=f"account-{index}",
                payload={"sequence": index},
            )
        )
    session.commit()
    return events


def test_empty_chain_without_checkpoint_is_valid(session: Session) -> None:
    result = verify_audit_chain(session)

    assert result.is_intact is True
    assert result.checked_record_count == 0
    assert result.violation_type is None


def test_empty_chain_with_explicit_empty_checkpoint_is_valid(session: Session) -> None:
    session.add(AuditChainState(hash_scheme_version=HASH_SCHEME_VERSION, event_count=0))
    session.commit()

    result = verify_audit_chain(session)

    assert result.is_intact is True
    assert result.checked_record_count == 0


def test_append_initializes_and_updates_checkpoint(session: Session) -> None:
    events = append_events(session, 2)
    checkpoint = session.get(AuditChainState, 1)

    assert checkpoint is not None
    assert checkpoint.event_count == 2
    assert checkpoint.head_event_id == events[-1].id
    assert checkpoint.head_chain_hash == events[-1].chain_hash
    assert verify_audit_chain(session).is_intact is True


def test_append_rollback_removes_event_and_checkpoint_together(session: Session) -> None:
    append_audit_event(
        session,
        event_type="USER_LOGIN",
        actor_id="actor-1",
        resource_type="session",
        resource_id="session-1",
        payload={},
    )

    session.rollback()

    assert session.scalar(select(AuditEvent)) is None
    assert session.get(AuditChainState, 1) is None


def test_append_rollback_preserves_an_existing_valid_chain(session: Session) -> None:
    events = append_events(session, 1)
    original_event_id = events[0].id
    original_checkpoint = session.get(AuditChainState, 1)
    assert original_checkpoint is not None
    checkpoint_before = (
        original_checkpoint.event_count,
        original_checkpoint.head_event_id,
        original_checkpoint.head_chain_hash,
    )

    append_audit_event(
        session,
        event_type="EVENT_2",
        actor_id="actor-1",
        resource_type="client_account",
        resource_id="account-2",
        payload={},
    )
    session.rollback()
    session.expunge_all()

    persisted_events = list(session.scalars(select(AuditEvent).order_by(AuditEvent.id)))
    persisted_checkpoint = session.get(AuditChainState, 1)
    assert [event.id for event in persisted_events] == [original_event_id]
    assert persisted_checkpoint is not None
    assert (
        persisted_checkpoint.event_count,
        persisted_checkpoint.head_event_id,
        persisted_checkpoint.head_chain_hash,
    ) == checkpoint_before
    assert verify_audit_chain(session).is_intact is True


def test_valid_single_and_multi_event_chains_verify(session: Session) -> None:
    append_events(session, 1)
    assert verify_audit_chain(session).is_intact is True

    append_events(session, 2)
    result = verify_audit_chain(session)
    assert result.is_intact is True
    assert result.checked_record_count == 3


def test_direct_event_content_modification_is_detected(session: Session) -> None:
    events = append_events(session, 2)
    events[0].payload = {"sequence": "tampered"}
    session.commit()

    result = verify_audit_chain(session)

    assert result.violation_type == VIOLATION_CONTENT_HASH_MISMATCH
    assert result.first_inconsistency_id == events[0].id


def test_direct_event_field_modification_is_detected(session: Session) -> None:
    events = append_events(session, 2)
    events[0].actor_id = "tampered-actor"
    session.commit()

    result = verify_audit_chain(session)

    assert result.violation_type == VIOLATION_CONTENT_HASH_MISMATCH
    assert result.first_inconsistency_id == events[0].id


def test_malformed_persisted_payload_is_distinguished_from_database_failure(
    session: Session,
) -> None:
    events = append_events(session, 1)
    events[0].payload = ["not", "an", "object"]
    session.commit()

    result = verify_audit_chain(session)

    assert result.violation_type == VIOLATION_MALFORMED_EVENT_CONTENT
    assert result.first_inconsistency_id == events[0].id


def test_invalid_raw_json_syntax_is_reported_at_its_event(
    session: Session,
) -> None:
    events = append_events(session, 2)
    session.execute(
        text("UPDATE audit_events SET payload = :payload WHERE id = :event_id"),
        {"payload": "{not valid JSON", "event_id": events[1].id},
    )

    result = verify_audit_chain(session)

    assert result.violation_type == VIOLATION_MALFORMED_EVENT_CONTENT
    assert result.first_inconsistency_id == events[1].id
    assert result.checked_record_count == 2
    session.rollback()


def test_invalid_raw_timestamp_is_reported_at_its_event(session: Session) -> None:
    events = append_events(session, 2)
    session.execute(
        text("UPDATE audit_events SET timestamp = :timestamp WHERE id = :event_id"),
        {"timestamp": "not-a-timestamp", "event_id": events[1].id},
    )

    result = verify_audit_chain(session)

    assert result.violation_type == VIOLATION_MALFORMED_EVENT_CONTENT
    assert result.first_inconsistency_id == events[1].id
    assert result.checked_record_count == 2
    session.rollback()


def test_earlier_content_hash_mismatch_precedes_later_malformed_json(
    session: Session,
) -> None:
    events = append_events(session, 2)
    session.execute(
        text("UPDATE audit_events SET content_hash = :hash WHERE id = :event_id"),
        {"hash": "f" * 64, "event_id": events[0].id},
    )
    session.execute(
        text("UPDATE audit_events SET payload = :payload WHERE id = :event_id"),
        {"payload": "{not valid JSON", "event_id": events[1].id},
    )

    result = verify_audit_chain(session)

    assert result.violation_type == VIOLATION_CONTENT_HASH_MISMATCH
    assert result.first_inconsistency_id == events[0].id
    assert result.checked_record_count == 1
    session.rollback()


def test_earlier_predecessor_mismatch_precedes_later_malformed_json(
    session: Session,
) -> None:
    events = append_events(session, 2)
    session.execute(
        text("UPDATE audit_events SET previous_hash = :hash WHERE id = :event_id"),
        {"hash": "f" * 64, "event_id": events[0].id},
    )
    session.execute(
        text("UPDATE audit_events SET payload = :payload WHERE id = :event_id"),
        {"payload": "{not valid JSON", "event_id": events[1].id},
    )

    result = verify_audit_chain(session)

    assert result.violation_type == VIOLATION_PREVIOUS_HASH_MISMATCH
    assert result.first_inconsistency_id == events[0].id
    assert result.checked_record_count == 1
    session.rollback()


def test_direct_content_hash_modification_is_detected(session: Session) -> None:
    events = append_events(session, 2)
    events[0].content_hash = "f" * 64
    session.commit()

    result = verify_audit_chain(session)

    assert result.violation_type == VIOLATION_CONTENT_HASH_MISMATCH
    assert result.first_inconsistency_id == events[0].id


def test_direct_previous_hash_modification_is_detected(session: Session) -> None:
    events = append_events(session, 2)
    events[1].previous_hash = "f" * 64
    session.commit()

    result = verify_audit_chain(session)

    assert result.violation_type == VIOLATION_PREVIOUS_HASH_MISMATCH
    assert result.first_inconsistency_id == events[1].id


@pytest.mark.parametrize(
    ("deleted_index", "expected_violation"),
    [
        (0, VIOLATION_PREVIOUS_HASH_MISMATCH),
        (1, VIOLATION_PREVIOUS_HASH_MISMATCH),
        (2, VIOLATION_CHECKPOINT_COUNT_MISMATCH),
    ],
)
def test_deletion_of_first_middle_or_last_event_is_detected(
    session: Session, deleted_index: int, expected_violation: str
) -> None:
    events = append_events(session, 3)
    session.delete(events[deleted_index])
    session.commit()

    result = verify_audit_chain(session)
    assert result.violation_type == expected_violation
    if deleted_index == 0:
        assert result.first_inconsistency_id == events[1].id
        assert result.checked_record_count == 1
    elif deleted_index == 1:
        assert result.first_inconsistency_id == events[2].id
        assert result.checked_record_count == 2
    else:
        assert result.first_inconsistency_id is None


def test_deletion_of_all_events_is_detected_by_checkpoint(session: Session) -> None:
    append_events(session, 2)
    session.execute(delete(AuditEvent))
    session.commit()

    result = verify_audit_chain(session)

    assert result.violation_type == VIOLATION_CHECKPOINT_COUNT_MISMATCH


def test_missing_checkpoint_for_existing_events_is_detected_and_blocks_append(
    session: Session,
) -> None:
    append_events(session, 1)
    checkpoint = session.get(AuditChainState, 1)
    assert checkpoint is not None
    session.delete(checkpoint)
    session.commit()

    assert verify_audit_chain(session).violation_type == VIOLATION_CHECKPOINT_MISSING
    with pytest.raises(AuditChainIntegrityError, match="checkpoint state missing"):
        append_audit_event(
            session,
            event_type="EVENT_2",
            actor_id="actor-1",
            resource_type="client_account",
            resource_id="account-2",
            payload={},
        )


@pytest.mark.parametrize(
    ("attribute", "replacement", "expected_violation"),
    [
        ("hash_scheme_version", "unsupported", VIOLATION_CHECKPOINT_VERSION_MISMATCH),
        ("event_count", 99, VIOLATION_CHECKPOINT_COUNT_MISMATCH),
        ("head_event_id", 99, VIOLATION_CHECKPOINT_HEAD_ID_MISMATCH),
        ("head_chain_hash", "f" * 64, VIOLATION_CHECKPOINT_HEAD_CHAIN_HASH_MISMATCH),
    ],
)
def test_incorrect_checkpoint_values_are_detected(
    session: Session, attribute: str, replacement: int | str, expected_violation: str
) -> None:
    append_events(session, 2)
    checkpoint = session.get(AuditChainState, 1)
    assert checkpoint is not None
    setattr(checkpoint, attribute, replacement)
    session.commit()

    result = verify_audit_chain(session)
    assert result.violation_type == expected_violation
    assert result.first_inconsistency_id is None


@pytest.mark.parametrize(
    ("attribute", "replacement", "message"),
    [
        ("event_count", 2, "event count"),
        ("head_event_id", 99, "head ID"),
        ("head_chain_hash", "f" * 64, "head chain hash"),
    ],
)
def test_inconsistent_checkpoint_blocks_append(
    session: Session, attribute: str, replacement: int | str, message: str
) -> None:
    append_events(session, 1)
    checkpoint = session.get(AuditChainState, 1)
    assert checkpoint is not None
    setattr(checkpoint, attribute, replacement)
    session.commit()

    with pytest.raises(AuditChainIntegrityError, match=message):
        append_audit_event(
            session,
            event_type="EVENT_2",
            actor_id="actor-1",
            resource_type="client_account",
            resource_id="account-2",
            payload={},
        )


def test_legitimate_id_gap_is_not_an_integrity_violation(session: Session) -> None:
    first_event = append_events(session, 1)[0]
    timestamp = datetime(2026, 11, 24, 9, 30, tzinfo=timezone.utc)
    second_hash = calculate_content_hash(
        event_type="EVENT_GAP",
        actor_id="actor-1",
        resource_type="client_account",
        resource_id="account-gap",
        payload={},
        timestamp=timestamp,
    )
    second_chain_hash = calculate_chain_hash(
        hash_scheme_version=HASH_SCHEME_VERSION,
        content_hash=second_hash,
        previous_chain_hash=first_event.chain_hash,
    )
    gap_event = AuditEvent(
        id=10,
        event_type="EVENT_GAP",
        actor_id="actor-1",
        resource_type="client_account",
        resource_id="account-gap",
        payload={},
        timestamp=timestamp,
        previous_hash=first_event.content_hash,
        content_hash=second_hash,
        hash_scheme_version=HASH_SCHEME_VERSION,
        previous_chain_hash=first_event.chain_hash,
        chain_hash=second_chain_hash,
    )
    checkpoint = session.get(AuditChainState, 1)
    assert checkpoint is not None
    session.add(gap_event)
    checkpoint.event_count = 2
    checkpoint.head_event_id = 10
    checkpoint.head_chain_hash = second_chain_hash
    session.commit()

    assert verify_audit_chain(session).is_intact is True


def test_verification_is_read_only(session: Session) -> None:
    events = append_events(session, 2)
    checkpoint = session.get(AuditChainState, 1)
    assert checkpoint is not None
    evidence_before = [
        (event.id, event.timestamp, event.previous_hash, event.content_hash)
        for event in events
    ]
    checkpoint_before = (
        checkpoint.event_count,
        checkpoint.head_event_id,
        checkpoint.head_chain_hash,
    )

    result = verify_audit_chain(session)

    assert result.is_intact is True
    assert not session.new
    assert not session.dirty
    session.expunge_all()
    reloaded_events = list(session.scalars(select(AuditEvent).order_by(AuditEvent.id)))
    reloaded_checkpoint = session.get(AuditChainState, 1)
    assert [
        (event.id, event.timestamp, event.previous_hash, event.content_hash)
        for event in reloaded_events
    ] == evidence_before
    assert reloaded_checkpoint is not None
    assert (
        reloaded_checkpoint.event_count,
        reloaded_checkpoint.head_event_id,
        reloaded_checkpoint.head_chain_hash,
    ) == checkpoint_before


def test_verification_reads_direct_sql_changes_despite_loaded_identity_map(
    session: Session,
) -> None:
    events = append_events(session, 1)
    loaded_event = session.get(AuditEvent, events[0].id)
    assert loaded_event is not None
    original_actor_id = loaded_event.actor_id

    # Text SQL bypasses ORM state synchronization, leaving this object stale.
    session.execute(
        text("UPDATE audit_events SET actor_id = :actor_id WHERE id = :event_id"),
        {"actor_id": "tampered-actor", "event_id": loaded_event.id},
    )

    result = verify_audit_chain(session)

    assert loaded_event.actor_id == original_actor_id
    assert result.violation_type == VIOLATION_CONTENT_HASH_MISMATCH
    session.rollback()


def test_verification_ignores_unflushed_local_changes(session: Session) -> None:
    events = append_events(session, 1)
    events[0].actor_id = "local-unflushed-change"

    result = verify_audit_chain(session)

    assert result.is_intact is True
    assert events[0].actor_id == "local-unflushed-change"
    assert events[0] in session.dirty
    session.rollback()


def test_operational_database_error_propagates(
    session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    append_events(session, 1)

    def unavailable_database(*args: object, **kwargs: object) -> object:
        raise OperationalError("SELECT", {}, RuntimeError("database unavailable"))

    monkeypatch.setattr(session, "execute", unavailable_database)

    with pytest.raises(OperationalError):
        verify_audit_chain(session)


def test_three_event_chain_has_transitive_linked_hashes(session: Session) -> None:
    events = append_events(session, 3)

    assert events[0].previous_chain_hash == GENESIS_CHAIN_HASH
    assert events[1].previous_chain_hash == events[0].chain_hash
    assert events[2].previous_chain_hash == events[1].chain_hash
    assert all(event.hash_scheme_version == HASH_SCHEME_VERSION for event in events)
    assert verify_audit_chain(session).is_intact is True


def test_recomputed_content_hash_still_requires_downstream_chain_recalculation(
    session: Session,
) -> None:
    events = append_events(session, 2)
    first = events[0]
    first.actor_id = "rewritten-actor"
    first.content_hash = calculate_content_hash(
        event_type=first.event_type,
        actor_id=first.actor_id,
        resource_type=first.resource_type,
        resource_id=first.resource_id,
        payload=first.payload,
        timestamp=first.timestamp,
    )
    first.chain_hash = calculate_chain_hash(
        hash_scheme_version=HASH_SCHEME_VERSION,
        content_hash=first.content_hash,
        previous_chain_hash=first.previous_chain_hash,
    )
    events[1].previous_hash = first.content_hash
    session.commit()

    result = verify_audit_chain(session)

    assert result.violation_type == VIOLATION_PREVIOUS_CHAIN_HASH_MISMATCH
    assert result.first_inconsistency_id == events[1].id


def test_chain_hash_modification_and_unsupported_scheme_are_distinguished(
    session: Session,
) -> None:
    event = append_events(session, 1)[0]
    event.chain_hash = "f" * 64
    session.commit()

    result = verify_audit_chain(session)
    assert result.violation_type == VIOLATION_CHAIN_HASH_MISMATCH

    event.hash_scheme_version = "unsupported"
    session.commit()
    result = verify_audit_chain(session)
    assert result.violation_type == VIOLATION_UNSUPPORTED_HASH_SCHEME


def test_malformed_chain_hash_is_reported_at_its_event(session: Session) -> None:
    event = append_events(session, 1)[0]
    event.chain_hash = "not-a-digest"
    session.commit()

    result = verify_audit_chain(session)

    assert result.violation_type == VIOLATION_MALFORMED_HASH
    assert result.first_inconsistency_id == event.id


def test_tail_integrity_validation_blocks_extension_without_full_scan(session: Session) -> None:
    event = append_events(session, 1)[0]
    checkpoint = session.get(AuditChainState, 1)
    assert checkpoint is not None
    event.chain_hash = "f" * 64
    checkpoint.head_chain_hash = event.chain_hash
    session.commit()

    with pytest.raises(AuditChainIntegrityError, match="tail chain hash"):
        append_audit_event(
            session,
            event_type="EVENT_2",
            actor_id="actor-1",
            resource_type="client_account",
            resource_id="account-2",
            payload={},
        )


def test_fully_coordinated_same_database_rewrite_remains_documented_limitation(
    session: Session,
) -> None:
    """A privileged actor can still rewrite all evidence and the checkpoint."""

    events = append_events(session, 2)
    events[0].payload = {"sequence": "rewritten"}
    previous_content_hash = GENESIS_HASH
    previous_chain_hash = GENESIS_CHAIN_HASH
    for event in events:
        event.previous_hash = previous_content_hash
        event.previous_chain_hash = previous_chain_hash
        event.content_hash = calculate_content_hash(
            event_type=event.event_type,
            actor_id=event.actor_id,
            resource_type=event.resource_type,
            resource_id=event.resource_id,
            payload=event.payload,
            timestamp=event.timestamp,
        )
        event.chain_hash = calculate_chain_hash(
            hash_scheme_version=HASH_SCHEME_VERSION,
            content_hash=event.content_hash,
            previous_chain_hash=event.previous_chain_hash,
        )
        previous_content_hash = event.content_hash
        previous_chain_hash = event.chain_hash
    checkpoint = session.get(AuditChainState, 1)
    assert checkpoint is not None
    checkpoint.head_chain_hash = events[-1].chain_hash
    session.commit()

    assert verify_audit_chain(session).is_intact is True
