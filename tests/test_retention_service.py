"""Focused tests for configured logical archival and its integrity evidence."""

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session

from app.database import Base
from app.models import AuditChainState, AuditEvent, AuditEventArchive
from app.services import audit_service
from app.services.audit_service import (
    AUDIT_RETENTION_APPLIED,
    AuditChainIntegrityError,
    ReservedLifecycleEventTypeError,
    VIOLATION_ARCHIVE_METADATA_MISMATCH,
    VIOLATION_ARCHIVE_MALFORMED_ACTION,
    VIOLATION_CONTENT_HASH_MISMATCH,
    append_audit_event,
    append_lifecycle_audit_event,
    query_audit_events,
    verify_audit_chain,
)
from app.services.retention_service import (
    DEFAULT_AUDIT_RETENTION_DAYS,
    MAX_AUDIT_RETENTION_DAYS,
    RetentionConfigurationError,
    parse_retention_days,
    run_retention,
)


@pytest.fixture()
def session() -> Session:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as database_session:
        yield database_session
    Base.metadata.drop_all(engine)
    engine.dispose()


def append_at(
    session: Session, monkeypatch: pytest.MonkeyPatch, timestamp: datetime, name: str
) -> AuditEvent:
    """Append a business event with a deterministic server clock in tests."""

    monkeypatch.setattr(audit_service, "utc_now", lambda: timestamp)
    return append_audit_event(
        session,
        event_type=name,
        actor_id="advisor-42",
        resource_type="client_account",
        resource_id=name.lower(),
        payload={"event": name},
    )


def test_retention_configuration_defaults_and_rejects_invalid_values() -> None:
    assert parse_retention_days(None) == DEFAULT_AUDIT_RETENTION_DAYS
    assert parse_retention_days("365") == 365
    for value in ("", " ", "0", "-1", "1.5", "ninety", str(MAX_AUDIT_RETENTION_DAYS + 1)):
        with pytest.raises(RetentionConfigurationError):
            parse_retention_days(value)


def test_retention_archives_strictly_older_business_events_and_verifies(
    session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AUDIT_RETENTION_DAYS", "10")
    now = datetime(2026, 11, 25, 12, 0, tzinfo=timezone.utc)
    old = append_at(session, monkeypatch, now - timedelta(days=11), "OLD")
    boundary = append_at(session, monkeypatch, now - timedelta(days=10), "BOUNDARY")
    recent = append_at(session, monkeypatch, now - timedelta(days=9), "RECENT")
    session.commit()
    original_evidence = (old.payload, old.content_hash, old.chain_hash, old.timestamp)

    result = run_retention(session, now=now)
    session.commit()

    assert result.archived_event_ids == (old.id,)
    assert result.action_event_id is not None
    action = session.get(AuditEvent, result.action_event_id)
    archive = session.scalar(select(AuditEventArchive))
    checkpoint = session.get(AuditChainState, 1)
    assert action is not None and archive is not None and checkpoint is not None
    assert action.event_type == AUDIT_RETENTION_APPLIED
    assert action.payload == {
        "archivedAt": "2026-11-25T12:00:00.000000Z",
        "archivedEventCount": 1,
        "archivedEventIds": [old.id],
        "cutoff": "2026-11-15T12:00:00.000000Z",
        "retentionDays": 10,
    }
    assert archive.target_event_id == old.id
    assert archive.archive_action_event_id == action.id
    assert archive.archived_at == action.timestamp
    assert (old.payload, old.content_hash, old.chain_hash, old.timestamp) == original_evidence
    assert boundary.id not in result.archived_event_ids
    assert recent.id not in result.archived_event_ids
    assert checkpoint.event_count == 4
    assert verify_audit_chain(session).is_intact is True


def test_retention_noop_repeat_and_later_eligibility_are_idempotent(
    session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AUDIT_RETENTION_DAYS", "10")
    first_now = datetime(2026, 11, 25, 12, 0, tzinfo=timezone.utc)
    event = append_at(session, monkeypatch, first_now - timedelta(days=9), "NEW")
    session.commit()

    first = run_retention(session, now=first_now)
    assert first.action_event_id is None
    second = run_retention(session, now=first_now + timedelta(days=2))
    assert second.archived_event_ids == (event.id,)
    session.commit()
    third = run_retention(session, now=first_now + timedelta(days=2))
    assert third.action_event_id is None


def test_reserved_event_types_require_the_internal_append_path(
    session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    timestamp = datetime(2026, 11, 25, 12, 0, tzinfo=timezone.utc)
    with pytest.raises(ReservedLifecycleEventTypeError):
        append_audit_event(
            session,
            event_type=AUDIT_RETENTION_APPLIED,
            actor_id="caller",
            resource_type="audit_log",
            resource_id="policy",
            payload={},
        )
    internal = append_lifecycle_audit_event(
        session,
        event_type=AUDIT_RETENTION_APPLIED,
        actor_id="audit-retention-service",
        resource_type="audit_log",
        resource_id="policy",
        payload={
            "archivedAt": "2026-11-25T12:00:00.000000Z",
            "archivedEventCount": 1,
            "archivedEventIds": [1],
            "cutoff": "2026-11-15T12:00:00.000000Z",
            "retentionDays": 10,
        },
        timestamp=timestamp,
    )
    assert internal.event_type == AUDIT_RETENTION_APPLIED
    session.rollback()


def test_retention_excludes_archived_and_reserved_events(
    session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AUDIT_RETENTION_DAYS", "10")
    now = datetime(2026, 11, 25, 12, 0, tzinfo=timezone.utc)
    old = append_at(session, monkeypatch, now - timedelta(days=20), "OLD")
    session.commit()
    run_retention(session, now=now)
    session.commit()

    repeat = run_retention(session, now=now + timedelta(days=1))
    assert repeat.archived_event_ids == ()
    assert repeat.action_event_id is None
    assert old.id is not None


def test_retention_rolls_back_action_metadata_and_checkpoint_together(
    session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AUDIT_RETENTION_DAYS", "10")
    now = datetime(2026, 11, 25, 12, 0, tzinfo=timezone.utc)
    old = append_at(session, monkeypatch, now - timedelta(days=20), "OLD")
    session.commit()
    old_id = old.id
    checkpoint_before = session.get(AuditChainState, 1)
    assert checkpoint_before is not None
    count_before = checkpoint_before.event_count

    run_retention(session, now=now)
    session.rollback()
    session.expunge_all()

    assert session.get(AuditEventArchive, 1) is None
    assert session.scalar(select(AuditEvent).where(AuditEvent.id == old_id)) is not None
    checkpoint_after = session.get(AuditChainState, 1)
    assert checkpoint_after is not None and checkpoint_after.event_count == count_before


def test_retention_rejects_corrupted_source_and_metadata_tampering_is_detected(
    session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AUDIT_RETENTION_DAYS", "10")
    now = datetime(2026, 11, 25, 12, 0, tzinfo=timezone.utc)
    old = append_at(session, monkeypatch, now - timedelta(days=20), "OLD")
    session.commit()
    old.payload = {"tampered": True}
    session.commit()
    with pytest.raises(AuditChainIntegrityError):
        run_retention(session, now=now)
    session.rollback()

    assert session.scalar(select(AuditEventArchive)) is None
    assert session.scalar(select(AuditEvent).where(AuditEvent.id == old.id)) is not None
    assert verify_audit_chain(session).is_intact is False


def test_archive_metadata_verification_and_archive_aware_querying(
    session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AUDIT_RETENTION_DAYS", "10")
    now = datetime(2026, 11, 25, 12, 0, tzinfo=timezone.utc)
    old = append_at(session, monkeypatch, now - timedelta(days=20), "OLD")
    recent = append_at(session, monkeypatch, now - timedelta(days=1), "RECENT")
    session.commit()
    retention = run_retention(session, now=now)
    session.commit()

    visible = query_audit_events(session, limit=1, offset=0)
    assert [event.id for event in visible] == [recent.id]
    all_events = query_audit_events(
        session, include_archived=True, limit=10, offset=0
    )
    assert [event.id for event in all_events] == [old.id, recent.id, retention.action_event_id]

    archive = session.scalar(select(AuditEventArchive))
    assert archive is not None
    session.delete(archive)
    session.commit()

    result = verify_audit_chain(session)
    assert result.violation_type == VIOLATION_ARCHIVE_METADATA_MISMATCH
    assert result.first_inconsistency_id == retention.action_event_id


def test_archive_verifier_detects_unexpected_metadata_and_timestamp_change(
    session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AUDIT_RETENTION_DAYS", "10")
    now = datetime(2026, 11, 25, 12, 0, tzinfo=timezone.utc)
    old = append_at(session, monkeypatch, now - timedelta(days=20), "OLD")
    recent = append_at(session, monkeypatch, now - timedelta(days=1), "RECENT")
    session.commit()
    retention = run_retention(session, now=now)
    session.commit()
    assert retention.action_event_id is not None

    session.add(
        AuditEventArchive(
            target_event_id=recent.id,
            archived_at=now,
            archive_action_event_id=retention.action_event_id,
        )
    )
    session.commit()
    assert verify_audit_chain(session).violation_type == VIOLATION_ARCHIVE_METADATA_MISMATCH
    session.delete(session.scalar(select(AuditEventArchive).where(AuditEventArchive.target_event_id == recent.id)))
    session.commit()

    session.execute(
        text("UPDATE audit_event_archives SET archived_at = :timestamp WHERE target_event_id = :target"),
        {"timestamp": "2026-11-25 12:00:01.000000", "target": old.id},
    )
    assert verify_audit_chain(session).violation_type == VIOLATION_ARCHIVE_METADATA_MISMATCH
    session.rollback()


def test_archive_verifier_handles_malformed_action_and_archived_payload_tampering(
    session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = datetime(2026, 11, 25, 12, 0, tzinfo=timezone.utc)
    old = append_at(session, monkeypatch, now - timedelta(days=20), "OLD")
    malformed = append_lifecycle_audit_event(
        session,
        event_type=AUDIT_RETENTION_APPLIED,
        actor_id="audit-retention-service",
        resource_type="audit_log",
        resource_id="policy",
        payload={"unexpected": True},
        timestamp=now,
    )
    session.commit()
    malformed_result = verify_audit_chain(session)
    assert malformed_result.violation_type == VIOLATION_ARCHIVE_MALFORMED_ACTION
    assert malformed_result.first_inconsistency_id == malformed.id

    session.delete(malformed)
    checkpoint = session.get(AuditChainState, 1)
    assert checkpoint is not None
    checkpoint.event_count = 1
    checkpoint.head_event_id = old.id
    checkpoint.head_chain_hash = old.chain_hash
    session.commit()
    old.payload = {"tampered": True}
    session.commit()
    assert verify_audit_chain(session).violation_type == VIOLATION_CONTENT_HASH_MISMATCH


def test_retention_metadata_flush_failure_rolls_back_caller_transaction(
    session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AUDIT_RETENTION_DAYS", "10")
    now = datetime(2026, 11, 25, 12, 0, tzinfo=timezone.utc)
    old = append_at(session, monkeypatch, now - timedelta(days=20), "OLD")
    session.commit()
    old_id = old.id
    original_flush = session.flush
    flush_count = 0

    def fail_metadata_flush(*args: object, **kwargs: object) -> None:
        nonlocal flush_count
        flush_count += 1
        if flush_count == 3:
            raise OperationalError("INSERT", {}, RuntimeError("metadata unavailable"))
        original_flush(*args, **kwargs)

    monkeypatch.setattr(session, "flush", fail_metadata_flush)
    with pytest.raises(OperationalError):
        run_retention(session, now=now)
    session.rollback()
    session.expunge_all()

    assert session.scalar(select(AuditEventArchive)) is None
    assert session.get(AuditEvent, old_id) is not None
    assert session.scalar(select(AuditEvent).where(AuditEvent.event_type == AUDIT_RETENTION_APPLIED)) is None


def test_physical_archived_event_deletion_is_detected_when_foreign_keys_are_bypassed(
    session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AUDIT_RETENTION_DAYS", "10")
    now = datetime(2026, 11, 25, 12, 0, tzinfo=timezone.utc)
    old = append_at(session, monkeypatch, now - timedelta(days=20), "OLD")
    session.commit()
    run_retention(session, now=now)
    session.commit()

    session.execute(text("PRAGMA foreign_keys=OFF"))
    session.execute(text("DELETE FROM audit_events WHERE id = :event_id"), {"event_id": old.id})
    session.commit()
    session.execute(text("PRAGMA foreign_keys=ON"))

    assert verify_audit_chain(session).is_intact is False
