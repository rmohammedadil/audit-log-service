"""Focused tests for non-destructive payload redaction."""

from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from app.database import Base
from app.models import AuditChainState, AuditEvent, AuditEventRedaction
from app.services import audit_service
from app.services.audit_service import (
    AUDIT_REDACTION_APPLIED,
    REDACTION_MARKER,
    VIOLATION_REDACTION_METADATA_MISMATCH,
    append_audit_event,
    masked_payload,
    verify_audit_chain,
)
from app.services.redaction_service import redact_audit_event, validate_redaction_request


@pytest.fixture()
def session() -> Session:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as database_session:
        yield database_session
    Base.metadata.drop_all(engine)
    engine.dispose()


def append_target(session: Session, monkeypatch: pytest.MonkeyPatch) -> AuditEvent:
    monkeypatch.setattr(audit_service, "utc_now", lambda: datetime(2026, 11, 25, 10, 0, tzinfo=timezone.utc))
    event = append_audit_event(
        session,
        event_type="RECORD_UPDATED",
        actor_id="advisor-42",
        resource_type="client_account",
        resource_id="account-1",
        payload={"profile": {"phone": "555", "a/b": "slash", "~key": "tilde"}, "items": [{"ssn": "111"}]},
    )
    session.commit()
    return event


def test_json_pointer_validation_and_projection() -> None:
    payload = {"profile": {"phone": "555", "a/b": "slash", "~key": "tilde"}, "items": [{"ssn": "111"}]}
    paths = validate_redaction_request(payload, ["/profile/a~1b", "/profile/~0key", "/items/0/ssn"], "SENSITIVE_DATA")
    projected = masked_payload(payload, list(paths))
    assert projected["profile"]["a/b"] == REDACTION_MARKER
    assert projected["profile"]["~key"] == REDACTION_MARKER
    assert projected["items"][0]["ssn"] == REDACTION_MARKER
    assert payload["items"][0]["ssn"] == "111"
    for invalid in ([], [""], ["/missing"], ["/items/-"], ["/items/-1"], ["/profile", "/profile/phone"]):
        with pytest.raises(ValueError):
            validate_redaction_request(payload, invalid, "SENSITIVE_DATA")


def test_redaction_creates_metadata_action_and_noop(session: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    target = append_target(session, monkeypatch)
    original_evidence = (target.payload.copy(), target.content_hash, target.chain_hash)
    result = redact_audit_event(session, event_id=target.id, paths=["/profile/phone", "/items/0/ssn"], reason="SENSITIVE_DATA", now=datetime(2026, 11, 25, 12, 0, tzinfo=timezone.utc))
    session.commit()
    assert result.newly_redacted_paths == ("/items/0/ssn", "/profile/phone")
    action = session.get(AuditEvent, result.action_event_id)
    assert action is not None and action.event_type == AUDIT_REDACTION_APPLIED
    assert action.payload["targetEventId"] == target.id
    assert session.scalar(select(AuditEventRedaction).where(AuditEventRedaction.target_event_id == target.id)) is not None
    checkpoint = session.get(AuditChainState, 1)
    assert checkpoint is not None and checkpoint.event_count == 2
    assert (target.payload, target.content_hash, target.chain_hash) == original_evidence
    assert verify_audit_chain(session).is_intact is True
    repeat = redact_audit_event(session, event_id=target.id, paths=["/profile/phone"], reason="PRIVACY_REQUEST")
    assert repeat.action_event_id is None


def test_redaction_metadata_tampering_is_detected(session: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    target = append_target(session, monkeypatch)
    redact_audit_event(session, event_id=target.id, paths=["/profile/phone"], reason="SENSITIVE_DATA")
    session.commit()
    metadata = session.scalar(select(AuditEventRedaction))
    assert metadata is not None
    session.delete(metadata)
    session.commit()
    assert verify_audit_chain(session).violation_type == VIOLATION_REDACTION_METADATA_MISMATCH


def test_redaction_flush_failure_rolls_back_action_metadata_and_original_evidence(
    session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = append_target(session, monkeypatch)
    target_id = target.id
    original_hash = target.content_hash
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
        redact_audit_event(session, event_id=target_id, paths=["/profile/phone"], reason="SENSITIVE_DATA")
    session.rollback()
    session.expunge_all()
    stored = session.get(AuditEvent, target_id)
    assert stored is not None and stored.content_hash == original_hash
    assert session.scalar(select(AuditEventRedaction)) is None
    assert session.scalar(select(AuditEvent).where(AuditEvent.event_type == AUDIT_REDACTION_APPLIED)) is None
