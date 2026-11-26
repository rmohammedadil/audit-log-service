"""Focused coverage for the isolated V4 tenant-scoped persistence foundation."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.authorization_models import TenantPrincipal
from app.database import Base
from app.services.audit_service import calculate_content_hash
from app.services.v4_audit_service import (
    V4_GENESIS_CONTENT_HASH,
    V4IntegrityError,
    append_v4_audit_event,
    begin_v4_write_transaction,
    calculate_v4_chain_hash,
    calculate_v4_content_hash,
    canonicalize_v4_content,
    v4_genesis_chain_hash,
    verify_v4_tenant_chain,
)
from app.v4_database import IncompatibleV4DatabaseError, V4_SCHEMA_VERSION, initialize_v4_database
from app.v4_models import (
    V4AuditEvent,
    V4AuditEventArchive,
    V4AuditEventIdempotency,
    V4AuditEventRedaction,
    V4SchemaState,
    V4TenantChainState,
)


@pytest.fixture
def v4_engine(tmp_path):
    engine = initialize_v4_database(str(tmp_path / "v4.sqlite"))
    yield engine
    engine.dispose()


def _append(session: Session, tenant: str, value: str = "one") -> V4AuditEvent:
    return append_v4_audit_event(
        session, tenant_id=tenant, event_type="ACCOUNT_UPDATED", actor_id="writer-a",
        resource_type="customer_account", resource_id="account-1", payload={"value": value},
        timestamp=datetime(2026, 1, 2, 3, 4, 5, 678901, tzinfo=timezone.utc),
    )


def test_v4_metadata_is_isolated_and_fresh_database_has_complete_schema(v4_engine) -> None:
    assert set(V4AuditEvent.__table__.metadata.tables).isdisjoint(Base.metadata.tables)
    with Session(v4_engine) as session:
        assert session.scalar(select(V4SchemaState.schema_version)) == V4_SCHEMA_VERSION


def test_v4_initializer_rejects_legacy_and_partial_targets_without_mutation(tmp_path) -> None:
    for name, ddl in (("legacy.sqlite", "CREATE TABLE audit_events (id INTEGER PRIMARY KEY)"), ("partial.sqlite", "CREATE TABLE tenant_principals (id INTEGER PRIMARY KEY)")):
        path = tmp_path / name
        with sqlite3.connect(path) as connection:
            connection.execute(ddl)
        with pytest.raises(IncompatibleV4DatabaseError):
            initialize_v4_database(str(path))
        with sqlite3.connect(path) as connection:
            assert len(connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()) == 1


def test_v4_initializer_reopens_complete_schema_and_enforces_foreign_keys(v4_engine, tmp_path) -> None:
    path = tmp_path / "reopen.sqlite"
    first = initialize_v4_database(str(path))
    first.dispose()
    second = initialize_v4_database(str(path))
    with second.connect() as connection:
        assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar() == 1
    second.dispose()


def test_v4_hashing_is_deterministic_and_binds_tenant_reference_and_sequence() -> None:
    values = dict(tenant_id="tenant-a", event_ref="00000000-0000-4000-8000-000000000001", event_type="READ", actor_id="a", resource_type="customer_account", resource_id="r", payload={"b": 2, "a": 1}, timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc))
    first = calculate_v4_content_hash(**values)
    assert first == calculate_v4_content_hash(**{**values, "payload": {"a": 1, "b": 2}})
    assert first != calculate_v4_content_hash(**{**values, "tenant_id": "tenant-b"})
    assert first != calculate_v4_content_hash(**{**values, "event_ref": "00000000-0000-4000-8000-000000000002"})
    genesis = v4_genesis_chain_hash("tenant-a")
    assert calculate_v4_chain_hash(tenant_id="tenant-a", tenant_sequence=1, content_hash=first, previous_chain_hash=genesis) != calculate_v4_chain_hash(tenant_id="tenant-a", tenant_sequence=2, content_hash=first, previous_chain_hash=genesis)
    assert V4_GENESIS_CONTENT_HASH != first
    assert canonicalize_v4_content(**values) == canonicalize_v4_content(**values)
    with pytest.raises(ValueError):
        canonicalize_v4_content(**{**values, "payload": ["not-an-object"]})
    with pytest.raises(ValueError):
        calculate_v4_chain_hash(tenant_id="tenant-a", tenant_sequence=1, content_hash=first, previous_chain_hash=genesis, hash_scheme_version="unknown")


def test_tenant_chains_are_independent_and_checkpointed(v4_engine) -> None:
    with Session(v4_engine) as session:
        begin_v4_write_transaction(session)
        first_a = _append(session, "tenant-a", "a1")
        first_b = _append(session, "tenant-b", "b1")
        second_a = _append(session, "tenant-a", "a2")
        first_a_id, first_b_id, second_a_id = first_a.id, first_b.id, second_a.id
        session.commit()
    with Session(v4_engine) as session:
        tenant_a = list(session.scalars(select(V4AuditEvent).where(V4AuditEvent.tenant_id == "tenant-a").order_by(V4AuditEvent.tenant_sequence)))
        tenant_b = session.get(V4AuditEvent, first_b_id)
        assert [item.tenant_sequence for item in tenant_a] == [1, 2]
        assert tenant_a[0].id == first_a_id and tenant_a[1].id == second_a_id
        assert tenant_a[0].resource_id == tenant_b.resource_id
        assert tenant_a[1].previous_chain_hash == tenant_a[0].chain_hash
        assert verify_v4_tenant_chain(session, "tenant-a").is_intact
        assert verify_v4_tenant_chain(session, "tenant-b").is_intact


def test_append_and_checkpoint_are_rolled_back_together(v4_engine) -> None:
    with Session(v4_engine) as session:
        begin_v4_write_transaction(session)
        _append(session, "tenant-a")
        session.rollback()
    with Session(v4_engine) as session:
        assert session.scalar(select(V4AuditEvent.id)) is None
        assert session.get(V4TenantChainState, "tenant-a") is None


def test_empty_tenant_and_checkpoint_version_inconsistency(v4_engine) -> None:
    with Session(v4_engine) as session:
        assert verify_v4_tenant_chain(session, "tenant-a").is_intact
        session.add(V4TenantChainState(tenant_id="tenant-a", hash_scheme_version="unknown", event_count=0, head_sequence=None, head_chain_hash=None))
        session.commit()
    with Session(v4_engine) as session:
        assert not verify_v4_tenant_chain(session, "tenant-a").is_intact


def test_v4_verification_does_not_flush_caller_pending_changes(v4_engine) -> None:
    with Session(v4_engine) as session:
        session.add(TenantPrincipal(tenant_id="tenant-a", subject="pending", active=True))
        assert verify_v4_tenant_chain(session, "tenant-a").is_intact
        assert session.new
        session.rollback()
    with Session(v4_engine) as session:
        assert session.scalar(select(TenantPrincipal.id)) is None


def test_v4_verification_uses_persisted_checkpoint_not_stale_identity_map(v4_engine) -> None:
    with Session(v4_engine) as session:
        begin_v4_write_transaction(session); _append(session, "tenant-a"); session.commit()
    with Session(v4_engine) as session:
        assert session.get(V4TenantChainState, "tenant-a") is not None
        with v4_engine.begin() as connection:
            connection.exec_driver_sql("UPDATE v4_tenant_chain_state SET event_count=7 WHERE tenant_id='tenant-a'")
        assert not verify_v4_tenant_chain(session, "tenant-a").is_intact


@pytest.mark.parametrize("column, value", [("tenant_id", "tenant-b"), ("tenant_sequence", 8), ("content_hash", "0" * 64), ("previous_chain_hash", "0" * 64)])
def test_v4_verification_detects_tenant_chain_evidence_tampering(v4_engine, column: str, value: object) -> None:
    with Session(v4_engine) as session:
        begin_v4_write_transaction(session); event = _append(session, "tenant-a"); session.commit(); event_id = event.id
    with Session(v4_engine) as session:
        event = session.get(V4AuditEvent, event_id)
        setattr(event, column, value)
        session.commit()
    with Session(v4_engine) as session:
        assert not verify_v4_tenant_chain(session, "tenant-a").is_intact


def test_inconsistent_chain_rejects_append(v4_engine) -> None:
    with Session(v4_engine) as session:
        begin_v4_write_transaction(session); event = _append(session, "tenant-a"); session.commit(); event_id = event.id
    with Session(v4_engine) as session:
        session.get(V4AuditEvent, event_id).payload = {"value": "changed"}; session.commit()
    with Session(v4_engine) as session:
        begin_v4_write_transaction(session)
        with pytest.raises(V4IntegrityError):
            _append(session, "tenant-a", "new")
        session.rollback()


@pytest.mark.parametrize("column, value", [("payload", "{not-json"), ("timestamp", "not-a-timestamp")])
def test_v4_verification_reports_malformed_persisted_evidence(v4_engine, column: str, value: str) -> None:
    with Session(v4_engine) as session:
        begin_v4_write_transaction(session); event = _append(session, "tenant-a"); session.commit(); event_id = event.id
    with v4_engine.begin() as connection:
        connection.exec_driver_sql(f"UPDATE v4_audit_events SET {column}=? WHERE id=?", (value, event_id))
    with Session(v4_engine) as session:
        result = verify_v4_tenant_chain(session, "tenant-a")
        assert not result.is_intact and result.first_inconsistency_sequence == 1


def test_concurrent_independent_sessions_serialize_tenant_sequences(v4_engine) -> None:
    """SQLite's immediate write transaction prevents two checkpoints racing."""
    barrier = Barrier(2)
    def write(value: str) -> int:
        with Session(v4_engine) as session:
            barrier.wait(timeout=3)
            begin_v4_write_transaction(session)
            event = _append(session, "tenant-a", value)
            session.commit()
            return event.id
    with ThreadPoolExecutor(max_workers=2) as pool:
        ids = list(pool.map(write, ("one", "two")))
    with Session(v4_engine) as session:
        events = list(session.scalars(select(V4AuditEvent).where(V4AuditEvent.tenant_id == "tenant-a").order_by(V4AuditEvent.tenant_sequence)))
        assert len(set(ids)) == 2
        assert [event.tenant_sequence for event in events] == [1, 2]
        assert session.get(V4TenantChainState, "tenant-a").event_count == 2
        assert verify_v4_tenant_chain(session, "tenant-a").is_intact


def test_v4_lifecycle_and_idempotency_foreign_keys_are_tenant_bound(v4_engine) -> None:
    with Session(v4_engine) as session:
        begin_v4_write_transaction(session)
        target = _append(session, "tenant-a", "target")
        action = _append(session, "tenant-a", "action")
        other = _append(session, "tenant-b", "other")
        session.add(TenantPrincipal(tenant_id="tenant-a", subject="writer-a", active=True))
        session.flush()
        session.add(V4AuditEventArchive(tenant_id="tenant-a", target_event_id=target.id, archive_action_event_id=action.id, archived_at=datetime.now(timezone.utc)))
        session.add(V4AuditEventRedaction(tenant_id="tenant-a", target_event_id=target.id, json_pointer="/secret", redaction_action_event_id=action.id, redacted_at=datetime.now(timezone.utc), redaction_reason="PRIVACY"))
        session.add(V4AuditEventIdempotency(tenant_id="tenant-a", writer_subject="writer-a", idempotency_key="key", request_fingerprint="1" * 64, event_id=target.id))
        target_id, other_id = target.id, other.id
        session.commit()
    with Session(v4_engine) as session:
        session.add(V4AuditEventArchive(tenant_id="tenant-a", target_event_id=target_id, archive_action_event_id=other_id, archived_at=datetime.now(timezone.utc)))
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()


def test_same_idempotency_key_is_valid_for_different_tenant_scopes(v4_engine) -> None:
    with Session(v4_engine) as session:
        begin_v4_write_transaction(session)
        first, second = _append(session, "tenant-a"), _append(session, "tenant-b")
        session.add_all([TenantPrincipal(tenant_id="tenant-a", subject="writer-a", active=True), TenantPrincipal(tenant_id="tenant-b", subject="writer-a", active=True)])
        session.flush()
        session.add_all([
            V4AuditEventIdempotency(tenant_id="tenant-a", writer_subject="writer-a", idempotency_key="same", request_fingerprint="a" * 64, event_id=first.id),
            V4AuditEventIdempotency(tenant_id="tenant-b", writer_subject="writer-a", idempotency_key="same", request_fingerprint="b" * 64, event_id=second.id),
        ])
        session.commit()


def test_v4_reuses_no_v3_content_hash_contract(v4_engine) -> None:
    """The V4 hash is additive; existing V3 content hashing remains callable."""
    assert calculate_content_hash(event_type="READ", actor_id="a", resource_type="r", resource_id="id", payload={"x": 1}, timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc))
