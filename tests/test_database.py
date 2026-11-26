"""Tests for safe V3 database initialization and schema rejection."""

from pathlib import Path

import pytest
from sqlalchemy import Engine, create_engine, inspect
from sqlalchemy.exc import OperationalError, SQLAlchemyError
from sqlalchemy.orm import Session

from tests import legacy_app as application_main
from app import models  # Registers V3 models with the shared declarative base.
from app.database import (
    DEFAULT_AUDIT_DB_PATH,
    EXPECTED_DATABASE_COLUMNS,
    AuditDatabaseConfigurationError,
    IncompatibleAuditDatabaseError,
    Base,
    database_url_from_path,
    preflight_database_schema,
    begin_write_transaction,
)
from app.services.audit_service import append_audit_event, verify_audit_chain


V2_TABLE_COLUMNS = {
    "audit_events": {
        "id",
        "event_type",
        "actor_id",
        "resource_type",
        "resource_id",
        "payload",
        "timestamp",
        "previous_hash",
        "content_hash",
        "hash_scheme_version",
        "previous_chain_hash",
        "chain_hash",
    },
    "audit_chain_state": {
        "singleton_id",
        "hash_scheme_version",
        "event_count",
        "head_event_id",
        "head_chain_hash",
    },
}


def create_table_with_columns(
    database_engine: Engine, table_name: str, columns: set[str]
) -> None:
    """Create simplified tables for name-based preflight rejection tests."""

    column_definitions = ", ".join(f'"{column}" TEXT' for column in sorted(columns))
    with database_engine.begin() as connection:
        connection.exec_driver_sql(f'CREATE TABLE "{table_name}" ({column_definitions})')


def test_database_url_uses_documented_default_when_path_is_absent() -> None:
    assert database_url_from_path(None) == "sqlite:///audit_log_v3.db"
    assert DEFAULT_AUDIT_DB_PATH == "audit_log_v3.db"


@pytest.mark.parametrize("configured_path", ["", "   ", "\t"])
def test_database_url_rejects_explicit_empty_or_whitespace_path(
    configured_path: str,
) -> None:
    with pytest.raises(AuditDatabaseConfigurationError, match="must not be empty"):
        database_url_from_path(configured_path)


def test_database_url_preserves_relative_absolute_and_spaced_paths(tmp_path: Path) -> None:
    relative_path = "runtime/audit log.db"
    absolute_path = tmp_path / "Audit Data" / "audit log v3.db"

    assert database_url_from_path(relative_path) == "sqlite:///runtime/audit log.db"
    assert database_url_from_path(str(absolute_path)) == (
        f"sqlite:///{absolute_path.as_posix()}"
    )

    absolute_path.parent.mkdir()
    engine = create_engine(database_url_from_path(str(absolute_path)))
    try:
        preflight_database_schema(engine)
        Base.metadata.create_all(engine)
        preflight_database_schema(engine)
        assert absolute_path.exists()
    finally:
        engine.dispose()


def test_preflight_allows_fresh_database_then_accepts_created_v3_schema(
    tmp_path: Path,
) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'fresh-v3.db'}")
    try:
        preflight_database_schema(engine)
        Base.metadata.create_all(engine)
        preflight_database_schema(engine)

        inspector = inspect(engine)
        for table_name, expected_columns in EXPECTED_DATABASE_COLUMNS.items():
            assert {column["name"] for column in inspector.get_columns(table_name)} == expected_columns
    finally:
        engine.dispose()


def test_preflight_rejects_legacy_v1_schema_without_mutating_database(tmp_path: Path) -> None:
    database_path = tmp_path / "legacy-v1.db"
    engine = create_engine(f"sqlite:///{database_path}")
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql(
                "CREATE TABLE audit_events (id INTEGER PRIMARY KEY, content_hash VARCHAR(64) NOT NULL)"
            )
            connection.exec_driver_sql(
                "CREATE TABLE audit_chain_state (singleton_id INTEGER PRIMARY KEY, event_count INTEGER NOT NULL)"
            )
        before = database_path.read_bytes()

        with pytest.raises(IncompatibleAuditDatabaseError, match="fresh V3 database"):
            preflight_database_schema(engine)

        assert database_path.read_bytes() == before
    finally:
        engine.dispose()


def test_preflight_accepts_an_existing_compatible_v3_database(tmp_path: Path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'existing-v3.db'}")
    try:
        Base.metadata.create_all(engine)

        preflight_database_schema(engine)
    finally:
        engine.dispose()


def test_database_initializer_allows_an_existing_compatible_v3_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'startup-v3.db'}")
    try:
        Base.metadata.create_all(engine)
        monkeypatch.setattr(application_main, "engine", engine)
        # Startup must validate explicit JWT settings even for an isolated DB.
        monkeypatch.setenv("AUDIT_JWT_SIGNING_KEY", "test-signing-key-with-at-least-thirty-two-characters")
        monkeypatch.setenv("AUDIT_JWT_ISSUER", "audit-test")
        monkeypatch.setenv("AUDIT_JWT_AUDIENCE", "audit-api")

        application_main.initialize_database()
    finally:
        engine.dispose()


def test_sqlite_immediate_write_lock_serializes_chain_appends(tmp_path: Path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'lock.db'}", connect_args={"timeout": 0.1})
    try:
        Base.metadata.create_all(engine)
        with Session(engine) as first, Session(engine) as second:
            begin_write_transaction(first)
            append_audit_event(first, event_type="ONE", actor_id="a", resource_type="r", resource_id="1", payload={})
            with pytest.raises(OperationalError):
                begin_write_transaction(second)
            first.commit()
            begin_write_transaction(second)
            append_audit_event(second, event_type="TWO", actor_id="b", resource_type="r", resource_id="2", payload={})
            second.commit()
        with Session(engine) as verifier:
            assert verify_audit_chain(verifier).is_intact is True
    finally:
        engine.dispose()


def test_readiness_sanitizes_database_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    class BrokenEngine:
        def connect(self):
            raise SQLAlchemyError("sensitive database path")

    monkeypatch.setattr(application_main, "engine", BrokenEngine())
    response = application_main.readiness_check()
    assert response.status_code == 503
    assert response.body == b'{"status":"unavailable"}'


def test_preflight_rejects_v2_schema_without_mutating_database(tmp_path: Path) -> None:
    database_path = tmp_path / "existing-v2.db"
    engine = create_engine(f"sqlite:///{database_path}")
    try:
        for table_name, columns in V2_TABLE_COLUMNS.items():
            create_table_with_columns(engine, table_name, columns)
        before = database_path.read_bytes()

        with pytest.raises(IncompatibleAuditDatabaseError, match="fresh V3 database"):
            preflight_database_schema(engine)

        assert database_path.read_bytes() == before
    finally:
        engine.dispose()


def test_preflight_rejects_partial_v3_schema_without_mutating_database(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "partial-v3.db"
    engine = create_engine(f"sqlite:///{database_path}")
    try:
        for table_name, columns in EXPECTED_DATABASE_COLUMNS.items():
            incomplete_columns = (
                columns - {"redaction_action_event_id"}
                if table_name == "audit_event_redactions"
                else columns
            )
            create_table_with_columns(engine, table_name, incomplete_columns)
        before = database_path.read_bytes()

        with pytest.raises(IncompatibleAuditDatabaseError, match="fresh V3 database"):
            preflight_database_schema(engine)

        assert database_path.read_bytes() == before
    finally:
        engine.dispose()


def test_preflight_rejects_mixed_audit_schema_without_mutating_database(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "mixed-v3.db"
    engine = create_engine(f"sqlite:///{database_path}")
    try:
        Base.metadata.create_all(engine)
        create_table_with_columns(engine, "audit_legacy_metadata", {"id"})
        before = database_path.read_bytes()

        with pytest.raises(IncompatibleAuditDatabaseError, match="fresh V3 database"):
            preflight_database_schema(engine)

        assert database_path.read_bytes() == before
    finally:
        engine.dispose()
