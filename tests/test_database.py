"""Tests for safe V2 database initialization and legacy-schema rejection."""

from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect

from app import models  # Registers V2 models with the shared declarative base.
from app.database import (
    DEFAULT_AUDIT_DB_PATH,
    EXPECTED_DATABASE_COLUMNS,
    AuditDatabaseConfigurationError,
    IncompatibleAuditDatabaseError,
    Base,
    database_url_from_path,
    preflight_database_schema,
)


def test_database_url_uses_documented_default_when_path_is_absent() -> None:
    assert database_url_from_path(None) == "sqlite:///audit_log_v2.db"
    assert DEFAULT_AUDIT_DB_PATH == "audit_log_v2.db"


@pytest.mark.parametrize("configured_path", ["", "   ", "\t"])
def test_database_url_rejects_explicit_empty_or_whitespace_path(
    configured_path: str,
) -> None:
    with pytest.raises(AuditDatabaseConfigurationError, match="must not be empty"):
        database_url_from_path(configured_path)


def test_database_url_preserves_relative_absolute_and_spaced_paths(tmp_path: Path) -> None:
    relative_path = "runtime/audit log.db"
    absolute_path = tmp_path / "Audit Data" / "audit log v2.db"

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


def test_preflight_allows_fresh_database_then_accepts_created_v2_schema(
    tmp_path: Path,
) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'fresh-v2.db'}")
    try:
        preflight_database_schema(engine)
        Base.metadata.create_all(engine)
        preflight_database_schema(engine)

        inspector = inspect(engine)
        for table_name, expected_columns in EXPECTED_DATABASE_COLUMNS.items():
            assert {column["name"] for column in inspector.get_columns(table_name)} == expected_columns
    finally:
        engine.dispose()


def test_preflight_rejects_legacy_schema_without_mutating_database(tmp_path: Path) -> None:
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

        with pytest.raises(IncompatibleAuditDatabaseError, match="fresh V2 database"):
            preflight_database_schema(engine)

        assert database_path.read_bytes() == before
    finally:
        engine.dispose()
