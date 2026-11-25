import os
import sqlite3
from pathlib import Path

from sqlalchemy import Engine, create_engine, event, inspect
from collections.abc import Generator

from sqlalchemy.orm import Session, declarative_base, sessionmaker

DEFAULT_AUDIT_DB_PATH = "audit_log_v3.db"


class AuditDatabaseConfigurationError(ValueError):
    """Raised when an explicitly configured audit database path is invalid."""


def database_url_from_path(configured_path: str | None) -> str:
    """Return the SQLite URL for an absent or explicitly valid path.

    A missing environment variable intentionally uses the documented V3
    default. An explicitly empty value is rejected instead of silently
    selecting another database, which could hide an operator mistake.
    """

    database_path = DEFAULT_AUDIT_DB_PATH if configured_path is None else configured_path
    if not database_path.strip():
        raise AuditDatabaseConfigurationError(
            "AUDIT_DB_PATH must not be empty or whitespace-only"
        )
    return f"sqlite:///{Path(database_path).as_posix()}"


AUDIT_DB_PATH = os.environ.get("AUDIT_DB_PATH")
DATABASE_URL = database_url_from_path(AUDIT_DB_PATH)

EXPECTED_DATABASE_COLUMNS = {
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
    "audit_event_archives": {
        "id",
        "target_event_id",
        "archived_at",
        "archive_action_event_id",
    },
    "audit_event_redactions": {
        "id",
        "target_event_id",
        "json_pointer",
        "redacted_at",
        "redaction_reason",
        "redaction_action_event_id",
    },
    "audit_event_idempotency": {"id", "writer_subject", "idempotency_key", "request_fingerprint", "event_id"},
}


class IncompatibleAuditDatabaseError(RuntimeError):
    """Raised before writes when an existing database is not the V3 schema."""


def _enable_sqlite_foreign_keys(
    dbapi_connection: object, connection_record: object
) -> None:
    """Enable SQLite foreign keys for every project-created SQLite connection.

    SQLite parses foreign-key declarations but does not enforce them unless
    each connection enables this pragma. The metadata tables rely on their
    target and lifecycle-action references, so silently leaving enforcement
    off would make their declared integrity boundary misleading.
    """

    del connection_record
    if isinstance(dbapi_connection, sqlite3.Connection):
        dbapi_connection.execute("PRAGMA foreign_keys=ON")


# Tests construct isolated SQLite engines directly; an Engine-level listener
# keeps their foreign-key behavior aligned with the application engine.
event.listen(Engine, "connect", _enable_sqlite_foreign_keys)


def preflight_database_schema(database_engine: Engine) -> None:
    """Reject non-V3 audit schemas before ``create_all`` can modify them.

    ``create_all`` only creates missing tables; it never upgrades old tables.
    Inspecting all tables with the ``audit_`` prefix first prevents V3 startup
    from silently adding metadata tables to V1, V2, partial, or mixed audit
    schemas. This checks names and column-name sets only, not types,
    constraints, indexes, or SQLite table definitions.
    """

    inspector = inspect(database_engine)
    existing_tables = set(inspector.get_table_names())
    audit_tables = set(EXPECTED_DATABASE_COLUMNS)
    additive_tables = {"audit_event_idempotency"}
    present_audit_tables = {
        table_name for table_name in existing_tables if table_name.startswith("audit_")
    }
    if not present_audit_tables:
        return
    if present_audit_tables not in (audit_tables, audit_tables - additive_tables):
        raise IncompatibleAuditDatabaseError(
            "incompatible audit database schema: configure AUDIT_DB_PATH to a fresh V3 database"
        )

    for table_name, expected_columns in EXPECTED_DATABASE_COLUMNS.items():
        if table_name not in present_audit_tables:
            continue
        actual_columns = {column["name"] for column in inspector.get_columns(table_name)}
        if actual_columns != expected_columns:
            raise IncompatibleAuditDatabaseError(
                "incompatible audit database schema: configure AUDIT_DB_PATH to a fresh V3 database"
            )

engine = create_engine(
    DATABASE_URL,
    # SQLite waits briefly for a competing writer instead of immediately
    # failing; routes still never retry non-idempotent writes automatically.
    connect_args={"check_same_thread": False, "timeout": 5},
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)

Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """Yield one request-scoped session without taking transaction ownership.

    Routes decide when to commit or roll back because the appropriate boundary
    depends on the HTTP operation. Closing here releases resources even when a
    route raises an exception.
    """

    database_session = SessionLocal()
    try:
        yield database_session
    finally:
        database_session.close()


def begin_write_transaction(database_session: Session) -> None:
    """Acquire SQLite's reserved write lock before an append/lifecycle write.

    ``BEGIN IMMEDIATE`` coordinates competing local SQLite writers through the
    database lock. It is not distributed concurrency control and callers keep
    commit/rollback ownership.
    """

    if database_session.bind is not None and database_session.bind.dialect.name == "sqlite":
        database_session.connection().exec_driver_sql("BEGIN IMMEDIATE")
