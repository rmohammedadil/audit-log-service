import os
from pathlib import Path

from sqlalchemy import Engine, create_engine, inspect
from collections.abc import Generator

from sqlalchemy.orm import Session, declarative_base, sessionmaker

DEFAULT_AUDIT_DB_PATH = "audit_log_v2.db"


class AuditDatabaseConfigurationError(ValueError):
    """Raised when an explicitly configured audit database path is invalid."""


def database_url_from_path(configured_path: str | None) -> str:
    """Return the SQLite URL for an absent or explicitly valid path.

    A missing environment variable intentionally uses the documented V2
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
}


class IncompatibleAuditDatabaseError(RuntimeError):
    """Raised before writes when an existing database is not the V2 schema."""


def preflight_database_schema(database_engine: Engine) -> None:
    """Reject legacy or partially upgraded audit tables without modifying them.

    ``create_all`` only creates missing tables; it never upgrades old tables.
    Inspecting first prevents a V2 application from silently using the original
    V1 database or a partially upgraded copy as if it were compatible.
    """

    inspector = inspect(database_engine)
    existing_tables = set(inspector.get_table_names())
    audit_tables = set(EXPECTED_DATABASE_COLUMNS)
    present_audit_tables = audit_tables & existing_tables
    if not present_audit_tables:
        return
    if present_audit_tables != audit_tables:
        raise IncompatibleAuditDatabaseError(
            "incompatible audit database schema: configure AUDIT_DB_PATH to a fresh V2 database"
        )

    for table_name, expected_columns in EXPECTED_DATABASE_COLUMNS.items():
        actual_columns = {column["name"] for column in inspector.get_columns(table_name)}
        if actual_columns != expected_columns:
            raise IncompatibleAuditDatabaseError(
                "incompatible audit database schema: configure AUDIT_DB_PATH to a fresh V2 database"
            )

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
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
