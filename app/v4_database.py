"""Explicit fresh V4 database initialization; V3 startup never imports this."""
from __future__ import annotations
import sqlite3
from pathlib import Path
from sqlalchemy import Engine, create_engine, event, inspect, select
from sqlalchemy.orm import Session
from app.authorization_models import AuthorizationBase
from app.v4_models import V4Base, V4SchemaState

V4_SCHEMA_VERSION = "audit-v4"
class IncompatibleV4DatabaseError(RuntimeError): pass

def _url(path: str) -> str:
    if not isinstance(path, str) or not path.strip(): raise IncompatibleV4DatabaseError("an explicit V4 database path is required")
    return f"sqlite:///{Path(path).as_posix()}"
def _fk(connection: object, record: object) -> None:
    del record
    if isinstance(connection, sqlite3.Connection): connection.execute("PRAGMA foreign_keys=ON")
def _expected() -> dict[str, set[str]]:
    result = {}
    for metadata in (AuthorizationBase.metadata, V4Base.metadata):
        for table in metadata.tables.values(): result[table.name] = {column.name for column in table.columns}
    # ``tenant_principals`` is a V4 metadata resolution bridge; the
    # authorization metadata above remains the authoritative table definition.
    result["tenant_principals"] = {column.name for column in AuthorizationBase.metadata.tables["tenant_principals"].columns}
    return result
def initialize_v4_database(path: str) -> Engine:
    """Create a fresh V4 target or open only a fully compatible V4 target.

    This deliberately refuses partial and legacy schemas before ``create_all``
    can add tables to them.  V3 application startup does not call this function.
    """
    engine = create_engine(_url(path), connect_args={"check_same_thread": False, "timeout": 5})
    event.listen(engine, "connect", _fk)
    expected = _expected(); inspector = inspect(engine); tables = set(inspector.get_table_names())
    if tables:
        if tables != set(expected): raise IncompatibleV4DatabaseError("database is not a complete compatible V4 target")
        for name, columns in expected.items():
            if {item["name"] for item in inspector.get_columns(name)} != columns: raise IncompatibleV4DatabaseError("database is not a complete compatible V4 target")
        with Session(engine) as session:
            states = list(session.scalars(select(V4SchemaState)))
            if len(states) != 1 or states[0].schema_version != V4_SCHEMA_VERSION: raise IncompatibleV4DatabaseError("database has an incompatible V4 schema version")
        return engine
    AuthorizationBase.metadata.create_all(engine); V4Base.metadata.create_all(engine)
    with Session(engine) as session:
        session.add(V4SchemaState(schema_version=V4_SCHEMA_VERSION)); session.commit()
    return engine
