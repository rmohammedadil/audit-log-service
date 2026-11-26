from __future__ import annotations
import sqlite3
import pytest
from fastapi.testclient import TestClient
from fastapi import APIRouter
from sqlalchemy.exc import OperationalError
from app.v4_database import IncompatibleV4DatabaseError

@pytest.fixture
def operational_app(tmp_path,monkeypatch):
    monkeypatch.setenv("AUDIT_JWT_SIGNING_KEY","operational-test-signing-key-at-least-thirty-two-chars")
    monkeypatch.setenv("AUDIT_JWT_ISSUER","operational")
    monkeypatch.setenv("AUDIT_JWT_AUDIENCE","operational")
    monkeypatch.setenv("AUDIT_RETENTION_DAYS","30")
    monkeypatch.setenv("AUDIT_V4_DB_PATH",str(tmp_path/"v4.sqlite"))
    from app.v4_main import create_v4_app
    return create_v4_app(str(tmp_path/"v4.sqlite"))

def test_v4_operational_surface_and_request_ids(operational_app):
    with TestClient(operational_app) as client:
        assert client.get("/").json()["message"].endswith("running")
        assert client.get("/health").json()=={"status":"healthy"}
        assert client.get("/ready").json()=={"status":"ready"}
        assert client.get("/docs").status_code==200 and client.get("/redoc").status_code==200
        paths=client.get("/openapi.json").json()["paths"]
        assert {"/audit/events","/audit/verify","/audit/exports","/audit/access-reports","/audit/retention/run"} <= set(paths)
        assert client.get("/audit/chain").status_code==404
        assert client.get("/health",headers={"X-Request-ID":"safe-id_1"}).headers["X-Request-ID"]=="safe-id_1"
        assert client.get("/health",headers={"X-Request-ID":"bad id"}).headers["X-Request-ID"]!="bad id"

@pytest.mark.parametrize("value",[None,"", "   "])
def test_v4_path_requires_explicit_nonblank_value(monkeypatch,value):
    if value is None: monkeypatch.delenv("AUDIT_V4_DB_PATH",raising=False)
    else: monkeypatch.setenv("AUDIT_V4_DB_PATH",value)
    from app.v4_main import _path
    with pytest.raises(RuntimeError): _path()

def test_v4_initializer_rejects_legacy_database_without_repair(tmp_path):
    path=tmp_path/"legacy.sqlite"
    with sqlite3.connect(path) as connection: connection.execute("CREATE TABLE audit_events (id INTEGER PRIMARY KEY)")
    from app.v4_database import initialize_v4_database
    with pytest.raises(IncompatibleV4DatabaseError): initialize_v4_database(str(path))
    with sqlite3.connect(path) as connection: assert connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()==[("audit_events",)]

def test_v4_readiness_failure_is_sanitized_and_liveness_survives(operational_app,monkeypatch):
    class Broken:
        def connect(self): raise OperationalError("SELECT secret",{},Exception("credentials"))
    monkeypatch.setattr(operational_app.state,"engine",Broken())
    with TestClient(operational_app) as client:
        assert client.get("/health").status_code==200
        response=client.get("/ready")
        assert response.status_code==503 and response.json()=={"status":"unavailable"}

@pytest.mark.parametrize("environment",[
    {"AUDIT_JWT_SIGNING_KEY":"short"},
    {"AUDIT_RETENTION_DAYS":"invalid"},
    {"AUDIT_EXPORT_PRIVATE_KEY_PATH":"missing.pem"},
])
def test_v4_startup_configuration_fails_closed(tmp_path,monkeypatch,environment):
    monkeypatch.setenv("AUDIT_JWT_SIGNING_KEY","operational-test-signing-key-at-least-thirty-two-chars"); monkeypatch.setenv("AUDIT_JWT_ISSUER","issuer"); monkeypatch.setenv("AUDIT_JWT_AUDIENCE","audience")
    for key,value in environment.items(): monkeypatch.setenv(key,value)
    from app.v4_main import create_v4_app
    app=create_v4_app(str(tmp_path/"v4.sqlite"))
    with pytest.raises(Exception):
        with TestClient(app): pass

def test_v4_unexpected_errors_are_sanitized_and_correlated(operational_app):
    @operational_app.get("/boom")
    def boom(): raise RuntimeError("secret-token-and-sql")
    with TestClient(operational_app) as client:
        response=client.get("/boom")
    assert response.status_code==500 and response.json()=={"detail":"Internal server error"}
    assert response.headers.get("X-Request-ID") and "secret" not in response.text
