"""Development-only isolated V4 application; it mounts no V3 audit routes."""
from __future__ import annotations
import os
from fastapi import FastAPI
from app.api.v4_audit_routes import build_v4_router
from app.auth import jwt_configuration
from app.v4_database import initialize_v4_database

def create_v4_app(path: str) -> FastAPI:
    jwt_configuration()
    app=FastAPI(title="Audit Log Service V4")
    app.include_router(build_v4_router(initialize_v4_database(path)))
    @app.get("/health")
    def health(): return {"status":"ok"}
    return app

def _path() -> str:
    value=os.environ.get("AUDIT_V4_DB_PATH")
    if not value or not value.strip(): raise RuntimeError("AUDIT_V4_DB_PATH is required for the isolated V4 application")
    return value

app=create_v4_app(_path())
