"""Operational isolated V4 application; it never mounts legacy audit routes."""
from __future__ import annotations
import os, json, logging, re
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator
from time import perf_counter
from uuid import uuid4
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from app.api.v4_audit_routes import build_v4_router
from app.auth import jwt_configuration
from app.v4_database import initialize_v4_database
from app.services.retention_service import configured_retention_days
from app.export_signing import sign_digest_if_configured

logger=logging.getLogger("app.operations")

def create_v4_app(path: str) -> FastAPI:
    engine=initialize_v4_database(path)
    def initialize() -> None:
        jwt_configuration(); configured_retention_days()
        if os.environ.get("AUDIT_EXPORT_PRIVATE_KEY_PATH") is not None: sign_digest_if_configured("0"*64)
    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        application.state.initializer(); yield; engine.dispose()
    app=FastAPI(title="Audit Log Service V4",lifespan=lifespan)
    app.state.initializer=initialize; app.state.engine=engine
    app.include_router(build_v4_router(engine))
    @app.middleware("http")
    async def operational(request: Request, call_next):
        supplied=request.headers.get("X-Request-ID")
        request_id=supplied if supplied and re.fullmatch(r"[A-Za-z0-9._-]{1,64}",supplied) else uuid4().hex; started=perf_counter()
        try: response=await call_next(request)
        except Exception:
            logger.error(json.dumps({"event":"unexpected_request_failure","request_id":request_id,"status":500}))
            response=JSONResponse(status_code=500,content={"detail":"Internal server error"})
        response.headers["X-Request-ID"]=request_id
        logger.info(json.dumps({"event":"request_complete","request_id":request_id,"method":request.method,"route":request.url.path,"status":response.status_code,"duration_ms":round((perf_counter()-started)*1000,2)})); return response
    @app.get("/")
    def root(): return {"message":"Audit Log Service V4 is running"}
    @app.get("/health")
    def health(): return {"status":"healthy"}
    @app.get("/ready")
    def ready(request: Request):
        try:
            with request.app.state.engine.connect() as connection: connection.execute(text("SELECT 1"))
        except SQLAlchemyError: return JSONResponse(status_code=503,content={"status":"unavailable"})
        return {"status":"ready"}
    return app

def _path() -> str:
    value=os.environ.get("AUDIT_V4_DB_PATH")
    if not value or not value.strip(): raise RuntimeError("AUDIT_V4_DB_PATH is required for the V4 application")
    return value

app=create_v4_app(_path())
