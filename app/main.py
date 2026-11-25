from contextlib import asynccontextmanager
from collections.abc import AsyncIterator, Callable
from time import perf_counter
import json
import logging
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app import models  # Registers SQLAlchemy models before schema creation.
from app.api.audit_routes import router as audit_router
from app.database import Base, engine, preflight_database_schema
from app.services.retention_service import configured_retention_days
from app.auth import jwt_configuration

logger = logging.getLogger("app.operations")


def initialize_database() -> None:
    """Preflight the configured database before creating fresh V3 tables."""

    # Reject an unsafe explicit policy before opening or mutating a database.
    configured_retention_days()
    jwt_configuration()
    preflight_database_schema(engine)
    Base.metadata.create_all(bind=engine)


@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncIterator[None]:
    """Initialize the configured database once per application lifespan.

    Tests replace ``database_initializer`` before starting the client, so
    startup never creates or changes the project's SQLite database in tests.
    """

    initializer: Callable[[], None] = application.state.database_initializer
    initializer()
    yield

app = FastAPI(
    title="Audit Log Service",
    description="A tamper-evident audit logging service",
    version="0.1.0",
    lifespan=lifespan,
)
app.state.database_initializer = initialize_database
app.include_router(audit_router)


@app.middleware("http")
async def request_observability(request: Request, call_next):
    """Emit safe request metadata without logging credentials or evidence."""

    request_id = uuid4().hex
    started = perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        # Do not include exception text: drivers can embed SQL or evidence.
        logger.error(json.dumps({"request_id": request_id, "method": request.method,
                                 "route": request.url.path, "status": 500,
                                 "event": "unexpected_request_failure"}))
        response = JSONResponse(status_code=500, content={"detail": "Internal server error"})
    response.headers["X-Request-ID"] = request_id
    route = request.scope.get("route")
    route_path = getattr(route, "path", request.url.path)
    logger.info(json.dumps({"request_id": request_id, "method": request.method,
                            "route": route_path, "status": response.status_code,
                            "duration_ms": round((perf_counter() - started) * 1000, 2),
                            "event": "request_complete"}))
    return response


@app.get("/")
def root():
    return {
        "message": "Audit Log Service is running"
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy"
    }


@app.get("/ready")
def readiness_check():
    """Readiness checks a lightweight database operation without details."""

    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except SQLAlchemyError:
        logger.error("readiness database check failed")
        return JSONResponse(status_code=503, content={"status": "unavailable"})
    return {"status": "ready"}
