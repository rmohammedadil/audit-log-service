from contextlib import asynccontextmanager
from collections.abc import AsyncIterator, Callable

from fastapi import FastAPI

from app import models  # Registers SQLAlchemy models before schema creation.
from app.api.audit_routes import router as audit_router
from app.database import Base, engine


def initialize_database() -> None:
    """Create prototype tables for the configured database when the app starts."""

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
