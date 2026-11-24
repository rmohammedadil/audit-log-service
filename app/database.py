from sqlalchemy import create_engine
from collections.abc import Generator

from sqlalchemy.orm import Session, declarative_base, sessionmaker

DATABASE_URL = "sqlite:///./audit_log.db"

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
