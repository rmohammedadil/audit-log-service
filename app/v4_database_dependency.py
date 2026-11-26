"""Request-scoped sessions for the explicitly selected V4 application."""
from __future__ import annotations
from collections.abc import Generator
from sqlalchemy import Engine
from sqlalchemy.orm import Session

def get_v4_db(engine: Engine) -> Generator[Session, None, None]:
    session = Session(engine)
    try: yield session
    finally: session.close()
