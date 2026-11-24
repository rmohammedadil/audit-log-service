
"""HTTP endpoints for audit-event creation."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import ValidationError
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas import AuditEventCreate, AuditEventRead
from app.services.audit_service import append_audit_event


router = APIRouter(prefix="/audit", tags=["audit"])


@router.post(
    "/events",
    response_model=AuditEventRead,
    response_model_by_alias=True,
    status_code=status.HTTP_201_CREATED,
)
def create_audit_event(
    event_input: AuditEventCreate,
    database_session: Annotated[Session, Depends(get_db)],
) -> AuditEventRead:
    """Create one audit event and commit only after its response validates.

    The append service owns timestamp assignment and hash-link construction.
    The route owns commit/rollback because it is the HTTP transaction boundary.
    """

    try:
        event = append_audit_event(
            database_session,
            event_type=event_input.event_type,
            actor_id=event_input.actor_id,
            resource_type=event_input.resource_type,
            resource_id=event_input.resource_id,
            payload=event_input.payload,
        )
        response = AuditEventRead.model_validate(event)
        database_session.commit()
    except (SQLAlchemyError, ValidationError):
        database_session.rollback()
        # Database details are intentionally withheld from public responses.
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to persist audit event",
        ) from None

    return response
