
"""HTTP endpoints for audit-event creation, retrieval, and verification."""

from datetime import datetime
import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import ValidationError
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas import AuditChainVerificationRead, AuditEventCreate, AuditEventRead
from app.services.audit_service import (
    AuditChainIntegrityError,
    DEFAULT_QUERY_LIMIT,
    MAX_QUERY_LIMIT,
    append_audit_event,
    query_audit_events,
    verify_audit_chain,
)


router = APIRouter(prefix="/audit", tags=["audit"])
logger = logging.getLogger(__name__)


def _validate_filter(value: str | None, public_name: str) -> str | None:
    """Reject whitespace-only filters after FastAPI applies length limits."""

    if value is None:
        return None
    normalized_value = value.strip()
    if not normalized_value:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"{public_name} must not be blank",
        )
    return normalized_value


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
    except AuditChainIntegrityError:
        database_session.rollback()
        # Log only the outcome: checkpoint details may reveal audit evidence.
        logger.warning("Audit append blocked by checkpoint integrity validation")
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Audit chain integrity check failed; event was not appended",
        ) from None
    except (SQLAlchemyError, ValidationError):
        database_session.rollback()
        # Database details are intentionally withheld from public responses.
        logger.error("Audit event persistence failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to persist audit event",
        ) from None

    return response


@router.get(
    "/events",
    response_model=list[AuditEventRead],
    response_model_by_alias=True,
)
def list_audit_events(
    database_session: Annotated[Session, Depends(get_db)],
    actor_id: Annotated[
        str | None,
        Query(alias="actorId", min_length=1, max_length=256),
    ] = None,
    resource_type: Annotated[
        str | None,
        Query(alias="resourceType", min_length=1, max_length=128),
    ] = None,
    resource_id: Annotated[
        str | None,
        Query(alias="resourceId", min_length=1, max_length=256),
    ] = None,
    event_type: Annotated[
        str | None,
        Query(alias="eventType", min_length=1, max_length=128),
    ] = None,
    from_timestamp: Annotated[datetime | None, Query(alias="from")] = None,
    to_timestamp: Annotated[datetime | None, Query(alias="to")] = None,
    limit: Annotated[
        int,
        Query(ge=1, le=MAX_QUERY_LIMIT, description="Maximum records to return"),
    ] = DEFAULT_QUERY_LIMIT,
    offset: Annotated[
        int,
        Query(ge=0, description="Records to skip before collecting a page"),
    ] = 0,
) -> list[AuditEventRead]:
    """Retrieve events through the read-only service using public aliases.

    FastAPI publishes the camelCase aliases and parses primitive query values;
    the service remains responsible for UTC boundary normalization, cumulative
    filtering, ordering, and read-only SQLAlchemy query construction.
    """

    try:
        events = query_audit_events(
            database_session,
            actor_id=_validate_filter(actor_id, "actorId"),
            resource_type=_validate_filter(resource_type, "resourceType"),
            resource_id=_validate_filter(resource_id, "resourceId"),
            event_type=_validate_filter(event_type, "eventType"),
            from_timestamp=from_timestamp,
            to_timestamp=to_timestamp,
            limit=limit,
            offset=offset,
        )
    except ValueError as error:
        # Validation errors from the reusable service become client errors.
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(error),
        ) from None
    except SQLAlchemyError:
        database_session.rollback()
        # Avoid returning driver, SQL, or database-path details to clients.
        logger.error("Audit event retrieval failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to retrieve audit events",
        ) from None

    return [AuditEventRead.model_validate(event) for event in events]


@router.get(
    "/verify",
    response_model=AuditChainVerificationRead,
    response_model_by_alias=True,
)
def verify_audit_events(
    database_session: Annotated[Session, Depends(get_db)],
) -> AuditChainVerificationRead:
    """Return the verifier's read-only integrity result for the full chain.

    An inconsistent chain is a successful verification outcome, so it remains
    HTTP 200. Only an operational database failure becomes HTTP 500. The
    service deliberately owns verification precedence and evidence handling;
    this route only serializes its structured result.
    """

    try:
        result = verify_audit_chain(database_session)
        return AuditChainVerificationRead.model_validate(result)
    except (SQLAlchemyError, ValidationError):
        database_session.rollback()
        # Do not include SQL, database paths, or evidence values in the log.
        logger.error("Audit chain verification failed during database operation")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to verify audit chain",
        ) from None
