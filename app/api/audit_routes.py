
"""HTTP endpoints for audit-event creation, retrieval, and verification."""

from datetime import datetime
import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import ValidationError
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas import (
    AuditChainVerificationRead,
    AuditEventCreate,
    AuditEventRead,
    AuditEventQueryRead,
    AuditAccessReportRead,
    AuditExportRequest,
    RedactionRead,
    RedactionRequest,
    RetentionRunRead,
    RetentionRunRequest,
)
from app.services.audit_service import (
    AuditChainIntegrityError,
    DEFAULT_QUERY_LIMIT,
    MAX_QUERY_LIMIT,
    append_audit_event,
    query_audit_events,
    query_access_reports,
    verify_audit_chain,
)
from app.services.retention_service import RetentionRunResult, run_retention
from app.models import AuditEventRedaction
from app.services.redaction_service import (
    RedactionNotFoundError,
    RedactionResult,
    redact_audit_event,
)
from app.services.audit_service import masked_payload
from app.services.export_service import create_audit_export
from app.auth import AuthenticatedIdentity, require_roles


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
    _: Annotated[AuthenticatedIdentity, Depends(require_roles("writer"))],
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


@router.post(
    "/events/{event_id}/redact",
    response_model=RedactionRead,
    response_model_by_alias=True,
)
def redact_event(
    event_id: int,
    request: RedactionRequest,
    database_session: Annotated[Session, Depends(get_db)],
    _: Annotated[AuthenticatedIdentity, Depends(require_roles("admin"))],
) -> RedactionRead:
    """Create a non-destructive redaction overlay in a trusted local setting."""

    try:
        result: RedactionResult = redact_audit_event(
            database_session, event_id=event_id, paths=request.paths, reason=request.reason
        )
        response = RedactionRead(
            targetEventId=result.target_event_id,
            newlyRedactedPathCount=len(result.newly_redacted_paths),
            newlyRedactedPaths=list(result.newly_redacted_paths),
            actionEventId=result.action_event_id,
        )
        database_session.commit()
    except RedactionNotFoundError:
        database_session.rollback()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit event not found") from None
    except AuditChainIntegrityError:
        database_session.rollback()
        logger.warning("Redaction blocked by audit integrity validation")
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Audit integrity check failed; redaction was not applied") from None
    except ValueError as error:
        database_session.rollback()
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(error)) from None
    except (SQLAlchemyError, ValidationError):
        database_session.rollback()
        logger.error("Redaction operation failed")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Unable to redact audit event") from None
    return response


@router.post(
    "/retention/run",
    response_model=RetentionRunRead,
    response_model_by_alias=True,
)
def run_configured_retention(
    database_session: Annotated[Session, Depends(get_db)],
    retention_request: RetentionRunRequest | None = None,
    _: Annotated[AuthenticatedIdentity, Depends(require_roles("admin"))] = None,
) -> RetentionRunRead:
    """Run the configured logical-archive policy in a trusted local setting.

    The empty request model rejects attempted client overrides. The route owns
    commit/rollback, while the service constructs the linked action event and
    archive metadata without committing.
    """

    del retention_request
    try:
        result: RetentionRunResult = run_retention(database_session)
        response = RetentionRunRead(
            retentionDays=result.retention_days,
            cutoff=result.cutoff,
            archivedEventCount=len(result.archived_event_ids),
            archivedEventIds=list(result.archived_event_ids),
            actionEventId=result.action_event_id,
        )
        database_session.commit()
    except AuditChainIntegrityError:
        database_session.rollback()
        logger.warning("Retention blocked by audit integrity validation")
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Audit integrity check failed; retention was not applied",
        ) from None
    except (SQLAlchemyError, ValidationError, ValueError, OverflowError):
        database_session.rollback()
        logger.error("Retention operation failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to apply retention policy",
        ) from None

    return response


@router.post("/exports")
def create_export(
    export_request: AuditExportRequest,
    database_session: Annotated[Session, Depends(get_db)],
    _: Annotated[AuthenticatedIdentity, Depends(require_roles("auditor", "admin"))],
) -> dict:
    """Return a verified, self-contained bundle without mutating source evidence."""

    try:
        # The export service verifies the complete persisted chain before it
        # reads a selected subset; it deliberately has no pagination limit.
        return create_audit_export(
            database_session,
            actor_id=export_request.actor_id,
            resource_id=export_request.resource_id,
            include_archived=export_request.include_archived,
        )
    except AuditChainIntegrityError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Audit integrity check failed; export was not created",
        ) from None
    except ValueError as error:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(error)) from None
    except (SQLAlchemyError, ValidationError):
        database_session.rollback()
        logger.error("Audit export failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to create audit export",
        ) from None


@router.get(
    "/access-reports",
    response_model=list[AuditAccessReportRead],
    response_model_by_alias=True,
)
def list_access_reports(
    from_timestamp: Annotated[datetime, Query(alias="from")],
    to_timestamp: Annotated[datetime, Query(alias="to")],
    database_session: Annotated[Session, Depends(get_db)],
    _: Annotated[AuthenticatedIdentity, Depends(require_roles("regulator"))],
    account_id: Annotated[str | None, Query(alias="accountId", min_length=1, max_length=256)] = None,
    actor_id: Annotated[str | None, Query(alias="actorId", min_length=1, max_length=256)] = None,
    operation: Annotated[str | None, Query(min_length=1, max_length=16)] = None,
    outcome: Annotated[str | None, Query(min_length=1, max_length=16)] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_QUERY_LIMIT)] = DEFAULT_QUERY_LIMIT,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[AuditAccessReportRead]:
    """Return only explicit client-account access evidence for future regulators.

    Authentication and regulator-role authorization are deliberately deferred;
    this endpoint is a trusted-local prototype boundary only.
    """

    try:
        events = query_access_reports(
            database_session,
            account_id=_validate_filter(account_id, "accountId"),
            actor_id=_validate_filter(actor_id, "actorId"),
            operation=_validate_filter(operation, "operation"),
            outcome=_validate_filter(outcome, "outcome"),
            from_timestamp=from_timestamp,
            to_timestamp=to_timestamp,
            limit=limit,
            offset=offset,
        )
        responses: list[AuditAccessReportRead] = []
        for event in events:
            paths = list(database_session.scalars(
                select(AuditEventRedaction.json_pointer)
                .where(AuditEventRedaction.target_event_id == event.id)
                .order_by(AuditEventRedaction.json_pointer.asc())
            ))
            base = AuditEventQueryRead.model_validate(event).model_dump()
            response = AuditAccessReportRead.model_validate({
                **base,
                "operation": event.payload["operation"],
                "outcome": event.payload["outcome"],
            })
            if paths:
                response = response.model_copy(update={
                    "payload": masked_payload(event.payload, paths), "redacted_paths": paths
                })
            responses.append(response)
        return responses
    except AuditChainIntegrityError:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Audit integrity check failed; report was not created") from None
    except ValueError as error:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(error)) from None
    except (SQLAlchemyError, ValidationError):
        database_session.rollback()
        logger.error("Access report retrieval failed")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Unable to retrieve access report") from None


@router.get(
    "/events",
    response_model=list[AuditEventQueryRead],
    response_model_by_alias=True,
)
def list_audit_events(
    database_session: Annotated[Session, Depends(get_db)],
    _: Annotated[AuthenticatedIdentity, Depends(require_roles("auditor", "admin"))],
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
    include_archived: Annotated[bool, Query(alias="includeArchived")] = False,
    limit: Annotated[
        int,
        Query(ge=1, le=MAX_QUERY_LIMIT, description="Maximum records to return"),
    ] = DEFAULT_QUERY_LIMIT,
    offset: Annotated[
        int,
        Query(ge=0, description="Records to skip before collecting a page"),
    ] = 0,
) -> list[AuditEventQueryRead]:
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
            include_archived=include_archived,
            limit=limit,
            offset=offset,
        )
    except AuditChainIntegrityError:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Lifecycle metadata cannot be trusted for retrieval") from None
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

    responses: list[AuditEventQueryRead] = []
    for event in events:
        paths = list(
            database_session.scalars(
                select(AuditEventRedaction.json_pointer)
                .where(AuditEventRedaction.target_event_id == event.id)
                .order_by(AuditEventRedaction.json_pointer.asc())
            )
        )
        response = AuditEventQueryRead.model_validate(event)
        if paths:
            response = response.model_copy(
                update={"payload": masked_payload(event.payload, paths), "redacted_paths": paths}
            )
        responses.append(response)
    return responses


@router.get(
    "/verify",
    response_model=AuditChainVerificationRead,
    response_model_by_alias=True,
)
def verify_audit_events(
    database_session: Annotated[Session, Depends(get_db)],
    _: Annotated[AuthenticatedIdentity, Depends(require_roles("auditor", "regulator", "admin"))],
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
