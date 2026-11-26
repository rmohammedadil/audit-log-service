"""Isolated V4 tenant-scoped event API; legacy routes are never mounted here."""
from __future__ import annotations
from typing import Annotated
import os
from datetime import datetime, timezone
from fastapi import APIRouter, Body, Depends, Header, HTTPException, Query, Response, status
from sqlalchemy import Engine, select, tuple_
from sqlalchemy.orm import Session
from app.auth import TenantAuthenticatedIdentity, require_v4_roles
from app.authorization_models import ResourceGrant
from app.authorization_service import AuthorizationDeniedError, active_tenant_principal, require_resource_grant, require_tenant_grant
from app.permissions import ResourcePermission, TenantPermission
from app.services.v4_audit_service import V4IdempotencyConflictError, V4IntegrityError, append_v4_audit_event, archive_v4_events, begin_v4_write_transaction, find_v4_replay, redact_v4_event, v4_redacted_payload, v4_request_fingerprint, verify_v4_lifecycle, verify_v4_tenant_chain
from app.v4_database_dependency import get_v4_db
from app.v4_models import V4AuditEvent, V4AuditEventArchive, V4AuditEventIdempotency
from app.v4_schemas import V4AuditEventCreate, V4AuditEventRead, V4ExportRequest
from app.schemas import RedactionRequest
from app.services.audit_service import ACCESS_OPERATIONS, ACCESS_OUTCOMES, CLIENT_ACCOUNT_ACCESS, ACCESS_RESOURCE_TYPE, is_canonical_access_payload
from app.services.v4_export_service import create_v4_export

router=APIRouter(prefix="/audit", tags=["v4-audit"])
def _key(value: str | None) -> str | None:
    if value is None: return None
    if not value or len(value)>128 or not all(char.isalnum() or char in ".:_-" for char in value): raise HTTPException(422,"Idempotency-Key is invalid")
    return value
def _session(engine: Engine):
    def dependency(): yield from get_v4_db(engine)
    return dependency
def _safe_integrity(session: Session, tenant: str) -> None:
    if not verify_v4_tenant_chain(session,tenant).is_intact or not verify_v4_lifecycle(session,tenant): raise HTTPException(409,"Audit integrity verification failed")

def build_v4_router(engine: Engine) -> APIRouter:
    api=APIRouter(prefix="/audit", tags=["v4-audit"])
    db=Depends(_session(engine))
    @api.post("/events", response_model=V4AuditEventRead, status_code=201)
    def create_event(body: V4AuditEventCreate, response: Response, identity: Annotated[TenantAuthenticatedIdentity, Depends(require_v4_roles("writer"))], session: Session=db, idempotency_key: Annotated[str|None,Header(alias="Idempotency-Key")]=None):
        key=_key(idempotency_key)
        if body.event_type.startswith("V4_EVENT_"): raise HTTPException(422,"eventType is reserved for internal lifecycle operations")
        try:
            begin_v4_write_transaction(session)
            require_resource_grant(session,identity,resource_type=body.resource_type,resource_id=body.resource_id,permission=ResourcePermission.CREATE_EVENT)
            fingerprint=v4_request_fingerprint(body.event_type,body.actor_id,body.resource_type,body.resource_id,body.payload)
            replay=find_v4_replay(session,identity.tenant_id,identity.subject,key,fingerprint) if key else None
            if replay is not None:
                _safe_integrity(session,identity.tenant_id); payload,_=v4_redacted_payload(session,replay); session.commit(); response.status_code=200; return V4AuditEventRead.model_validate(replay).model_copy(update={"payload":payload})
            event=append_v4_audit_event(session,tenant_id=identity.tenant_id,event_type=body.event_type,actor_id=body.actor_id,resource_type=body.resource_type,resource_id=body.resource_id,payload=body.payload)
            if key: session.add(V4AuditEventIdempotency(tenant_id=identity.tenant_id,writer_subject=identity.subject,idempotency_key=key,request_fingerprint=fingerprint,event_id=event.id))
            session.commit(); return V4AuditEventRead.model_validate(event)
        except AuthorizationDeniedError: session.rollback(); raise HTTPException(403,"Insufficient permissions") from None
        except V4IdempotencyConflictError: session.rollback(); raise HTTPException(409,"Idempotency key conflicts with a different request") from None
        except V4IntegrityError: session.rollback(); raise HTTPException(409,"Audit integrity verification failed") from None
        except HTTPException: session.rollback(); raise
        except Exception: session.rollback(); raise HTTPException(500,"Audit event creation failed") from None
    @api.get("/events", response_model=list[V4AuditEventRead])
    def list_events(identity: Annotated[TenantAuthenticatedIdentity, Depends(require_v4_roles("auditor","admin","writer"))], session: Session=db, actor_id: str|None=Query(None,alias="actorId"), resource_type: str|None=Query(None,alias="resourceType"), resource_id: str|None=Query(None,alias="resourceId"), limit: int=Query(100,ge=1,le=1000), offset: int=Query(0,ge=0,le=1_000_000)):
        try:
            principal=active_tenant_principal(session,identity)
            grants=list(session.execute(select(ResourceGrant.resource_type,ResourceGrant.resource_id).where(ResourceGrant.tenant_id==identity.tenant_id,ResourceGrant.principal_id==principal.id,ResourceGrant.permission==ResourcePermission.READ_EVENT.value,ResourceGrant.active.is_(True))).all())
            statement=select(V4AuditEvent).where(V4AuditEvent.tenant_id==identity.tenant_id)
            if resource_type: statement=statement.where(V4AuditEvent.resource_type==resource_type)
            if resource_id: statement=statement.where(V4AuditEvent.resource_id==resource_id)
            if actor_id: statement=statement.where(V4AuditEvent.actor_id==actor_id)
            if not grants: return []
            archived=select(V4AuditEventArchive.target_event_id).where(V4AuditEventArchive.tenant_id==identity.tenant_id)
            statement=statement.where(tuple_(V4AuditEvent.resource_type,V4AuditEvent.resource_id).in_(grants),~V4AuditEvent.id.in_(archived),~V4AuditEvent.event_type.like("V4_EVENT_%")).order_by(V4AuditEvent.tenant_sequence).offset(offset).limit(limit)
            _safe_integrity(session,identity.tenant_id)
            return [V4AuditEventRead.model_validate(event).model_copy(update={"payload":v4_redacted_payload(session,event)[0]}) for event in session.scalars(statement)]
        except AuthorizationDeniedError: raise HTTPException(403,"Insufficient permissions") from None
    @api.post("/events/{event_ref}/redact")
    def redact_event(event_ref: str, body: RedactionRequest, identity: Annotated[TenantAuthenticatedIdentity, Depends(require_v4_roles("admin"))], session: Session=db):
        try:
            begin_v4_write_transaction(session)
            target=session.scalar(select(V4AuditEvent).where(V4AuditEvent.tenant_id==identity.tenant_id,V4AuditEvent.event_ref==event_ref))
            if target is None: raise HTTPException(404,"Audit event not found")
            require_resource_grant(session,identity,resource_type=target.resource_type,resource_id=target.resource_id,permission=ResourcePermission.REDACT_EVENT)
            _safe_integrity(session,identity.tenant_id)
            _,paths=redact_v4_event(session,tenant_id=identity.tenant_id,event_ref=event_ref,paths=body.paths,reason=body.reason,operator=identity.subject)
            session.commit(); return {"redactedPaths":paths}
        except AuthorizationDeniedError: session.rollback(); raise HTTPException(404,"Audit event not found") from None
        except HTTPException: session.rollback(); raise
        except ValueError: session.rollback(); raise HTTPException(422,"Invalid redaction request") from None
        except Exception: session.rollback(); raise HTTPException(500,"Redaction failed") from None
    @api.post("/retention/run")
    def run_retention(identity: Annotated[TenantAuthenticatedIdentity, Depends(require_v4_roles("admin"))], session: Session=db):
        try:
            begin_v4_write_transaction(session)
            require_tenant_grant(session,identity,permission=TenantPermission.RUN_RETENTION)
            _safe_integrity(session,identity.tenant_id)
            days=int(os.environ.get("AUDIT_RETENTION_DAYS","30"))
            count=archive_v4_events(session,tenant_id=identity.tenant_id,retention_days=days,operator=identity.subject)
            session.commit(); return {"archivedEventCount":count}
        except AuthorizationDeniedError: session.rollback(); raise HTTPException(403,"Insufficient permissions") from None
        except HTTPException: session.rollback(); raise
        except Exception: session.rollback(); raise HTTPException(500,"Retention failed") from None
    @api.get("/verify")
    def verify_tenant(identity: Annotated[TenantAuthenticatedIdentity, Depends(require_v4_roles("auditor","admin","regulator"))], session: Session=db):
        try:
            require_tenant_grant(session,identity,permission=TenantPermission.VERIFY_TENANT_CHAIN)
            result=verify_v4_tenant_chain(session,identity.tenant_id)
            # The tenant-wide permission permits this tenant result only; no
            # cross-tenant references or detailed corruption diagnostics leak.
            return {"isIntact":result.is_intact,"checkedRecordCount":result.checked_record_count}
        except AuthorizationDeniedError: raise HTTPException(403,"Insufficient permissions") from None
    @api.get("/access-reports")
    def access_reports(from_timestamp: Annotated[datetime,Query(alias="from")], to_timestamp: Annotated[datetime,Query(alias="to")], identity: Annotated[TenantAuthenticatedIdentity, Depends(require_v4_roles("regulator"))], session: Session=db, account_id: str|None=Query(None,alias="accountId"), actor_id: str|None=Query(None,alias="actorId"), operation: str|None=None, outcome: str|None=None, include_archived: bool=Query(True,alias="includeArchived"), limit: int=Query(100,ge=1,le=1000), offset: int=Query(0,ge=0,le=1_000_000)):
        try:
            if from_timestamp.tzinfo is None or to_timestamp.tzinfo is None or from_timestamp > to_timestamp or (operation is not None and operation not in ACCESS_OPERATIONS) or (outcome is not None and outcome not in ACCESS_OUTCOMES): raise HTTPException(422,"Invalid report filters")
            principal=active_tenant_principal(session,identity)
            grants=list(session.execute(select(ResourceGrant.resource_type,ResourceGrant.resource_id).where(ResourceGrant.tenant_id==identity.tenant_id,ResourceGrant.principal_id==principal.id,ResourceGrant.permission==ResourcePermission.READ_ACCESS_REPORT.value,ResourceGrant.active.is_(True))).all())
            if not grants: return []
            statement=select(V4AuditEvent).where(V4AuditEvent.tenant_id==identity.tenant_id,V4AuditEvent.event_type==CLIENT_ACCOUNT_ACCESS,V4AuditEvent.resource_type==ACCESS_RESOURCE_TYPE,V4AuditEvent.timestamp>=from_timestamp.astimezone(timezone.utc),V4AuditEvent.timestamp<=to_timestamp.astimezone(timezone.utc),tuple_(V4AuditEvent.resource_type,V4AuditEvent.resource_id).in_(grants))
            if account_id: statement=statement.where(V4AuditEvent.resource_id==account_id)
            if actor_id: statement=statement.where(V4AuditEvent.actor_id==actor_id)
            if not include_archived: statement=statement.where(~V4AuditEvent.id.in_(select(V4AuditEventArchive.target_event_id).where(V4AuditEventArchive.tenant_id==identity.tenant_id)))
            _safe_integrity(session,identity.tenant_id)
            events=[event for event in session.scalars(statement.order_by(V4AuditEvent.tenant_sequence)) if is_canonical_access_payload(event.payload) and (operation is None or event.payload["operation"]==operation) and (outcome is None or event.payload["outcome"]==outcome)]
            return [V4AuditEventRead.model_validate(event).model_copy(update={"payload":v4_redacted_payload(session,event)[0]}) for event in events[offset:offset+limit]]
        except AuthorizationDeniedError: raise HTTPException(403,"Insufficient permissions") from None
    @api.post("/exports")
    def export_events(body: V4ExportRequest, identity: Annotated[TenantAuthenticatedIdentity, Depends(require_v4_roles("auditor","admin"))]=None, session: Session=db):
        try:
            actor,resource,archived=body.actor_id,body.resource_id,body.include_archived
            principal=active_tenant_principal(session,identity); require_tenant_grant(session,identity,permission=TenantPermission.EXPORT_TENANT_WITNESS)
            grants=set(session.execute(select(ResourceGrant.resource_type,ResourceGrant.resource_id).where(ResourceGrant.tenant_id==identity.tenant_id,ResourceGrant.principal_id==principal.id,ResourceGrant.permission==ResourcePermission.EXPORT_RESOURCE.value,ResourceGrant.active.is_(True))).all())
            if resource is not None and ("customer_account",resource) not in grants: raise PermissionError()
            return create_v4_export(session,tenant_id=identity.tenant_id,actor_id=actor,resource_id=resource,include_archived=archived,authorized=grants)
        except AuthorizationDeniedError: raise HTTPException(403,"Insufficient permissions") from None
        except PermissionError: raise HTTPException(403,"Insufficient permissions") from None
        except ValueError: raise HTTPException(409,"Audit integrity verification failed") from None
    return api
