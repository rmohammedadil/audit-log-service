"""Isolated V4 tenant-scoped event API; legacy routes are never mounted here."""
from __future__ import annotations
from typing import Annotated
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Response, status
from sqlalchemy import Engine, select, tuple_
from sqlalchemy.orm import Session
from app.auth import TenantAuthenticatedIdentity, require_v4_roles
from app.authorization_models import ResourceGrant
from app.authorization_service import AuthorizationDeniedError, active_tenant_principal, require_resource_grant
from app.permissions import ResourcePermission
from app.services.v4_audit_service import V4IdempotencyConflictError, append_v4_audit_event, begin_v4_write_transaction, find_v4_replay, v4_request_fingerprint, verify_v4_tenant_chain
from app.v4_database_dependency import get_v4_db
from app.v4_models import V4AuditEvent, V4AuditEventIdempotency
from app.v4_schemas import V4AuditEventCreate, V4AuditEventRead

router=APIRouter(prefix="/audit", tags=["v4-audit"])
def _key(value: str | None) -> str | None:
    if value is None: return None
    if not value or len(value)>128 or not all(char.isalnum() or char in ".:_-" for char in value): raise HTTPException(422,"Idempotency-Key is invalid")
    return value
def _session(engine: Engine):
    def dependency(): yield from get_v4_db(engine)
    return dependency
def _safe_integrity(session: Session, tenant: str) -> None:
    if not verify_v4_tenant_chain(session,tenant).is_intact: raise HTTPException(409,"Audit integrity verification failed")

def build_v4_router(engine: Engine) -> APIRouter:
    api=APIRouter(prefix="/audit", tags=["v4-audit"])
    db=Depends(_session(engine))
    @api.post("/events", response_model=V4AuditEventRead, status_code=201)
    def create_event(body: V4AuditEventCreate, response: Response, identity: Annotated[TenantAuthenticatedIdentity, Depends(require_v4_roles("writer"))], session: Session=db, idempotency_key: Annotated[str|None,Header(alias="Idempotency-Key")]=None):
        key=_key(idempotency_key)
        try:
            begin_v4_write_transaction(session)
            require_resource_grant(session,identity,resource_type=body.resource_type,resource_id=body.resource_id,permission=ResourcePermission.CREATE_EVENT)
            fingerprint=v4_request_fingerprint(body.event_type,body.actor_id,body.resource_type,body.resource_id,body.payload)
            replay=find_v4_replay(session,identity.tenant_id,identity.subject,key,fingerprint) if key else None
            if replay is not None:
                _safe_integrity(session,identity.tenant_id); session.commit(); response.status_code=200; return V4AuditEventRead.model_validate(replay)
            event=append_v4_audit_event(session,tenant_id=identity.tenant_id,event_type=body.event_type,actor_id=body.actor_id,resource_type=body.resource_type,resource_id=body.resource_id,payload=body.payload)
            if key: session.add(V4AuditEventIdempotency(tenant_id=identity.tenant_id,writer_subject=identity.subject,idempotency_key=key,request_fingerprint=fingerprint,event_id=event.id))
            session.commit(); return V4AuditEventRead.model_validate(event)
        except AuthorizationDeniedError: session.rollback(); raise HTTPException(403,"Insufficient permissions") from None
        except V4IdempotencyConflictError: session.rollback(); raise HTTPException(409,"Idempotency key conflicts with a different request") from None
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
            statement=statement.where(tuple_(V4AuditEvent.resource_type,V4AuditEvent.resource_id).in_(grants)).order_by(V4AuditEvent.tenant_sequence).offset(offset).limit(limit)
            _safe_integrity(session,identity.tenant_id)
            return [V4AuditEventRead.model_validate(event) for event in session.scalars(statement)]
        except AuthorizationDeniedError: raise HTTPException(403,"Insufficient permissions") from None
    return api
