"""Tenant-specific V4 append and verification primitives; no HTTP integration."""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from uuid import UUID, uuid4
from sqlalchemy import select, text
from sqlalchemy.orm import Session
from app.auth import validate_tenant_id
from app.models import utc_now
from app.v4_models import V4AuditEvent, V4TenantChainState
from app.v4_models import V4AuditEventIdempotency
from app.v4_models import V4AuditEventRedaction, V4AuditEventArchive
from app.services.audit_service import REDACTION_REASON_CODES, masked_payload, validate_json_pointer

class V4IdempotencyConflictError(Exception): pass

V4_HASH_SCHEME_VERSION = "audit-tenant-chain-v1"
V4_CHAIN_DOMAIN = "audit-tenant-chain-hash"
V4_GENESIS_CONTENT_HASH = sha256(b"audit-tenant-content-genesis-v1").hexdigest()
class V4IntegrityError(Exception): pass
@dataclass(frozen=True)
class V4VerificationResult: is_intact: bool; checked_record_count: int; first_inconsistency_sequence: int | None; detail: str
def _json(value: dict) -> bytes: return json.dumps(value, sort_keys=True, separators=(",",":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None: raise ValueError("timestamp must include timezone information")
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00","Z")
def _persisted_payload(value: object) -> dict:
    if not isinstance(value, str): raise ValueError("persisted payload is not JSON text")
    decoded = json.loads(value)
    if type(decoded) is not dict: raise ValueError("persisted payload is not a JSON object")
    return decoded
def _persisted_timestamp(value: object) -> datetime:
    if not isinstance(value, str): raise ValueError("persisted timestamp is invalid")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
def _event_ref(value: str) -> str:
    try: return str(UUID(value))
    except (ValueError, TypeError, AttributeError) as error: raise ValueError("event reference must be a UUID") from error
def v4_genesis_chain_hash(tenant_id: str) -> str:
    return sha256(_json({"domain":V4_CHAIN_DOMAIN,"hashSchemeVersion":V4_HASH_SCHEME_VERSION,"tenantId":validate_tenant_id(tenant_id),"genesis":True})).hexdigest()
def canonicalize_v4_content(*, tenant_id: str, event_ref: str, event_type: str, actor_id: str, resource_type: str, resource_id: str, payload: dict, timestamp: datetime) -> bytes:
    if type(payload) is not dict: raise ValueError("payload must be a JSON object")
    return _json({"tenantId":validate_tenant_id(tenant_id),"eventRef":_event_ref(event_ref),"eventType":event_type,"actorId":actor_id,"resourceType":resource_type,"resourceId":resource_id,"payload":payload,"timestamp":_timestamp(timestamp)})
def calculate_v4_content_hash(**kwargs: object) -> str: return sha256(canonicalize_v4_content(**kwargs)).hexdigest()
def calculate_v4_chain_hash(*, tenant_id: str, tenant_sequence: int, content_hash: str, previous_chain_hash: str, hash_scheme_version: str = V4_HASH_SCHEME_VERSION) -> str:
    if hash_scheme_version != V4_HASH_SCHEME_VERSION or type(tenant_sequence) is not int or tenant_sequence < 1: raise ValueError("unsupported V4 chain evidence")
    for value in (content_hash, previous_chain_hash):
        if not isinstance(value,str) or len(value)!=64 or any(c not in "0123456789abcdef" for c in value): raise ValueError("invalid V4 chain digest")
    return sha256(_json({"domain":V4_CHAIN_DOMAIN,"hashSchemeVersion":hash_scheme_version,"tenantId":validate_tenant_id(tenant_id),"tenantSequence":tenant_sequence,"contentHash":content_hash,"previousChainHash":previous_chain_hash})).hexdigest()
def begin_v4_write_transaction(session: Session) -> None:
    if session.bind is not None and session.bind.dialect.name == "sqlite": session.connection().exec_driver_sql("BEGIN IMMEDIATE")
def verify_v4_tenant_chain(session: Session, tenant_id: str) -> V4VerificationResult:
    """Read V4 evidence without flushing unrelated caller-owned changes."""

    with session.no_autoflush:
        return _verify_v4_tenant_chain(session, tenant_id)


def _verify_v4_tenant_chain(session: Session, tenant_id: str) -> V4VerificationResult:
    tenant_id=validate_tenant_id(tenant_id)
    events=list(session.execute(text("SELECT tenant_id,event_ref,tenant_sequence,event_type,actor_id,resource_type,resource_id,payload AS payload_raw,timestamp AS timestamp_raw,previous_content_hash,content_hash,hash_scheme_version,previous_chain_hash,chain_hash FROM v4_audit_events WHERE tenant_id=:tenant_id ORDER BY tenant_sequence"), {"tenant_id": tenant_id}).mappings())
    previous_content, previous_chain=V4_GENESIS_CONTENT_HASH,v4_genesis_chain_hash(tenant_id)
    for expected,event in enumerate(events,1):
        try:
            if event["tenant_sequence"] != expected: raise ValueError("sequence")
            content=calculate_v4_content_hash(tenant_id=event["tenant_id"],event_ref=event["event_ref"],event_type=event["event_type"],actor_id=event["actor_id"],resource_type=event["resource_type"],resource_id=event["resource_id"],payload=_persisted_payload(event["payload_raw"]),timestamp=_persisted_timestamp(event["timestamp_raw"]))
            chain=calculate_v4_chain_hash(tenant_id=tenant_id,tenant_sequence=expected,content_hash=event["content_hash"],previous_chain_hash=previous_chain,hash_scheme_version=event["hash_scheme_version"])
            if content!=event["content_hash"] or event["previous_content_hash"]!=previous_content or event["previous_chain_hash"]!=previous_chain or chain!=event["chain_hash"]: raise ValueError("hash")
        except (ValueError, TypeError, json.JSONDecodeError): return V4VerificationResult(False,expected,event["tenant_sequence"],"tenant chain evidence is inconsistent")
        previous_content,previous_chain=event["content_hash"],event["chain_hash"]
    state=session.execute(text("SELECT hash_scheme_version,event_count,head_sequence,head_chain_hash FROM v4_tenant_chain_state WHERE tenant_id=:tenant_id"), {"tenant_id": tenant_id}).mappings().one_or_none()
    if not events:
        if state is not None and (state["hash_scheme_version"] != V4_HASH_SCHEME_VERSION or state["event_count"]!=0 or state["head_sequence"] is not None or state["head_chain_hash"] is not None): return V4VerificationResult(False,0,None,"tenant checkpoint is inconsistent")
    elif state is None or state["hash_scheme_version"]!=V4_HASH_SCHEME_VERSION or state["event_count"]!=len(events) or state["head_sequence"]!=events[-1]["tenant_sequence"] or state["head_chain_hash"]!=events[-1]["chain_hash"]: return V4VerificationResult(False,len(events),None,"tenant checkpoint is inconsistent")
    if not verify_v4_lifecycle(session, tenant_id): return V4VerificationResult(False,len(events),None,"tenant lifecycle evidence is inconsistent")
    return V4VerificationResult(True,len(events),None,"tenant chain is intact")
def append_v4_audit_event(session: Session, *, tenant_id: str, event_type: str, actor_id: str, resource_type: str, resource_id: str, payload: dict, timestamp: datetime | None=None, event_ref: str | None=None) -> V4AuditEvent:
    tenant_id=validate_tenant_id(tenant_id); result=verify_v4_tenant_chain(session,tenant_id)
    if not result.is_intact: raise V4IntegrityError(result.detail)
    state=session.get(V4TenantChainState,tenant_id); sequence=result.checked_record_count+1; prior_content=V4_GENESIS_CONTENT_HASH if state is None else session.scalar(select(V4AuditEvent.content_hash).where(V4AuditEvent.tenant_id==tenant_id,V4AuditEvent.tenant_sequence==state.head_sequence)); prior_chain=v4_genesis_chain_hash(tenant_id) if state is None else state.head_chain_hash
    stamp=utc_now() if timestamp is None else timestamp; reference=_event_ref(event_ref or str(uuid4())); content=calculate_v4_content_hash(tenant_id=tenant_id,event_ref=reference,event_type=event_type,actor_id=actor_id,resource_type=resource_type,resource_id=resource_id,payload=payload,timestamp=stamp); chain=calculate_v4_chain_hash(tenant_id=tenant_id,tenant_sequence=sequence,content_hash=content,previous_chain_hash=prior_chain)
    event=V4AuditEvent(tenant_id=tenant_id,event_ref=reference,tenant_sequence=sequence,event_type=event_type,actor_id=actor_id,resource_type=resource_type,resource_id=resource_id,payload=payload,timestamp=stamp,previous_content_hash=prior_content,content_hash=content,hash_scheme_version=V4_HASH_SCHEME_VERSION,previous_chain_hash=prior_chain,chain_hash=chain); session.add(event); session.flush()
    if state is None: state=V4TenantChainState(tenant_id=tenant_id,hash_scheme_version=V4_HASH_SCHEME_VERSION,event_count=1,head_sequence=sequence,head_chain_hash=chain);session.add(state)
    else: state.event_count=sequence;state.head_sequence=sequence;state.head_chain_hash=chain
    session.flush(); return event

def v4_request_fingerprint(event_type: str, actor_id: str, resource_type: str, resource_id: str, payload: dict) -> str:
    return sha256(_json({"eventType":event_type,"actorId":actor_id,"resourceType":resource_type,"resourceId":resource_id,"payload":payload})).hexdigest()

def find_v4_replay(session: Session, tenant_id: str, subject: str, key: str, fingerprint: str) -> V4AuditEvent | None:
    mapping=session.scalar(select(V4AuditEventIdempotency).where(V4AuditEventIdempotency.tenant_id==tenant_id,V4AuditEventIdempotency.writer_subject==subject,V4AuditEventIdempotency.idempotency_key==key))
    if mapping is None: return None
    if mapping.request_fingerprint != fingerprint: raise V4IdempotencyConflictError()
    return session.scalar(select(V4AuditEvent).where(V4AuditEvent.id==mapping.event_id,V4AuditEvent.tenant_id==tenant_id))

def v4_redacted_payload(session: Session, event: V4AuditEvent) -> tuple[dict, list[str]]:
    paths=list(session.scalars(select(V4AuditEventRedaction.json_pointer).where(V4AuditEventRedaction.tenant_id==event.tenant_id,V4AuditEventRedaction.target_event_id==event.id)))
    return masked_payload(event.payload,sorted(paths)), sorted(paths)

def redact_v4_event(session: Session, *, tenant_id: str, event_ref: str, paths: list[str], reason: str, operator: str) -> tuple[V4AuditEvent, list[str]]:
    event=session.scalar(select(V4AuditEvent).where(V4AuditEvent.tenant_id==tenant_id,V4AuditEvent.event_ref==event_ref))
    if event is None: raise LookupError()
    if reason not in REDACTION_REASON_CODES: raise ValueError("invalid redaction reason")
    existing=set(session.scalars(select(V4AuditEventRedaction.json_pointer).where(V4AuditEventRedaction.tenant_id==tenant_id,V4AuditEventRedaction.target_event_id==event.id)))
    fresh=sorted(set(paths)-existing)
    for pointer in fresh: validate_json_pointer(event.payload,pointer)
    for pointer in fresh:
        action=append_v4_audit_event(session,tenant_id=tenant_id,event_type="V4_EVENT_REDACTED",actor_id=operator,resource_type=event.resource_type,resource_id=event.resource_id,payload={"eventRef":event.event_ref,"path":pointer,"reason":reason})
        session.add(V4AuditEventRedaction(tenant_id=tenant_id,target_event_id=event.id,json_pointer=pointer,redaction_action_event_id=action.id,redacted_at=action.timestamp,redaction_reason=reason))
    return event,fresh

def archive_v4_events(session: Session, *, tenant_id: str, retention_days: int, operator: str) -> int:
    if type(retention_days) is not int or not 0 < retention_days <= 36_500: raise ValueError("invalid retention policy")
    cutoff=utc_now()-timedelta(days=retention_days)
    archived=set(session.scalars(select(V4AuditEventArchive.target_event_id).where(V4AuditEventArchive.tenant_id==tenant_id)))
    targets=list(session.scalars(select(V4AuditEvent).where(V4AuditEvent.tenant_id==tenant_id,V4AuditEvent.timestamp < cutoff).order_by(V4AuditEvent.tenant_sequence)))
    count=0
    for target in targets:
        if target.id in archived or target.event_type.startswith("V4_EVENT_"): continue
        action=append_v4_audit_event(session,tenant_id=tenant_id,event_type="V4_EVENT_ARCHIVED",actor_id=operator,resource_type=target.resource_type,resource_id=target.resource_id,payload={"eventRef":target.event_ref,"retentionDays":retention_days})
        session.add(V4AuditEventArchive(tenant_id=tenant_id,target_event_id=target.id,archive_action_event_id=action.id,archived_at=action.timestamp)); count+=1
    return count

def verify_v4_lifecycle(session: Session, tenant_id: str) -> bool:
    """Validate tenant-bound lifecycle metadata against its chained action."""
    for archive in session.scalars(select(V4AuditEventArchive).where(V4AuditEventArchive.tenant_id==tenant_id)):
        target=session.get(V4AuditEvent,archive.target_event_id); action=session.get(V4AuditEvent,archive.archive_action_event_id)
        if target is None or action is None or target.tenant_id!=tenant_id or action.tenant_id!=tenant_id or action.event_type!="V4_EVENT_ARCHIVED" or action.payload.get("eventRef")!=target.event_ref: return False
        days=action.payload.get("retentionDays")
        if type(days) is not int or not 0 < days <= 36_500 or archive.archived_at != action.timestamp or not target.timestamp < action.timestamp-timedelta(days=days): return False
    for redaction in session.scalars(select(V4AuditEventRedaction).where(V4AuditEventRedaction.tenant_id==tenant_id)):
        target=session.get(V4AuditEvent,redaction.target_event_id); action=session.get(V4AuditEvent,redaction.redaction_action_event_id)
        if target is None or action is None or target.tenant_id!=tenant_id or action.tenant_id!=tenant_id or action.event_type!="V4_EVENT_REDACTED" or action.payload.get("eventRef")!=target.event_ref or action.payload.get("path")!=redaction.json_pointer or action.payload.get("reason")!=redaction.redaction_reason or redaction.redacted_at != action.timestamp: return False
        try: validate_json_pointer(target.payload, redaction.json_pointer)
        except ValueError: return False
    return True
