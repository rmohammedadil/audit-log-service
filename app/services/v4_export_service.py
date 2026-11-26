"""Tenant-only V4 export bundles; deliberately separate from legacy format."""
from __future__ import annotations
from datetime import datetime, timezone
from app.export_signing import sign_digest_if_configured
from app.services.export_service import calculate_bundle_digest
from app.services.v4_audit_service import V4_CHAIN_DOMAIN, V4_GENESIS_CONTENT_HASH, v4_genesis_chain_hash, v4_redacted_payload, verify_v4_tenant_chain
from app.v4_models import V4AuditEvent, V4AuditEventArchive, V4TenantChainState
from sqlalchemy import select, tuple_
from sqlalchemy.orm import Session

def create_v4_export(session: Session, *, tenant_id: str, actor_id: str|None, resource_id: str|None, include_archived: bool, authorized: set[tuple[str,str]]) -> dict:
    if (actor_id is None)==(resource_id is None): raise ValueError("exactly one selector is required")
    if not verify_v4_tenant_chain(session,tenant_id).is_intact: raise ValueError("integrity")
    events=list(session.scalars(select(V4AuditEvent).where(V4AuditEvent.tenant_id==tenant_id).order_by(V4AuditEvent.tenant_sequence)))
    selected=select(V4AuditEvent).where(
        V4AuditEvent.tenant_id==tenant_id,
        ~V4AuditEvent.event_type.like("V4_EVENT_%"),
    )
    if actor_id is not None:
        # Scope before actor matching so a 200 empty export does not reveal
        # whether the actor has activity on a resource the caller cannot read.
        selected=selected.where(tuple_(V4AuditEvent.resource_type,V4AuditEvent.resource_id).in_(list(authorized)),V4AuditEvent.actor_id==actor_id)
    else:
        if ("customer_account",resource_id) not in authorized: raise PermissionError()
        selected=selected.where(V4AuditEvent.resource_type=="customer_account",V4AuditEvent.resource_id==resource_id)
    if not include_archived:
        selected=selected.where(~V4AuditEvent.id.in_(select(V4AuditEventArchive.target_event_id).where(V4AuditEventArchive.tenant_id==tenant_id)))
    chosen=list(session.scalars(selected.order_by(V4AuditEvent.tenant_sequence)))
    records=[]
    for event in chosen:
        payload,paths=v4_redacted_payload(session,event)
        records.append({"eventRef":event.event_ref,"eventType":event.event_type,"actorId":event.actor_id,"resourceType":event.resource_type,"resourceId":event.resource_id,"payload":payload,"timestamp":event.timestamp.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00","Z"),"contentHash":event.content_hash,"previousContentHash":event.previous_content_hash,"previousChainHash":event.previous_chain_hash,"chainHash":event.chain_hash,"redactedPaths":paths})
    witness=[{"eventRef":e.event_ref,"tenantSequence":e.tenant_sequence,"contentHash":e.content_hash,"previousChainHash":e.previous_chain_hash,"chainHash":e.chain_hash,"hashSchemeVersion":e.hash_scheme_version} for e in events]
    state=session.get(V4TenantChainState,tenant_id)
    bundle={"bundleSchemaVersion":"audit-v4-export-v1","exportedAt":datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00","Z"),"selector":{"actorId":actor_id} if actor_id else {"resourceId":resource_id},"options":{"includeArchived":include_archived},"hashScheme":{"version":"audit-tenant-chain-v1","tenantId":tenant_id,"chainDomain":V4_CHAIN_DOMAIN,"contentGenesis":V4_GENESIS_CONTENT_HASH,"chainGenesis":v4_genesis_chain_hash(tenant_id)},"records":records,"chainWitness":witness,"checkpoint":{"eventCount":state.event_count if state else 0,"headSequence":state.head_sequence if state else None,"headChainHash":state.head_chain_hash if state else None}}
    bundle["bundleDigest"]=calculate_bundle_digest(bundle); signature=sign_digest_if_configured(bundle["bundleDigest"])
    if signature: bundle["signature"]=signature
    return bundle
