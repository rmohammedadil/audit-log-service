"""Offline consistency verification for isolated V4 export bundles."""
from __future__ import annotations
from hashlib import sha256
from typing import Any
from datetime import datetime
import base64
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from app.verify_export import BundleVerificationError, _canonical_bytes, _require_digest
from app.export_signing import SIGNATURE_FORMAT, signing_message
from app.services.v4_audit_service import V4_CHAIN_DOMAIN, V4_HASH_SCHEME_VERSION, calculate_v4_chain_hash, calculate_v4_content_hash, v4_genesis_chain_hash

V4_BUNDLE_VERSION="audit-v4-export-v1"
def verify_v4_bundle(bundle: object, expected_digest: str|None=None, public_key_path: str|None=None) -> dict[str, Any]:
    if not isinstance(bundle,dict) or bundle.get("bundleSchemaVersion")!=V4_BUNDLE_VERSION: raise BundleVerificationError("unsupported V4 bundle")
    digest=_require_digest(bundle.get("bundleDigest"),"bundleDigest"); unsigned=dict(bundle); unsigned.pop("bundleDigest",None); unsigned.pop("signature",None)
    if sha256(_canonical_bytes(unsigned)).hexdigest()!=digest: raise BundleVerificationError("bundle digest mismatch")
    if expected_digest is not None and digest != _require_digest(expected_digest,"expected digest"): raise BundleVerificationError("trusted digest mismatch")
    if public_key_path is not None:
        signature=bundle.get("signature")
        if not isinstance(signature,dict) or signature.get("algorithm")!="Ed25519" or signature.get("format")!=SIGNATURE_FORMAT or not isinstance(signature.get("value"),str): raise BundleVerificationError("signature is required and invalid")
        try:
            public=serialization.load_pem_public_key(Path(public_key_path).read_bytes())
            if not isinstance(public,Ed25519PublicKey): raise ValueError()
            key_id=sha256(public.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()[:16]
            if signature.get("keyId") != key_id: raise ValueError()
            public.verify(base64.b64decode(signature["value"],validate=True),signing_message(digest))
        except (OSError,ValueError,TypeError,InvalidSignature): raise BundleVerificationError("signature verification failed") from None
    witness=bundle.get("chainWitness"); checkpoint=bundle.get("checkpoint"); scheme=bundle.get("hashScheme")
    if not isinstance(witness,list) or not isinstance(checkpoint,dict) or not isinstance(scheme,dict) or scheme.get("version")!=V4_HASH_SCHEME_VERSION: raise BundleVerificationError("invalid V4 evidence")
    tenant=scheme.get("tenantId")
    if not isinstance(tenant,str): raise BundleVerificationError("tenant binding missing")
    previous=v4_genesis_chain_hash(tenant)
    for sequence,row in enumerate(witness,1):
        if not isinstance(row,dict) or row.get("tenantSequence")!=sequence: raise BundleVerificationError("tenant sequence mismatch")
        if calculate_v4_chain_hash(tenant_id=tenant,tenant_sequence=sequence,content_hash=_require_digest(row.get("contentHash"),"contentHash"),previous_chain_hash=previous,hash_scheme_version=row.get("hashSchemeVersion"))!=row.get("chainHash"): raise BundleVerificationError("chain witness mismatch")
        previous=row["chainHash"]
    if checkpoint.get("eventCount")!=len(witness) or checkpoint.get("headChainHash")!=(previous if witness else None): raise BundleVerificationError("checkpoint mismatch")
    hashes=set(); witness_by_hash={row["contentHash"]:row for row in witness}
    for record in bundle.get("records",[]):
        if not isinstance(record,dict) or record.get("contentHash") in hashes or record.get("contentHash") not in witness_by_hash or record.get("eventRef")!=witness_by_hash[record.get("contentHash")].get("eventRef"): raise BundleVerificationError("selected-record membership mismatch")
        hashes.add(record["contentHash"])
        # A masked record cannot prove its original content hash offline; it is
        # intentionally reported as limited rather than treated as recomputed.
        if not record.get("redactedPaths"):
            try:
                timestamp=datetime.fromisoformat(record["timestamp"].replace("Z","+00:00"))
                if calculate_v4_content_hash(tenant_id=tenant,event_ref=record["eventRef"],event_type=record["eventType"],actor_id=record["actorId"],resource_type=record["resourceType"],resource_id=record["resourceId"],payload=record["payload"],timestamp=timestamp)!=record["contentHash"]: raise BundleVerificationError("selected content hash mismatch")
            except (KeyError,TypeError,ValueError): raise BundleVerificationError("selected record malformed") from None
    return {"isValid":True,"recordCount":len(bundle.get("records",[])),"bundleDigest":digest}
