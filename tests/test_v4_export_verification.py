from __future__ import annotations
import copy
import json
from datetime import datetime, timezone
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from app.export_signing import SIGNATURE_FORMAT, signing_message
from app.services.export_service import calculate_bundle_digest
from app.services.v4_audit_service import V4_HASH_SCHEME_VERSION, calculate_v4_chain_hash, calculate_v4_content_hash, v4_genesis_chain_hash
from app.verify_export import BundleVerificationError
from app.verify_v4_export import verify_v4_bundle
from app.verify_export import main as verify_cli

def bundle():
    tenant="tenant-a"; stamp=datetime(2026,1,1,tzinfo=timezone.utc); ref="00000000-0000-4000-8000-000000000001"
    content=calculate_v4_content_hash(tenant_id=tenant,event_ref=ref,event_type="READ",actor_id="actor",resource_type="customer_account",resource_id="account",payload={"x":1},timestamp=stamp)
    chain=calculate_v4_chain_hash(tenant_id=tenant,tenant_sequence=1,content_hash=content,previous_chain_hash=v4_genesis_chain_hash(tenant))
    data={"bundleSchemaVersion":"audit-v4-export-v1","exportedAt":"2026-01-01T00:00:00.000000Z","selector":{"resourceId":"account"},"options":{"includeArchived":False},"hashScheme":{"version":V4_HASH_SCHEME_VERSION,"tenantId":tenant},"records":[{"eventRef":ref,"eventType":"READ","actorId":"actor","resourceType":"customer_account","resourceId":"account","payload":{"x":1},"timestamp":"2026-01-01T00:00:00.000000Z","contentHash":content,"redactedPaths":[]}],"chainWitness":[{"eventRef":ref,"tenantSequence":1,"contentHash":content,"previousChainHash":v4_genesis_chain_hash(tenant),"chainHash":chain,"hashSchemeVersion":V4_HASH_SCHEME_VERSION}],"checkpoint":{"eventCount":1,"headSequence":1,"headChainHash":chain}}
    data["bundleDigest"]=calculate_bundle_digest(data); return data

def sign(data,tmp_path):
    private=Ed25519PrivateKey.generate(); public=private.public_key(); path=tmp_path/"public.pem"; der=public.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo); path.write_bytes(public.public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)); data["signature"]={"algorithm":"Ed25519","format":SIGNATURE_FORMAT,"keyId":__import__("hashlib").sha256(der).hexdigest()[:16],"value":__import__("base64").b64encode(private.sign(signing_message(data["bundleDigest"]))).decode()}; return path

def test_valid_unsigned_and_signed_v4_bundles(tmp_path):
    data=bundle(); assert verify_v4_bundle(data)["isValid"]
    path=sign(data,tmp_path); assert verify_v4_bundle(data,public_key_path=str(path))["isValid"]

@pytest.mark.parametrize("change",["missing","malformed","wrong"])
def test_signature_failures_fail_closed(tmp_path,change):
    data=bundle(); path=sign(data,tmp_path)
    if change=="missing": data.pop("signature")
    elif change=="malformed": data["signature"]["value"]="bad"
    else: path=sign(bundle(),tmp_path)
    with pytest.raises(BundleVerificationError): verify_v4_bundle(data,public_key_path=str(path))

@pytest.mark.parametrize("change",["content","witness","duplicate","tenant","checkpoint"])
def test_tampered_v4_bundle_evidence_is_rejected(change):
    data=bundle()
    if change=="content": data["records"][0]["payload"]={"x":2}
    elif change=="witness": data["chainWitness"]=[]
    elif change=="duplicate": data["records"].append(copy.deepcopy(data["records"][0]))
    elif change=="tenant": data["hashScheme"]["tenantId"]="tenant-b"
    else: data["checkpoint"]["eventCount"]=2
    data["bundleDigest"]=calculate_bundle_digest(data)
    with pytest.raises(BundleVerificationError): verify_v4_bundle(data)

def test_redacted_record_has_explicit_nonrecomputed_limit():
    data=bundle(); data["records"][0]["payload"]={"x":"[REDACTED]"}; data["records"][0]["redactedPaths"]=["/x"]; data["bundleDigest"]=calculate_bundle_digest(data)
    assert verify_v4_bundle(data)["isValid"]

@pytest.mark.parametrize("mutation",["non-object-record","missing-timestamp","invalid-timestamp"])
def test_malformed_v4_export_records_fail_closed(mutation):
    """A recomputed bundle digest cannot make malformed selected evidence valid."""

    data=bundle()
    if mutation=="non-object-record":
        data["records"]=["not-an-object"]
    elif mutation=="missing-timestamp":
        data["records"][0].pop("timestamp")
    else:
        data["records"][0]["timestamp"]="not-a-UTC-timestamp"
    data["bundleDigest"]=calculate_bundle_digest(data)
    with pytest.raises(BundleVerificationError):
        verify_v4_bundle(data)

@pytest.mark.parametrize("mutation",["null-records","non-list-records","missing-witness-scheme","unsupported-witness-scheme","blank-tenant"])
def test_v4_bundle_structural_evidence_failures_are_controlled(mutation):
    """Recomputed digests must not turn malformed bundle sections into crashes."""

    data=bundle()
    if mutation=="null-records":
        data["records"]=None
    elif mutation=="non-list-records":
        data["records"]={}
    elif mutation=="missing-witness-scheme":
        data["chainWitness"][0].pop("hashSchemeVersion")
    elif mutation=="unsupported-witness-scheme":
        data["chainWitness"][0]["hashSchemeVersion"]="unsupported-v4-scheme"
    else:
        data["hashScheme"]["tenantId"]=""
    data["bundleDigest"]=calculate_bundle_digest(data)
    with pytest.raises(BundleVerificationError):
        verify_v4_bundle(data)

@pytest.mark.parametrize("mutation",["null-records","unsupported-witness-scheme"])
def test_v4_cli_reports_malformed_evidence_without_a_traceback(tmp_path,capsys,mutation):
    data=bundle()
    if mutation=="null-records":
        data["records"]=None
    else:
        data["chainWitness"][0]["hashSchemeVersion"]="unsupported-v4-scheme"
    data["bundleDigest"]=calculate_bundle_digest(data)
    path=tmp_path/"malformed-v4.json"; path.write_text(json.dumps(data),encoding="utf-8")
    assert verify_cli([str(path)])==1
    captured=capsys.readouterr()
    assert "verification failed:" in captured.err
    assert "Traceback" not in captured.err

def test_existing_cli_dispatches_v4_without_breaking_legacy_verifier(tmp_path):
    path=tmp_path/"v4.json"; path.write_text(json.dumps(bundle()),encoding="utf-8")
    assert verify_cli([str(path)])==0
    # Legacy verification remains a separately callable compatibility path.
    from app.verify_export import verify_bundle
    with pytest.raises(BundleVerificationError): verify_bundle(bundle())
