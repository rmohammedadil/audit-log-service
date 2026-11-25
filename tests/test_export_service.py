"""Focused tests for self-contained audit export bundles."""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import sys

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from app.database import Base
from app.services import audit_service
from app.services.audit_service import AuditChainIntegrityError, append_audit_event
from app.services.export_service import calculate_bundle_digest, create_audit_export
from app.services.redaction_service import redact_audit_event
from app.services.retention_service import run_retention
from app.verify_export import BundleVerificationError, verify_bundle
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


@pytest.fixture()
def session() -> Session:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as database_session:
        yield database_session
    Base.metadata.drop_all(engine)
    engine.dispose()


def append(session: Session, monkeypatch: pytest.MonkeyPatch, name: str, actor: str = "actor-a", timestamp: datetime | None = None):
    if timestamp is not None:
        monkeypatch.setattr(audit_service, "utc_now", lambda: timestamp)
    return append_audit_event(
        session, event_type=name, actor_id=actor, resource_type="account",
        resource_id=f"resource-{name}", payload={"name": name, "secret": "keep"},
    )


def test_export_selects_actor_records_and_independent_verifier_accepts(session: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    first = append(session, monkeypatch, "ONE")
    append(session, monkeypatch, "TWO", actor="actor-b")
    third = append(session, monkeypatch, "THREE")
    session.commit()

    bundle = create_audit_export(session, actor_id="actor-a", resource_id=None, include_archived=False,
                                 exported_at=datetime(2026, 1, 1, tzinfo=timezone.utc))
    assert [record["id"] for record in bundle["records"]] == [first.id, third.id]
    assert [item["id"] for item in bundle["chainWitness"]] == [first.id, first.id + 1, third.id]
    result = verify_bundle(bundle, bundle["bundleDigest"])
    assert result["isValid"] is True
    assert result["contentHashesRecomputed"] == 2
    assert result["trustedDigestMatched"] is True


@pytest.mark.parametrize("actor_id,resource_id", [(None, None), ("actor", "resource")])
def test_export_requires_exactly_one_selector(session: Session, actor_id: str | None, resource_id: str | None) -> None:
    with pytest.raises(ValueError, match="exactly one"):
        create_audit_export(session, actor_id=actor_id, resource_id=resource_id, include_archived=False)


def test_export_empty_selection_has_full_witness(session: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    append(session, monkeypatch, "ONE")
    session.commit()
    bundle = create_audit_export(session, actor_id="nobody", resource_id=None, include_archived=False)
    assert bundle["records"] == []
    assert len(bundle["chainWitness"]) == 1
    assert verify_bundle(bundle)["recordCount"] == 0


def test_export_applies_redaction_without_exposing_original_value(session: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    event = append(session, monkeypatch, "ONE")
    session.commit()
    redact_audit_event(session, event_id=event.id, paths=["/secret"], reason="SENSITIVE_DATA")
    session.commit()
    bundle = create_audit_export(session, actor_id="actor-a", resource_id=None, include_archived=False)
    record = next(record for record in bundle["records"] if record["id"] == event.id)
    assert record["payload"]["secret"] == "[REDACTED]"
    assert "keep" not in json.dumps(bundle)
    result = verify_bundle(bundle)
    assert result["redactedRecordsNotRecomputed"] == 1


def test_export_can_include_logically_archived_records(session: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    now = datetime(2026, 11, 25, tzinfo=timezone.utc)
    event = append(session, monkeypatch, "OLD", timestamp=now - timedelta(days=91))
    session.commit()
    monkeypatch.setenv("AUDIT_RETENTION_DAYS", "90")
    run_retention(session, now=now)
    session.commit()
    excluded = create_audit_export(session, actor_id="actor-a", resource_id=None, include_archived=False)
    included = create_audit_export(session, actor_id="actor-a", resource_id=None, include_archived=True)
    assert event.id not in [record["id"] for record in excluded["records"]]
    assert event.id in [record["id"] for record in included["records"]]
    assert included["archives"][0]["targetEventId"] == event.id


def test_export_rejects_corrupt_source(session: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    event = append(session, monkeypatch, "ONE")
    session.commit()
    session.execute(text("UPDATE audit_events SET payload = :payload WHERE id = :id"), {"payload": '{""bad"":true}', "id": event.id})
    session.commit()
    with pytest.raises(AuditChainIntegrityError):
        create_audit_export(session, actor_id="actor-a", resource_id=None, include_archived=False)


@pytest.mark.parametrize("mutation", ["record", "witness", "checkpoint", "membership"])
def test_independent_verifier_rejects_modified_bundle(session: Session, monkeypatch: pytest.MonkeyPatch, mutation: str) -> None:
    append(session, monkeypatch, "ONE")
    append(session, monkeypatch, "TWO")
    session.commit()
    bundle = create_audit_export(session, actor_id="actor-a", resource_id=None, include_archived=False)
    if mutation == "record":
        bundle["records"][0]["payload"]["name"] = "changed"
    elif mutation == "witness":
        bundle["chainWitness"][1]["previousChainHash"] = "0" * 64
    elif mutation == "checkpoint":
        bundle["checkpoint"]["eventCount"] = 999
    else:
        bundle["records"][0]["id"] = 999
    # Any post-digest mutation is rejected before a misleading success result.
    with pytest.raises(BundleVerificationError):
        verify_bundle(bundle)


def test_independent_verifier_rejects_trusted_digest_mismatch(session: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    append(session, monkeypatch, "ONE")
    session.commit()
    bundle = create_audit_export(session, actor_id="actor-a", resource_id=None, include_archived=False)
    with pytest.raises(BundleVerificationError, match="trusted digest"):
        verify_bundle(bundle, "0" * 64)


def test_standalone_module_verifies_saved_bundle(session: Session, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    append(session, monkeypatch, "ONE")
    session.commit()
    path = tmp_path / "export.json"
    path.write_text(json.dumps(create_audit_export(session, actor_id="actor-a", resource_id=None, include_archived=False)), encoding="utf-8")
    completed = subprocess.run([sys.executable, "-m", "app.verify_export", str(path)], capture_output=True, text=True, check=False)
    assert completed.returncode == 0
    assert '"isValid": true' in completed.stdout


def test_signed_export_requires_independently_trusted_public_key(session: Session, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    private = Ed25519PrivateKey.generate()
    private_path, public_path = tmp_path / "private.pem", tmp_path / "public.pem"
    private_path.write_bytes(private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    public_path.write_bytes(private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    monkeypatch.setenv("AUDIT_EXPORT_PRIVATE_KEY_PATH", str(private_path))
    append(session, monkeypatch, "ONE")
    session.commit()
    bundle = create_audit_export(session, actor_id="actor-a", resource_id=None, include_archived=False)
    assert bundle["bundleSchemaVersion"] == "audit-export-v2"
    assert verify_bundle(bundle, public_key_path=str(public_path))["signatureVerified"] is True
    bundle["signature"]["value"] = "AAAA"
    with pytest.raises(BundleVerificationError):
        verify_bundle(bundle, public_key_path=str(public_path))


def test_signature_verification_rejects_downgrade_wrong_key_and_recomputed_tampering(session: Session, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    private = Ed25519PrivateKey.generate(); wrong = Ed25519PrivateKey.generate()
    private_path, public_path, wrong_path = tmp_path / "private.pem", tmp_path / "public.pem", tmp_path / "wrong.pem"
    private_path.write_bytes(private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    public_path.write_bytes(private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    wrong_path.write_bytes(wrong.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    monkeypatch.setenv("AUDIT_EXPORT_PRIVATE_KEY_PATH", str(private_path)); append(session, monkeypatch, "ONE"); session.commit()
    bundle = create_audit_export(session, actor_id="actor-a", resource_id=None, include_archived=False)
    with pytest.raises(BundleVerificationError): verify_bundle(bundle, public_key_path=str(wrong_path))
    unsigned = dict(bundle); unsigned.pop("signature")
    with pytest.raises(BundleVerificationError): verify_bundle(unsigned, public_key_path=str(public_path))
    bundle["records"][0]["payload"]["name"] = "changed"
    bundle["bundleDigest"] = calculate_bundle_digest(bundle)
    with pytest.raises(BundleVerificationError): verify_bundle(bundle, public_key_path=str(public_path))


def test_invalid_configured_signing_key_fails_closed(session: Session, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("AUDIT_EXPORT_PRIVATE_KEY_PATH", str(tmp_path / "missing.pem")); append(session, monkeypatch, "ONE"); session.commit()
    with pytest.raises(RuntimeError): create_audit_export(session, actor_id="actor-a", resource_id=None, include_archived=False)
