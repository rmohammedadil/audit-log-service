"""Standalone verifier for ``POST /audit/exports`` JSON bundles.

It uses only the Python standard library and never opens an application
database.  A valid result establishes internal bundle consistency; comparing
an externally retained expected digest adds trust in the supplied file, not
proof of source authenticity or selector completeness.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import re
import sys
from typing import Any
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature


BUNDLE_SCHEMA_VERSION = "audit-export-v1"
HASH_SCHEME_VERSION = "audit-chain-v1"
CHAIN_HASH_DOMAIN = "audit-log-chain-hash"
GENESIS_HASH = "AUDIT_LOG_GENESIS_V1"
GENESIS_CHAIN_HASH = sha256(b"audit-log-chain-genesis-v1").hexdigest()
_DIGEST = re.compile(r"[0-9a-f]{64}")


class BundleVerificationError(ValueError):
    """A safe explanation of a malformed or inconsistent bundle."""


def _canonical_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def _digest(value: dict[str, Any]) -> str:
    return sha256(_canonical_bytes(value)).hexdigest()


def _require_digest(value: object, name: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise BundleVerificationError(f"invalid {name}")
    return value


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise BundleVerificationError("invalid timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise BundleVerificationError("invalid timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise BundleVerificationError("timestamp must include timezone information")
    return parsed.astimezone(timezone.utc)


def _normal_timestamp(value: object) -> str:
    return _timestamp(value).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _content_hash(record: dict[str, Any]) -> str:
    required = ("eventType", "actorId", "resourceType", "resourceId", "payload", "timestamp")
    if any(key not in record for key in required) or not isinstance(record.get("payload"), dict):
        raise BundleVerificationError("selected record has invalid original content")
    content = {
        "eventType": record["eventType"], "actorId": record["actorId"],
        "resourceType": record["resourceType"], "resourceId": record["resourceId"],
        "payload": record["payload"], "timestamp": _normal_timestamp(record["timestamp"]),
    }
    return _digest(content)


def _chain_hash(content_hash: str, previous_chain_hash: str) -> str:
    _require_digest(content_hash, "contentHash")
    _require_digest(previous_chain_hash, "previousChainHash")
    return _digest({"contentHash": content_hash, "domain": CHAIN_HASH_DOMAIN,
                    "hashSchemeVersion": HASH_SCHEME_VERSION, "previousChainHash": previous_chain_hash})


def verify_bundle(bundle: object, expected_digest: str | None = None, public_key_path: str | None = None) -> dict[str, Any]:
    """Verify bundle-internal consistency without accessing source storage."""

    if not isinstance(bundle, dict):
        raise BundleVerificationError("bundle must be a JSON object")
    supplied_digest = _require_digest(bundle.get("bundleDigest"), "bundleDigest")
    unsigned = dict(bundle)
    unsigned.pop("bundleDigest", None)
    unsigned.pop("signature", None)
    if _digest(unsigned) != supplied_digest:
        raise BundleVerificationError("bundle digest mismatch")
    if expected_digest is not None and supplied_digest != _require_digest(expected_digest, "expected digest"):
        raise BundleVerificationError("trusted digest mismatch")
    version = bundle.get("bundleSchemaVersion")
    if version not in (BUNDLE_SCHEMA_VERSION, "audit-export-v2"):
        raise BundleVerificationError("unsupported bundle schema version")
    signature_verified = False
    if public_key_path is not None:
        signature = bundle.get("signature")
        if not isinstance(signature, dict) or signature.get("algorithm") != "Ed25519" or signature.get("format") != "audit-export-ed25519-v1" or not isinstance(signature.get("keyId"), str) or not isinstance(signature.get("value"), str):
            raise BundleVerificationError("signature is required and invalid")
        try:
            public = serialization.load_pem_public_key(Path(public_key_path).read_bytes())
            if not isinstance(public, Ed25519PublicKey): raise ValueError()
            public_der = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            if sha256(public_der).hexdigest()[:16] != signature["keyId"]: raise ValueError()
            public.verify(base64.b64decode(signature["value"], validate=True), f"audit-export-ed25519-v1:{supplied_digest}".encode("ascii"))
            signature_verified = True
        except (OSError, ValueError, TypeError, InvalidSignature):
            raise BundleVerificationError("signature verification failed") from None
    _timestamp(bundle.get("exportedAt"))
    selector = bundle.get("selector")
    if not isinstance(selector, dict) or set(selector) not in ({"actorId"}, {"resourceId"}):
        raise BundleVerificationError("bundle selector is invalid")
    if not isinstance(next(iter(selector.values())), str):
        raise BundleVerificationError("bundle selector is invalid")
    options = bundle.get("options")
    if not isinstance(options, dict) or type(options.get("includeArchived")) is not bool:
        raise BundleVerificationError("bundle options are invalid")
    scheme = bundle.get("hashScheme")
    expected_scheme = {"version": HASH_SCHEME_VERSION, "chainDomain": CHAIN_HASH_DOMAIN,
                       "contentGenesis": GENESIS_HASH, "chainGenesis": GENESIS_CHAIN_HASH}
    if scheme != expected_scheme:
        raise BundleVerificationError("unsupported hash scheme")
    witness = bundle.get("chainWitness")
    records = bundle.get("records")
    checkpoint = bundle.get("checkpoint")
    if not isinstance(witness, list) or not isinstance(records, list) or not isinstance(checkpoint, dict):
        raise BundleVerificationError("bundle sections are invalid")

    previous_content = GENESIS_HASH
    previous_chain = GENESIS_CHAIN_HASH
    witness_by_id: dict[int, dict[str, Any]] = {}
    last_id = 0
    for item in witness:
        if not isinstance(item, dict) or type(item.get("id")) is not int or item["id"] <= last_id:
            raise BundleVerificationError("chain witness is not in ascending unique ID order")
        last_id = item["id"]
        if item.get("hashSchemeVersion") != HASH_SCHEME_VERSION:
            raise BundleVerificationError("unsupported witness hash scheme")
        if item.get("previousHash") != previous_content:
            raise BundleVerificationError("witness predecessor content hash mismatch")
        if item.get("previousChainHash") != previous_chain:
            raise BundleVerificationError("witness predecessor chain hash mismatch")
        content_hash = _require_digest(item.get("contentHash"), "witness contentHash")
        if _chain_hash(content_hash, previous_chain) != item.get("chainHash"):
            raise BundleVerificationError("witness chain hash mismatch")
        _require_digest(item.get("chainHash"), "witness chainHash")
        witness_by_id[item["id"]] = item
        previous_content, previous_chain = content_hash, item["chainHash"]

    if checkpoint != {"hashSchemeVersion": HASH_SCHEME_VERSION, "eventCount": len(witness),
                      "headEventId": (last_id if witness else None),
                      "headChainHash": (previous_chain if witness else None)}:
        raise BundleVerificationError("checkpoint does not match chain witness")

    selected_ids: set[int] = set()
    recomputed = 0
    redacted = 0
    selector_key, selector_value = next(iter(selector.items()))
    for record in records:
        if not isinstance(record, dict) or type(record.get("id")) is not int or record["id"] in selected_ids:
            raise BundleVerificationError("selected records are invalid")
        selected_ids.add(record["id"])
        linked = witness_by_id.get(record["id"])
        if linked is None:
            raise BundleVerificationError("selected record is absent from chain witness")
        for field in ("previousHash", "contentHash", "hashSchemeVersion", "previousChainHash", "chainHash"):
            if record.get(field) != linked.get(field):
                raise BundleVerificationError("selected integrity evidence differs from witness")
        if record.get(selector_key) != selector_value:
            raise BundleVerificationError("selected record does not satisfy selector")
        paths = record.get("redactedPaths")
        if not isinstance(paths, list) or any(type(path) is not str for path in paths):
            raise BundleVerificationError("selected record redaction metadata is invalid")
        if paths:
            redacted += 1
        else:
            if _content_hash(record) != record.get("contentHash"):
                raise BundleVerificationError("selected record content hash mismatch")
            recomputed += 1
    if [record["id"] for record in records] != sorted(selected_ids):
        raise BundleVerificationError("selected records are not in ascending ID order")
    return {"isValid": True, "bundleDigest": supplied_digest, "recordCount": len(records),
            "contentHashesRecomputed": recomputed, "redactedRecordsNotRecomputed": redacted,
            "trustedDigestMatched": expected_digest is not None, "signatureVerified": signature_verified,
            "bundleSigned": "signature" in bundle}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify an audit export bundle without a database")
    parser.add_argument("bundle", help="path to an export JSON file")
    parser.add_argument("--expected-digest", dest="expected_digest")
    parser.add_argument("--public-key", dest="public_key")
    args = parser.parse_args(argv)
    try:
        with Path(args.bundle).open("r", encoding="utf-8") as handle:
            bundle = json.load(handle)
        result = verify_bundle(bundle, args.expected_digest, args.public_key)
    except (OSError, json.JSONDecodeError, BundleVerificationError) as error:
        print(f"verification failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
