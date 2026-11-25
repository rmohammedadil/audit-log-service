"""Optional Ed25519 signing for self-contained export bundle digests."""
from __future__ import annotations
import base64
from hashlib import sha256
import os
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

SIGNATURE_ALGORITHM = "Ed25519"
SIGNATURE_FORMAT = "audit-export-ed25519-v1"

class ExportSigningError(RuntimeError): pass

def signing_message(digest: str) -> bytes:
    return f"{SIGNATURE_FORMAT}:{digest}".encode("ascii")

def sign_digest_if_configured(digest: str) -> dict[str, str] | None:
    path = os.environ.get("AUDIT_EXPORT_PRIVATE_KEY_PATH")
    if path is None:
        return None
    if not path.strip():
        raise ExportSigningError("export signing configuration is invalid")
    try:
        private = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
        if not isinstance(private, Ed25519PrivateKey):
            raise ValueError("key is not Ed25519")
        public_der = private.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        return {"algorithm": SIGNATURE_ALGORITHM, "format": SIGNATURE_FORMAT,
                "keyId": sha256(public_der).hexdigest()[:16],
                "value": base64.b64encode(private.sign(signing_message(digest))).decode("ascii")}
    except (OSError, ValueError, TypeError):
        raise ExportSigningError("export signing configuration is invalid") from None
