"""Generate new Ed25519 PEM keys without overwriting caller files."""
import argparse
import os
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
p=argparse.ArgumentParser(); p.add_argument("--private", required=True); p.add_argument("--public", required=True); a=p.parse_args()
private_path, public_path = Path(a.private), Path(a.public)
if private_path.exists() or public_path.exists(): p.error("refusing to overwrite existing key file")
private_path.parent.mkdir(parents=True, exist_ok=True); public_path.parent.mkdir(parents=True, exist_ok=True)
private=Ed25519PrivateKey.generate()
with private_path.open("xb") as handle:
    handle.write(private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
try: os.chmod(private_path, 0o600)
except OSError: pass
with public_path.open("xb") as handle:
    handle.write(private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
