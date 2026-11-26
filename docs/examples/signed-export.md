# Signed export example

## Objective

Create and independently verify an optional Ed25519-signed export.

Generate keys outside the repository: `python -m app.generate_export_keys --private C:/audit-demo/private.pem --public C:/audit-demo/public.pem`. Set `AUDIT_EXPORT_PRIVATE_KEY_PATH` to that private path, create an export with auditor/admin role, save the JSON outside the repository, then run `python -m app.verify_export C:/audit-demo/export.json --public-key C:/audit-demo/public.pem`. Expected: matching trusted key validates; wrong key, modified signature, stripped signature when a public key is required, and modified bundle are rejected. Never commit PEM files. Source/evidence: export signing/verifier modules and `tests/test_export_service.py`.
