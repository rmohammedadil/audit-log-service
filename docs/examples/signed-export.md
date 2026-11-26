# Signed export example

## Objective

Create and independently verify an optional Ed25519-signed export.

Generate keys outside the repository: `python -m app.generate_export_keys --private C:/audit-demo/private.pem --public C:/audit-demo/public.pem`. Set `AUDIT_EXPORT_PRIVATE_KEY_PATH` to that private path. In V4, an auditor/admin needs `EXPORT_RESOURCE` for selected records and `EXPORT_TENANT_WITNESS` before creating an export. Save JSON outside the repository, then run `python -m app.verify_export C:/audit-demo/export.json --public-key C:/audit-demo/public.pem`. A trusted key validates signer authenticity; wrong key, modified/missing signature, downgrade, and modified bundle are rejected. This still does not prove source selection completeness or redacted originals. Never commit PEM files.
