# Practical Examples

These guides use fictional data and disposable environments. The supported
runtime is V4: follow the [walkthrough](../walkthrough.md) for mandatory
`AUDIT_V4_DB_PATH`, tenant-aware tokens, and explicit grants. Older snippets
that refer to `AUDIT_DB_PATH`, numeric IDs, or role-only access are historical
examples, not V4 startup instructions. Automated evidence remains in
[testing.md](../testing.md).

| Guide | Focus |
| --- | --- |
| [authentication](authentication.md) | Local JWT tokens and role boundaries |
| [happy path](happy-path.md) | Event creation, retrieval, verification |
| [tamper detection](tamper-detection.md) | Isolated-copy corruption diagnosis |
| [retention and redaction](retention-and-redaction.md) | Lifecycle projections |
| [signed export](signed-export.md) | Digest/signature verification |
| [compliance reporting](compliance-reporting.md) | Recorded access reports |
| [idempotency](idempotency.md) | 201/200/409 creation behavior |
| [Docker and CI](docker-and-ci.md) | Container and CI evidence boundaries |

No screenshots were captured during Task 32 because no sanctioned capture workflow was available. Suggested manual captures are Swagger, creation, verification, tamper result, redacted retrieval, retention result, export verification, report, and idempotency replay. Never capture tokens, private keys, secrets, or unredacted data.
