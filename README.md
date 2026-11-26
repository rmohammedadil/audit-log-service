# Audit Log Service

Audit Log Service is a Python/FastAPI functional prototype for recording,
querying, and verifying tamper-evident audit evidence. It was developed for an
assessment spanning core audit logging, retention/redaction/exports, and
regulatory reporting. It is not a claim of production readiness, tamper-proof
storage, regulatory certification, or complete capture of external access.

## Implemented capabilities

- SHA-256 canonical content hashing, linked chain hashes, and checkpoint-backed
  integrity verification.
- Validated event creation, UTC filtering, deterministic pagination, and
  writer-scoped transactional idempotency.
- Logical archival and JSON Pointer response/export masking with lifecycle
  integrity verification.
- Self-contained exports, canonical bundle digests, optional Ed25519 signatures,
  and database-independent verification.
- Explicit recorded client-account access reports.
- Tenant-aware HS256 JWT authentication, deny-by-default resource and tenant
  grants, safe request IDs/logging, readiness, SQLite write coordination,
  Docker/Compose, and CI configuration.

## Quick start

Prerequisites: Python 3.12 and Git. Docker Desktop is needed only for Docker
commands.

### Windows PowerShell

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
$env:AUDIT_V4_DB_PATH = "C:/Charles_Schwab/audit-demo/audit-v4.db"
$env:AUDIT_JWT_SIGNING_KEY = "replace-with-a-unique-local-secret-at-least-32-characters"
$env:AUDIT_JWT_ISSUER = "audit-local"
$env:AUDIT_JWT_AUDIENCE = "audit-api"
python -m uvicorn app.main:app --reload
```

### Windows Git Bash

```bash
py -3.12 -m venv .venv
source .venv/Scripts/activate
python -m pip install -r requirements.txt
export AUDIT_V4_DB_PATH="C:/Charles_Schwab/audit-demo/audit-v4.db"
export AUDIT_JWT_SIGNING_KEY="replace-with-a-unique-local-secret-at-least-32-characters"
export AUDIT_JWT_ISSUER="audit-local"
export AUDIT_JWT_AUDIENCE="audit-api"
python -m uvicorn app.main:app --reload
```

`AUDIT_V4_DB_PATH` is mandatory for the supported application. It must name a
fresh V4 SQLite database or an already complete V4 database. Startup rejects a
missing, legacy, partial, or incompatible database; it never falls back to
`AUDIT_DB_PATH`, migrates V3 evidence, or changes the historical
`audit_log.db`.

`AUDIT_RETENTION_DAYS` is validated once at startup and read through the same
shared policy for each retention run. Its default is 90 days; set it explicitly
for reproducible local demonstrations.

Open:

- Swagger: `http://127.0.0.1:8000/docs`
- Health: `http://127.0.0.1:8000/health`
- Readiness: `http://127.0.0.1:8000/ready`

## Local authentication

Provision an active tenant membership and exact permissions through the trusted
offline CLI, then generate a temporary tenant-aware token. These examples use
only fictional local identities and a fresh V4 database:

```bash
python -m app.manage_grants --database "$AUDIT_V4_DB_PATH" principal-add --tenant tenant-demo --subject writer-demo
python -m app.manage_grants --database "$AUDIT_V4_DB_PATH" resource-grant --tenant tenant-demo --subject writer-demo --resource-type customer_account --resource-id account-demo-001 --permission CREATE_EVENT
python -m app.generate_token --subject writer-demo --role writer --tenant-id tenant-demo
```

PowerShell uses the same CLI with `$env:AUDIT_V4_DB_PATH`, for example:

```powershell
python -m app.manage_grants --database $env:AUDIT_V4_DB_PATH principal-add --tenant tenant-demo --subject auditor-demo
python -m app.manage_grants --database $env:AUDIT_V4_DB_PATH resource-grant --tenant tenant-demo --subject auditor-demo --resource-type customer_account --resource-id account-demo-001 --permission READ_EVENT
python -m app.generate_token --subject auditor-demo --role auditor --tenant-id tenant-demo
```

PowerShell uses the same CLI with `$env:AUDIT_V4_DB_PATH`, for example:

```powershell
python -m app.manage_grants --database $env:AUDIT_V4_DB_PATH principal-add --tenant tenant-demo --subject auditor-demo
python -m app.manage_grants --database $env:AUDIT_V4_DB_PATH resource-grant --tenant tenant-demo --subject auditor-demo --resource-type customer_account --resource-id account-demo-001 --permission READ_EVENT
python -m app.generate_token --subject auditor-demo --role auditor --tenant-id tenant-demo
```

The token must contain a verified `tenant_id`, `sub`, role list, issuer,
audience, and expiration. Role membership is necessary but insufficient: every
operation also requires active tenant membership and the exact resource or
tenant permission. Revoke a grant with `resource-revoke` or `tenant-revoke`;
subsequent calls and idempotent replays are denied. The JWT subject is the API
caller; the event `actorId` remains a business assertion from a trusted writer.

## API overview

| Endpoint | Role | Purpose |
| --- | --- | --- |
| `POST /audit/events` | writer + `CREATE_EVENT` | Create tenant event; optional `Idempotency-Key` |
| `GET /audit/events` | read-capable role + `READ_EVENT` | List authorized, redacted evidence |
| `GET /audit/verify` | permitted role + `VERIFY_TENANT_CHAIN` | Verify the caller's tenant chain |
| `POST /audit/retention/run` | admin + `RUN_RETENTION` | Apply tenant logical archival |
| `POST /audit/events/{eventRef}/redact` | admin + `REDACT_EVENT` | Add a tenant-scoped redaction overlay |
| `POST /audit/exports` | auditor/admin + `EXPORT_RESOURCE` and `EXPORT_TENANT_WITNESS` | Create a scoped export bundle |
| `GET /audit/access-reports` | regulator + `READ_ACCESS_REPORT` | Report authorized recorded account access |

See [docs/api-reference.md](docs/api-reference.md) for headers, request bodies,
query parameters, status codes, and examples.

## Run tests

The latest recorded cutover regression is 428 passing tests with one existing
TestClient deprecation warning. This is a single full-suite count, not a
coverage percentage. Use the project virtual environment:

```bash
python -m pytest -q
```

If Windows denies pytest access to its default temporary location, use a
dedicated disposable directory. Pytest may clear it.

```bash
mkdir -p /c/Charles_Schwab/pytest-temp
python -m pytest -q -p no:cacheprovider --basetemp "C:/Charles_Schwab/pytest-temp/run-$(date +%Y%m%d-%H%M%S)"
```

`-p no:cacheprovider` disables the result-cache plugin; `--basetemp` chooses
fixture temporary storage. Neither diagnoses the underlying Windows permission
configuration.

## Docker and CI

Copy `.env.example` to an untracked `.env`, replace its local JWT placeholders,
then run `docker compose up --build`. Compose starts `app.main:app` with
`AUDIT_V4_DB_PATH=/var/lib/audit-v4/audit_log_v4.db` on the named
`audit-v4-data` volume. It does not open or migrate V3 volumes. Use `docker
compose down` to preserve V4 evidence and `down -v` only for disposable V4
data. Optional signing uses `compose.signing.yaml` with a private PEM outside
the repository.

GitHub Actions is configured for regression, strict dependency scan, and Docker
smoke checks. The developer confirmed a successful post-remediation run; its
run ID and detailed job logs were not independently retrieved during the final
review.

## Documentation

| Document | Purpose |
| --- | --- |
| [ATTESTATION.md](ATTESTATION.md) | Engineer-provided submission attestation |
| [ENGINEERING_SUMMARY.md](ENGINEERING_SUMMARY.md) | Evaluator-facing summary |
| [docs/architecture.md](docs/architecture.md) | High-level current architecture |
| [docs/system-design.md](docs/system-design.md) | Low-level design and algorithms |
| [docs/requirements.md](docs/requirements.md) | Recovered requirements and historical decisions |
| [docs/testing.md](docs/testing.md) | Validation evidence and traceability |
| [docs/api-reference.md](docs/api-reference.md) | Endpoint contract |
| [docs/security.md](docs/security.md) | Security model and residual risks |
| [docs/walkthrough.md](docs/walkthrough.md) | Live-assessment demonstration |
| [docs/scenarios/](docs/scenarios/) | Scenario A/B/C guides |
| [docs/examples/](docs/examples/) | Practical examples |
| [docs/ai-usage-log.md](docs/ai-usage-log.md) | AI-assisted development history |

## Known limitations

The tenant checkpoint, grants, and lifecycle metadata share the application
database; a privileged coordinated rewrite can evade detection. Redaction
masks views but does not erase originals/backups. Historical V3 evidence is
not migrated. SQLite is a single-node design with no distributed coordination
or full-chain scalability evidence. JWT rotation, external identity
integration, managed key services, migrations, production monitoring, and
regulatory certification are not implemented. Docker runtime validation remains
pending on a Docker-capable runner. See [security.md](docs/security.md) and
[system-design.md](docs/system-design.md) for detailed boundaries.
