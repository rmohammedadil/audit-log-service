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
- HS256 JWT authentication, endpoint RBAC, safe request IDs/logging, readiness,
  SQLite write coordination, Docker/Compose, and CI configuration.

## Quick start

Prerequisites: Python 3.12 and Git. Docker Desktop is needed only for Docker
commands.

### Windows PowerShell

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
$env:AUDIT_DB_PATH = "C:/Charles_Schwab/audit-demo/audit.db"
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
export AUDIT_DB_PATH="C:/Charles_Schwab/audit-demo/audit.db"
export AUDIT_JWT_SIGNING_KEY="replace-with-a-unique-local-secret-at-least-32-characters"
export AUDIT_JWT_ISSUER="audit-local"
export AUDIT_JWT_AUDIENCE="audit-api"
python -m uvicorn app.main:app --reload
```

`AUDIT_DB_PATH` defaults to relative `audit_log_v3.db` only when unset; an
explicit empty/whitespace value is rejected. Use a fresh V3 path for local
work. Do not use or migrate the historical `audit_log.db`.

Open:

- Swagger: `http://127.0.0.1:8000/docs`
- Health: `http://127.0.0.1:8000/health`
- Readiness: `http://127.0.0.1:8000/ready`

## Local authentication

Generate a temporary token only after configuring the same JWT variables:

```bash
python -m app.generate_token --subject writer-demo --role writer
```

Use it as `Authorization: Bearer <token>`. Roles are writer (create), auditor
(query/verify/export), regulator (access report/verify), and admin
(query/verify/export/retention/redaction). The JWT subject is the API caller;
the event `actorId` remains a business assertion from a trusted writer.

## API overview

| Endpoint | Role | Purpose |
| --- | --- | --- |
| `POST /audit/events` | writer | Create event; optional `Idempotency-Key` |
| `GET /audit/events` | auditor/admin | List verified, redacted audit evidence |
| `GET /audit/verify` | auditor/regulator/admin | Verify full evidence chain |
| `POST /audit/retention/run` | admin | Apply configured logical archival |
| `POST /audit/events/{eventId}/redact` | admin | Add redaction overlay |
| `POST /audit/exports` | auditor/admin | Create verified export bundle |
| `GET /audit/access-reports` | regulator | Report recorded account access |

See [docs/api-reference.md](docs/api-reference.md) for headers, request bodies,
query parameters, status codes, and examples.

## Run tests

The recorded final regression baseline is 341 tests with one existing
TestClient deprecation warning. Use the project virtual environment:

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
then run `docker compose up --build`. Compose persists SQLite in named
`audit-data`; use `docker compose down` to preserve it and `down -v` only for
disposable data. Optional signing uses `compose.signing.yaml` with a private
PEM outside the repository.

GitHub Actions is configured for regression, strict dependency scan, and Docker
smoke checks. The developer confirmed a successful post-remediation run; its
run ID and detailed job logs were not independently retrieved during the final
review.

## Documentation

| Document | Purpose |
| --- | --- |
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

The checkpoint and lifecycle metadata share the application database; a
privileged coordinated rewrite can evade detection. Redaction masks views but
does not erase originals/backups. SQLite is a single-node design with no
distributed coordination or full-chain scalability evidence. JWT rotation,
revocation, external identity integration, managed key services, migrations,
production monitoring, and regulatory certification are not implemented. See
[security.md](docs/security.md) and [system-design.md](docs/system-design.md)
for detailed boundaries.
