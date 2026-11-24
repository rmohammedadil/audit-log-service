# Audit Log Service

Audit Log Service is a Python/FastAPI prototype for recording and verifying a
tamper-evident audit trail. It appends hash-linked events, supports filtered
event retrieval, and reports integrity failures caused by direct database
modification or deletion.

Scenario A is conditionally accepted based on the implemented behavior,
automated tests, and developer-performed manual validation. It remains subject
to independent reconciliation with the original assessment source.

## What is implemented

- `POST /audit/events` creates a validated, server-timestamped audit event.
- `GET /audit/events` retrieves events with combined filters, inclusive UTC
  time bounds, and offset/limit pagination.
- `GET /audit/verify` verifies the full persisted hash chain and checkpoint.
- Canonical UTF-8 JSON and SHA-256 produce deterministic content hashes and
  versioned cryptographically linked chain hashes.
- SQLite persistence restores server-assigned timestamps as timezone-aware UTC
  values so persisted events remain hash-verifiable.
- Automated tests cover normal writes, queries, verification, direct-database
  modification/deletion, malformed persisted evidence, rollback, and error
  handling.

This is a tamper-evident prototype, not a tamper-proof or production-ready
system. It does not claim regulatory compliance.

## Architecture

The HTTP routes validate and serialize API requests and responses. The service
layer owns canonical hashing, append rules, filtering, and verification. The
SQLAlchemy models persist events and a singleton chain checkpoint. The API
layer owns request transaction commit/rollback.

For detailed decisions and boundaries, see:

- [Requirements analysis](docs/requirements.md)
- [Architecture](docs/architecture.md)
- [AI usage log](docs/ai-usage-log.md)

## Technology stack

- Python 3.12
- FastAPI and Uvicorn
- Pydantic v2
- SQLAlchemy and SQLite
- pytest and httpx
- SHA-256 from the Python standard library

## Prerequisites

Install Python 3.12 and Git. The commands below use `python -m` so they target
the active virtual environment explicitly.

`requirements.txt` pins the direct runtime and test dependencies verified by
this project. Direct pins are not a complete transitive dependency lock or a
hash-verified software supply chain.

## Setup

### Windows PowerShell

```powershell
git clone <repository-url>
cd audit-log-service
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

If PowerShell blocks activation, follow your organization's execution-policy
guidance or invoke `.venv\Scripts\python.exe` directly.

### Windows Git Bash

```bash
git clone <repository-url>
cd audit-log-service
py -3.12 -m venv .venv
source .venv/Scripts/activate
python -m pip install -r requirements.txt
```

### POSIX-compatible shells

```bash
git clone <repository-url>
cd audit-log-service
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Verify the installed dependency set:

```bash
python -m pip check
```

## Run the application

From the repository root, start the development server:

```bash
python -m uvicorn app.main:app --reload
```

The prototype creates `audit_log_v2.db` in the current working directory on
startup. Set `AUDIT_DB_PATH` to select another fresh V2 SQLite database. The
original `audit_log.db` is a legacy V1 database and is never migrated or
modified automatically; startup rejects incompatible schemas before creating
or changing tables. If `AUDIT_DB_PATH` is absent, the default is a relative
`audit_log_v2.db` path under the process working directory. Relative and
absolute paths, including filenames with spaces, are supported; explicitly
empty or whitespace-only values are rejected as configuration errors.

Open these local URLs while the server is running:

- Health: `http://127.0.0.1:8000/health`
- Swagger UI: `http://127.0.0.1:8000/docs`
- OpenAPI: `http://127.0.0.1:8000/openapi.json`

## API overview

### Create an event

`POST /audit/events` accepts exactly these client fields:

- `eventType`
- `actorId`
- `resourceType`
- `resourceId`
- `payload` (a JSON object)

The server assigns the timestamp, ID, predecessor hash, and content hash.
Unexpected fields, including caller-supplied timestamps and hashes, are
rejected.

Responses retain `previousHash` (the predecessor content hash) and
`contentHash`, and add `hashSchemeVersion`, `previousChainHash`, and
`chainHash`. `chainHash` commits to this event's content hash and its
predecessor chain hash using the `audit-chain-v1` canonical JSON rule.

```bash
curl -X POST http://127.0.0.1:8000/audit/events \
  -H "Content-Type: application/json" \
  -d '{"eventType":"RECORD_UPDATED","actorId":"advisor-42","resourceType":"client_account","resourceId":"account-123","payload":{"changedFields":["address"]}}'
```

In PowerShell, the equivalent request can use `Invoke-RestMethod`:

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/audit/events -ContentType 'application/json' -Body '{"eventType":"RECORD_UPDATED","actorId":"advisor-42","resourceType":"client_account","resourceId":"account-123","payload":{"changedFields":["address"]}}'
```

Successful creation returns HTTP 201. If checkpoint state makes an append
unsafe, the request is rolled back and returns HTTP 409.

### Query events

`GET /audit/events` supports any combination of:

- `actorId`
- `resourceType`
- `resourceId`
- `eventType`
- `from` and `to` timezone-aware ISO-8601 timestamps
- `limit` (default 100, maximum 1000) and `offset` (default 0)

Results are in deterministic ascending ID order. Time boundaries are inclusive
and normalized to UTC.

```bash
curl "http://127.0.0.1:8000/audit/events?actorId=advisor-42&resourceType=client_account&limit=25"
```

No matching events return HTTP 200 with `[]`. Invalid filters, time bounds, or
pagination values return HTTP 422.

### Verify the chain

`GET /audit/verify` reads persisted evidence and returns HTTP 200 for both
intact and inconsistent chains. An inconsistency is a completed verification
result, not an HTTP client error.

```bash
curl http://127.0.0.1:8000/audit/verify
```

An intact response has this shape:

```json
{
  "isIntact": true,
  "checkedRecordCount": 2,
  "firstInconsistencyId": null,
  "violationType": null,
  "detail": "audit chain and checkpoint are intact"
}
```

An inconsistent response sets `isIntact` to `false` and reports the first
identifiable record and a violation type such as `CONTENT_HASH_MISMATCH` or
`CHECKPOINT_COUNT_MISMATCH`. Checkpoint-only inconsistencies may correctly
have `firstInconsistencyId: null`.

Operational database failures return a sanitized HTTP 500 response. Routes do
not return SQL, database paths, payloads, credentials, or exception details.

## Run tests

Run the full suite from the repository root:

```bash
python -m pytest -q
```

On Windows systems where pytest cannot write `.pytest_cache`, disable that
optional cache provider:

```bash
python -m pytest -q -p no:cacheprovider
```

Disabling `cacheprovider` prevents pytest from writing its result cache. It
does not change the separate temporary directories used by fixtures such as
`tmp_path`. If Windows denies access to the default temporary directory, point
`--basetemp` at a dedicated disposable directory that the current user can
write. Pytest may clear or reuse that directory, so never point it at a
directory containing evidence, source files, or other data you need to keep.

Portable example:

```bash
mkdir -p ./pytest-temp
python -m pytest -q -p no:cacheprovider --basetemp ./pytest-temp/run
```

Successful Windows Git Bash workaround used during Task 11 manual validation:

```bash
mkdir -p /c/Charles_Schwab/pytest-temp
python -m pytest -q -p no:cacheprovider --basetemp "C:/Charles_Schwab/pytest-temp/run-$(date +%Y%m%d-%H%M%S)"
```

This workaround confines pytest's temporary files to a new writable location.
It does not diagnose or repair the underlying Windows permission configuration.

The committed baseline at the end of Task 10 is 145 passing tests. Task 11
revalidates this baseline from a fresh isolated environment.

## Safe manual testing

Do not perform direct-database tampering against a database you need to keep.
Use a disposable worktree or copy instead. For example, after committing the
desired code revision:

```bash
git worktree add --detach ../audit-log-service-manual HEAD
cd ../audit-log-service-manual
```

Create the virtual environment and start the application inside that disposable
directory. Its `audit_log.db` is then separate from the original checkout.
Direct SQL modification or deletion can be used there to observe the verifier.
Remove the worktree only after confirming its exact path and that no evidence
needs to be retained.

## Current limitations

- The checkpoint is stored in the same database; it is not an external trust
  anchor. A privileged actor who rewrites events, hashes, links, and checkpoint
  state together may evade detection.
- Concurrent writers are not coordinated, and verification does not provide a
  consistent concurrent snapshot.
- Append validates current tail/checkpoint consistency, not every historical
  event on every write. Full historical verification is available through
  `GET /audit/verify`.
- Full-chain verification materializes the chain in memory, so it is not yet
  designed for very large audit histories.
- There is no authentication or authorization, including no JWT or RBAC.
- SQLite, startup `create_all`, and offset pagination are prototype choices;
  there are no migrations, retention, redaction, export, Docker, CI/CD, or
  production deployment configuration.
- `AuditEventRead` preserves the four persisted event strings exactly as
  stored. Malformed JSON, timestamps, nulls, or incompatible stored types are
  separate retrieval concerns.
- The linked chain detects ordinary coordinated content/hash/link edits unless
  every later chain hash and the checkpoint are also rewritten. A privileged
  actor who rewrites the complete database can still evade a same-database,
  unkeyed design.
- The installed Starlette/TestClient integration emits a known deprecation
  warning. Dependency versions are preserved because they are the tested set.

Startup preflight compares the names of existing audit tables and their column
sets with the expected V2 schema before calling `create_all`. It does not
validate database column types, constraints, indexes, or SQLite table SQL.

Planned Scenario B work concerns retention, redaction, and export. Scenario C
and broader production hardening are intentionally not implemented here.

