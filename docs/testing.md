# Acceptance Validation and Traceability

This document records test evidence for the functional prototype. It does not
claim production readiness, tamper-proof storage, or regulatory certification.

## Task 36F cutover evidence

- The latest complete local cutover regression passed **428 tests** with one
  existing Starlette/TestClient deprecation warning. This supersedes earlier
  historical suite counts; counts are not additive.
- It included historical V3 regression tests through `tests/legacy_app.py` and
  active V4 authorization, persistence, lifecycle, export, verifier,
  operational, and default-entry-point tests.
- `compileall`, `pip check`, and `git diff --check` passed during cutover
  validation. The historical `audit_log.db` checksum remained
  `B0401EBDF6E7A1A65B9E6CB4667A7E0A64D12A94D5D28E8AD3755FC5A2DCC96A`.
- Docker runtime smoke execution remains pending because Docker was unavailable
  locally. Static Compose/workflow and Git Bash syntax checks are not a Docker
  runtime result.

## Evidence status

- Local commit and `origin/main` both resolve to
  `82d88adc658b3a55e7bc008ef3023c40cdcf5597` at the start of Task 31.
- The developer confirmed the post-remediation GitHub Actions workflow passed.
  This acceptance review could not retrieve its run ID or individual job logs:
  the configured GitHub CLI credential was invalid and unauthenticated Actions
  API access returned 404. Docker runtime success is therefore developer-
  confirmed, not independently log-verified here.
- Task 31 selected isolated API/crypto acceptance tests: 24 passed with one
  existing TestClient deprecation warning. They used pytest temporary SQLite
  databases and test-only JWT/key material.

## Requirements-to-evidence matrix

| Area | Implemented behavior | Automated evidence | Manual / external evidence | Limitations |
| --- | --- | --- | --- | --- |
| Scenario A: append integrity | Canonical SHA-256 content hashes, linked chain hashes, checkpoint updates, caller-owned transactions | `test_hashing.py`, `test_chain_verification.py`, `test_audit_service.py` | Earlier developer Swagger and SQLite inspection recorded in the AI log | Same-database checkpoint is not an external trust anchor. |
| Scenario A: tamper detection | Verification detects changed fields, hashes, links, malformed persisted values, deletion, and checkpoint inconsistency | `test_chain_verification.py`, API verification tests in `test_audit_routes.py` | Developer Task 10 tampering exercise | A privileged coordinated rewrite of all evidence and checkpoint can evade this prototype. |
| Scenario A: API safety | POST/GET/verify, UTC validation, pagination, sanitized failures, request IDs, idempotency | `test_audit_routes.py`, `test_schemas.py`, `test_database.py` | Task 31 selected API tests | No rate limiting or external identity provider. |
| Scenario B: retention | Server-configured logical archive with chained lifecycle action and metadata | `test_retention_service.py`, retention API tests | Earlier developer validation is recorded; final manual Swagger pass remains outside this acceptance run | No scheduler, physical reclamation, or streaming batches. |
| Scenario B: redaction | JSON Pointer retrieval overlay, lifecycle integrity checks, fail-closed retrieval | `test_redaction_service.py`, redaction/fail-closed API tests | Task 31 selected redaction/replay tests | Original database evidence remains stored; redaction is not erasure. |
| Scenario B: export | Verified bundle, redaction projection, archive metadata, digest and optional Ed25519 signature | `test_export_service.py`, export API tests | Task 31 selected signed-export, trusted-key, wrong-key, tamper, and digest tests | Bundle verification establishes internal consistency, not external source authenticity or complete selection. |
| Scenario C: access reporting | Explicit account-access contract; UTC/filter/pagination; archived records; redaction; fail-closed integrity handling | `test_audit_routes.py::test_access_report_*` and query-service coverage | Task 31 selected archived/corrupt-source tests | Covers recorded application events only; it does not prove completeness of external access logging. |
| Security | HS256 JWT validation, issuer/audience/expiry/subject/roles, endpoint RBAC, no token/payload logging | `test_auth.py`, invalid-token/RBAC/log tests in `test_audit_routes.py` | Task 31 selected authentication/RBAC/log tests | Local symmetric signing key, no rotation, revocation, or IdP integration. |
| Operational readiness | Health/readiness, request correlation IDs, local SQLite write coordination, container configuration | `test_database.py`, API tests, CI smoke script | Developer-confirmed GitHub Actions/Docker run; details unavailable to this review | Single SQLite replica; no distributed coordination or observability backend. |
| Dependency security | Direct pins, strict `pip-audit` CI gate | Task 30/31 local strict scan | Developer-confirmed post-remediation workflow success; run details unavailable | Advisory data changes over time; scan must remain a release gate. |

## Task 31 acceptance checks

The selected 24-test run confirmed application startup configuration, health and
sanitized readiness failure, JWT rejection/RBAC, event creation and chain
verification, idempotent 201/200/409 behavior, redacted replay protection,
retention, export signing, offline trusted-key verification, wrong-key/tampered
bundle rejection, trusted digest mismatch rejection, archived access reporting,
corrupt-source fail-closed reporting, OpenAPI metadata, request IDs, and safe
request logging.

Final local regression passed: 341 tests with one existing TestClient
deprecation warning. `compileall`, `pip check`, `git diff --check`, and strict
`pip-audit --requirement requirements.txt --strict` passed; the scan reported
no known vulnerabilities. The historical `audit_log.db` is never used for
destructive validation; its SHA-256 baseline is
`B0401EBDF6E7A1A65B9E6CB4667A7E0A64D12A94D5D28E8AD3755FC5A2DCC96A`.

## Outstanding checks and limitations

- Independently retrieving the successful GitHub Actions run ID and individual
  job logs remains unavailable with the current local GitHub credential.
- Docker execution is developer-confirmed through CI but not independently
  replayed locally because Docker is unavailable here.
- The prototype remains constrained by its same-database trust boundary,
  SQLite single-replica design, whole-chain memory use, absent migrations, and
  deferred production identity/secret-management infrastructure.

## Test strategy and coverage inventory

The 341-test final regression baseline is a single full-suite count. The 24 selected Task 31 acceptance tests are a subset selected from that coverage and must not be added to it. The suite uses isolated SQLite databases, dependency overrides, temporary credentials, and temporary signing keys where required.

| Testing layer | Primary modules and representative coverage |
| --- | --- |
| Unit/schema/hash | `test_schemas.py`, `test_hashing.py`, `test_models.py`: aliases, input constraints, canonical JSON, fixed vectors, UTC persistence, constraints. |
| Service/database | `test_audit_service.py`, `test_chain_verification.py`, `test_database.py`: append/query/verification, tampering precedence, checkpoints, preflight, locks, readiness. |
| API/integration | `test_audit_routes.py`: JWT/RBAC, OpenAPI, creation, query, verify, lifecycle endpoints, reports, idempotency, sanitized errors, request logging. |
| Lifecycle | `test_retention_service.py`, `test_redaction_service.py`: eligibility, atomicity, metadata integrity, masking, no-op behavior. |
| Export/crypto | `test_export_service.py`: witness/digest, redaction/archive projection, Ed25519 signing, wrong key, downgrade and tamper rejection. |
| Operational/security | Auth, request-ID/logging, SQLite write coordination, `compileall`, `pip check`, strict local `pip-audit`; Docker smoke coverage is developer-confirmed through CI. |

The existing Starlette/TestClient deprecation warning is recorded, not hidden. No load/throughput benchmark, production monitoring test, or independently retrieved remote CI job log is claimed.

## Independent coverage thresholds

`scripts/check_coverage.py` evaluates coverage.py JSON evidence without relying
on coverage's combined percentage. It independently requires overall line
coverage of at least **90%** and overall branch coverage of at least **78%**.
It also requires each active V4/security module below to meet **85%** line and
**70%** branch coverage, except that a module with no executable branches is
reported as branch `N/A`.

- `app/auth.py`, `app/authorization_models.py`,
  `app/authorization_service.py`, and `app/permissions.py`
- `app/api/v4_audit_routes.py`
- `app/services/v4_audit_service.py` and
  `app/services/v4_export_service.py`
- `app/v4_database.py`, `app/v4_database_dependency.py`, `app/v4_main.py`,
  `app/v4_models.py`, and `app/v4_schemas.py`
- `app/verify_v4_export.py`, `app/export_signing.py`, and
  `app/manage_grants.py`

The legacy-compatible `app/verify_export.py` has separate initial floors of
**80%** line and **60%** branch coverage. Token and export-key generation CLIs
remain in overall coverage but do not yet have individual gates pending their
Task 38C coverage work.

Run the gate against existing evidence with:

```bash
python scripts/check_coverage.py .coverage-reports/coverage.json
```

The gate validates raw counts, requires branch coverage, checks the source-file
inventory, and fails on malformed or inconsistent evidence. Coverage's combined
percentage is not sufficient because it can conceal a regression in either line
or branch coverage. A coverage JSON file records execution evidence but does
not prove the Git revision or test command that produced it; freshness must be
established separately by the surrounding CI or validation record.

The initial limits prevent regression from the Task 37C baseline. Future
improvement targets are 91.5% overall line coverage, 82% overall branch
coverage, and 90% line / 80% branch coverage for active V4/security modules.

## Task 32 focused documentation demonstration

Task 32 executed a separate temporary-database FastAPI `TestClient` example using temporary in-process JWT configuration. It returned HTTP 201 for initial writer creation, HTTP 200 for an identical idempotent replay with the same ID, and HTTP 200 with `isIntact:true` for auditor verification. It emitted the existing TestClient deprecation warning. It was not a substitute for, nor added to, the recorded 341-test full regression baseline.
