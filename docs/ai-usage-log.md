# AI Usage Log

This log records the actual AI-assisted workflow for this repository. It is
updated as tasks are proposed, approved, implemented, and reviewed. It does
not represent approval or work that has not occurred.

## Task 1 - Requirements baseline and architecture outline

- **Assessment requirement addressed:** Requirement understanding, task
  decomposition, architecture/design documentation, AI-use traceability, and
  controlled engineer oversight across Scenarios A, B, and C.
- **Prompt record:** Review the supplied assessment; inspect the repository;
  create a complete requirement-to-implementation checklist; then, after
  approval, document the initial requirements baseline and architecture
  without implementing application features.
- **Files created or modified:** `docs/requirements.md`,
  `docs/architecture.md`, and this file.
- **AI contribution:** Extracted requirements from the supplied assessment,
  proposed a minimal FastAPI/SQLite/SQLAlchemy separation, documented
  provisional hash-chain decisions, and listed unresolved Scenario B/C
  questions.
- **Engineer direction accepted:** The engineer approved the Task 1 plan on
  2026-11-24.
- **Engineer modifications or rejections:** None recorded at this point.
- **Reasoning:** Documentation is established before product behavior so later
  implementation and commits can be traced to explicit requirements and
  assumptions.
- **Validation performed:** Manually checked that all three scenarios,
  deliverables, working decisions, and known ambiguities are represented in
  the requirements baseline. No application code changed, so no automated
  tests apply.
- **Engineer review and approval of this implementation:** Approved by the
  engineer on 2026-11-24; approved for a focused documentation commit.

## Task 2 - Audit-event persistence model

- **Assessment requirement addressed:** Scenario A event persistence, required
  event fields, deterministic chain order, and storage for predecessor and
  content hashes.
- **Prompt record:** After approval, implement only the SQLAlchemy audit-event
  model and focused persistence tests; do not add API routes, hash generation,
  or verification behavior.
- **Files created or modified:** `app/models.py`, `tests/test_models.py`, and
  this file.
- **AI contribution:** Proposed the model fields, a server-side UTC timestamp
  default, required hash columns, and in-memory SQLite tests.
- **Engineer direction accepted:** The engineer approved the Task 2 plan on
  2026-11-24.
- **Engineer modifications or rejections:** None recorded at this point.
- **Validation performed:** `.venv\\Scripts\\python.exe -m pytest
  tests\\test_models.py -q` passed: 3 tests passed.
- **Engineer review and approval of this implementation:** Approved by the
  engineer on 2026-11-24; committed as `15f5ae2 feat: add audit event
  persistence model`.

## Task 3 - Canonical audit-event content hashing

- **Assessment requirement addressed:** Scenario A deterministic content
  hashing for the required event fields, while retaining `previous_hash` as a
  separate chain link.
- **Prompt record:** Implement only canonical event-content serialization and
  SHA-256 hashing. Exclude the database ID and `previous_hash`; do not add
  chain appending, database writes, API routes, queries, or verification.
- **Files created or modified:** `app/services/audit_service.py`,
  `tests/test_hashing.py`, `docs/requirements.md`,
  `docs/architecture.md`, and this file.
- **AI contribution:** Proposed one canonical JSON representation, explicit
  UTC timestamp normalization, pure hashing functions, and focused tests.
- **Engineer direction accepted:** The engineer approved the Task 3 plan on
  2026-11-24, including the requirement for explainable code comments.
- **Engineer modifications or rejections:** None recorded at this point.
- **Validation performed:** `.venv\\Scripts\\python.exe -m pytest
  tests\\test_hashing.py -q` passed: 9 tests passed.
- **Engineer review and approval of this implementation:** Approved by the
  engineer on 2026-11-24; approved for a focused hashing commit.

## Task 4 - Service-level audit-event append

- **Assessment requirement addressed:** Scenario A event creation,
  append-only service behavior, server-assigned timestamps, genesis handling,
  and predecessor linkage.
- **Prompt record:** Implement only a service-level append operation that
  creates and flushes one hash-linked event. Do not add routes, queries,
  verification, update/delete behavior, or concurrent-writer coordination.
- **Files created or modified:** `app/services/audit_service.py`,
  `tests/test_audit_service.py`, `docs/requirements.md`,
  `docs/architecture.md`, and this file.
- **AI contribution:** Proposed the transaction-controlled append function,
  genesis constant, predecessor lookup, focused in-memory SQLite tests, and
  explainability comments.
- **Engineer direction accepted:** The engineer approved the Task 4 plan on
  2026-11-24.
- **Engineer modifications or rejections:** None recorded at this point.
- **Validation performed:** `.venv\\Scripts\\python.exe -m pytest
  tests\\test_audit_service.py tests\\test_hashing.py tests\\test_models.py
  -q` passed: 16 tests passed.
- **Engineer review and approval of this implementation:** Approved by the
  engineer on 2026-11-24; approved for a focused append-service commit.

## Task 5 - Validated audit-event API schemas

- **Assessment requirement addressed:** Scenario A write-event field contract,
  server-owned timestamps and integrity evidence, and API/schema definitions.
- **Prompt record:** Implement only Pydantic request and response schemas with
  camelCase API aliases, validation aligned to the model's string limits, and
  explicit rejection of server-owned or unexpected input fields.
- **Files created or modified:** `app/schemas.py`, `tests/test_schemas.py`,
  `docs/requirements.md`, `docs/architecture.md`, and this file.
- **AI contribution:** Proposed Pydantic v2 schemas, alias mapping,
  model-instance serialization, and focused validation tests.
- **Engineer direction accepted:** The engineer approved the Task 5 plan on
  2026-11-24.
- **Engineer modifications or rejections:** None recorded at this point.
- **Validation performed:** The first focused run found that response aliases
  did not read snake_case SQLAlchemy attributes. The read schema was corrected
  with Pydantic's `validate_by_name=True`. The rerun of
  `.venv\\Scripts\\python.exe -m pytest tests\\test_schemas.py -q` passed:
  24 tests passed. The full suite `.venv\\Scripts\\python.exe -m pytest -q`
  passed: 40 tests passed.
- **Engineer review and approval of this implementation:** Approved by the
  engineer on 2026-11-24; approved for a focused schema-contract commit.

## Task 6A - UTC timestamp persistence prerequisite

- **Assessment requirement addressed:** Scenario A timestamp integrity and
  reliable content-hash reproduction after persisted events are read back.
- **Blocker:** SQLite returned timezone-naive datetimes after persistence even
  though the model declared `DateTime(timezone=True)`. The canonical hashing
  contract correctly rejects naive timestamps.
- **Approved scope expansion:** The engineer approved a model-level
  `TypeDecorator` and focused persistence tests before implementation of the
  Task 6 HTTP write API.
- **Files created or modified:** `app/models.py`, `tests/test_models.py`,
  `docs/requirements.md`, `docs/architecture.md`, and this file.
- **AI contribution:** Identified the SQLite round-trip behavior, proposed a
  UTC-normalizing type decorator, and added reload-based hash-consistency
  tests.
- **Engineer modifications or rejections:** None recorded at this point.
- **Validation performed:** The first focused run identified a test-isolation
  issue: an expired model ID was accessed after detachment. The test was
  corrected to retain the ID before the reload. The rerun of
  `.venv\\Scripts\\python.exe -m pytest tests\\test_models.py -q` passed:
  6 tests passed. The full suite `.venv\\Scripts\\python.exe -m pytest -q`
  passed: 43 tests passed.
- **Engineer review and approval of this implementation:** Approved by the
  engineer on 2026-11-24; approved for a focused UTC-persistence commit.

## Task 6 - POST /audit/events write API

- **Assessment requirement addressed:** Scenario A event-write API,
  append-only public behavior, server-assigned timestamp, and end-to-end
  creation through the API and data store.
- **Prompt record:** Add only a request-scoped database dependency, startup
  schema initialization, and `POST /audit/events`; reuse the existing schema
  and append service; test against a temporary database.
- **Prerequisite:** Task 6A corrected SQLite UTC timestamp round-tripping so
  reloaded events remain compatible with canonical hashing.
- **Files created or modified:** `app/database.py`, `app/main.py`,
  `app/api/audit_routes.py`, `tests/test_audit_routes.py`,
  `docs/requirements.md`, `docs/architecture.md`, and this file.
- **AI contribution:** Proposed request session ownership, replaceable
  lifespan initialization for test isolation, a creation-only route, and
  integration tests for validation, rollback, and persisted hash consistency.
- **Engineer direction accepted:** The engineer approved Task 6 on
  2026-11-24 and approved the Task 6A prerequisite before work resumed.
- **Engineer modifications or rejections:** None recorded at this point.
- **Validation performed:** `.venv\\Scripts\\python.exe -m pytest
  tests\\test_audit_routes.py -q` passed: 17 tests passed. The full suite
  `.venv\\Scripts\\python.exe -m pytest -q` passed: 60 tests passed. Both
  runs reported one existing Starlette `TestClient` deprecation warning about
  the installed `httpx` integration; there were no test failures.
- **Manual validation:** The engineer manually exercised `POST /audit/events`
  through Swagger UI, created two events, confirmed predecessor-hash linkage,
  and verified both records in SQLite.
- **Known limitations:** This task provides only creation. Querying,
  verification, concurrent-writer coordination, retention, redaction, and
  export remain out of scope.
- **Engineer review and approval of this implementation:** Approved by the
  engineer on 2026-11-24, subject to final validation and a focused commit.

## Task 7 - Service-level audit-event querying

- **Assessment requirement addressed:** Scenario A querying with combined
  filters, inclusive time ranges, deterministic ordering, and pagination.
- **Prompt record:** Implement only a read-only SQLAlchemy query service; use
  optional AND-composed filters, UTC-normalized timestamps, and validated
  limit/offset pagination. Do not add an HTTP query endpoint.
- **Files created or modified:** `app/services/audit_service.py`,
  `tests/test_audit_service.py`, `docs/requirements.md`,
  `docs/architecture.md`, and this file.
- **AI contribution:** Proposed the parameterized SQLAlchemy query, timestamp
  validation, pagination safeguards, and focused filter-composition tests.
- **Engineer direction accepted:** The engineer approved Task 7 on
  2026-11-24.
- **Engineer modifications or rejections:** None recorded at this point.
- **Validation performed:** `.venv\\Scripts\\python.exe -m pytest
  tests\\test_audit_service.py -q` passed: 19 tests passed. The full suite
  `.venv\\Scripts\\python.exe -m pytest -q` passed: 75 tests passed with one
  existing Starlette `TestClient` deprecation warning and no test failures.
- **Engineer review and approval of this implementation:** Approved by the
  engineer on 2026-11-24; approved for a focused query-service commit.

## Task 8 - GET /audit/events query API

- **Assessment requirement addressed:** Scenario A query API, combined
  filtering, inclusive time bounds, pagination, and read-only API access.
- **Prompt record:** Expose the existing query service as `GET /audit/events`
  with public camelCase query aliases, strict pagination validation, isolated
  API tests, and no duplicated SQLAlchemy query logic.
- **Review-driven correction:** Task 7 range checks did not enforce exact
  Python integer types for direct service callers. This task adds explicit
  rejection of floats, strings, and booleans without rewriting Task 7 history.
- **Schema concern identified:** `AuditEventRead` uses trimmed string
  constraints, which could normalize direct-database tampering in responses.
  The existing schema is reused as required; no out-of-scope schema change was
  made.
- **Files created or modified:** `app/services/audit_service.py`,
  `app/api/audit_routes.py`, `tests/test_audit_service.py`,
  `tests/test_audit_routes.py`, `docs/requirements.md`,
  `docs/architecture.md`, and this file.
- **AI contribution:** Proposed query aliases, boundary validation, generic
  database-error handling, strict service pagination checks, and isolated
  integration tests.
- **Engineer direction accepted:** The engineer approved Task 8 on
  2026-11-24.
- **Engineer modifications or rejections:** None recorded at this point.
- **Validation performed:** `.venv\\Scripts\\python.exe -m pytest
  tests\\test_audit_service.py tests\\test_audit_routes.py -q` passed:
  64 tests passed. The full suite `.venv\\Scripts\\python.exe -m pytest -q`
  passed: 103 tests passed with one existing Starlette `TestClient` deprecation
  warning and no test failures.
- **Engineer review and approval of this implementation:** Approved by the
  engineer on 2026-11-24; approved for a focused query-API commit.

## Task 9 - Checkpoint-backed chain verification foundation

- **Assessment requirement addressed:** Scenario A hash-chain verification,
  direct modification/deletion detection, and append-only integrity evidence.
- **Prompt record:** Add a transactional singleton checkpoint and a read-only
  verification service. Do not add `GET /audit/verify` or alter the canonical
  hash contract.
- **Design correction accepted:** Database IDs are ordered but not required to
  be gap-free; predecessor links and checkpoint metadata provide deletion
  evidence instead. The checkpoint detects trailing deletion.
- **AuditEventRead status:** The whitespace-normalization concern identified
  in Task 8 remains unresolved. Verification reads raw ORM values and does not
  use that schema; no unrelated schema change was made.
- **Files created or modified:** `app/models.py`,
  `app/services/audit_service.py`, `tests/test_models.py`,
  `tests/test_chain_verification.py`, `docs/requirements.md`,
  `docs/architecture.md`, and this file.
- **AI contribution:** Proposed the constrained singleton checkpoint,
  deterministic verification precedence, append safeguards, and isolated
  direct-tampering tests.
- **Engineer direction accepted:** The engineer approved Task 9 on
  2026-11-25.
- **Engineer modifications or rejections:** Manual review required a domain
  exception, accurate checkpoint-only result identifiers, raw persisted-value
  reading, and per-record malformed-content handling before commit.
- **Validation performed:** Earlier review-cycle validation passed: focused
  model, append, and verification tests (58 passed), then the full suite (130
  passed with one existing Starlette `TestClient` deprecation warning). After
  the final per-record decoding correction,
  `.venv\\Scripts\\python.exe -m pytest tests\\test_models.py
  tests\\test_audit_service.py tests\\test_chain_verification.py -q` passed:
  63 tests passed. The complete suite `.venv\\Scripts\\python.exe -m pytest -q`
  passed: 135 tests passed with the same existing deprecation warning and no
  test failures.
- **Review-driven corrections:** Added `AuditChainIntegrityError` for blocked
  appends; operational database errors now propagate instead of being reported
  as malformed evidence; checkpoint-only mismatches return no event ID; and
  verification now queries raw column mappings to avoid stale identity-map
  values or flushing unrelated local changes. The final correction reads raw
  JSON and timestamp text and decodes each event inside the ascending-ID
  verification loop, so a later malformed record cannot prevent reporting an
  earlier hash or predecessor mismatch.
- **Engineer review and approval of this implementation:** Pending.
