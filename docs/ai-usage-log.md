# AI Usage Log

This log records the actual AI-assisted workflow for this repository. It is
updated as tasks are proposed, approved, implemented, and reviewed. It does
not represent approval or work that has not occurred.

This document is organized by task number for readability and assessment
traceability. Historical entries reflect the state of development when they
were recorded; Git history remains the authoritative chronological development
record.

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
- **Engineer review and approval of this implementation:** Approved by the
  engineer on 2026-11-25 and committed as `ac74f04 feat: implement audit
  chain verification and checkpoint integrity`.

## Task 10 - Chain verification API

- **Assessment requirement addressed:** Scenario A `GET /audit/verify`, full
  chain-verification reporting, and direct-database modification/deletion
  detection through the public API.
- **Prompt record:** Expose the existing verification service without changing
  its hashing, checkpoint, or persisted-evidence behavior. Return HTTP 200 for
  intact and inconsistent chains, HTTP 409 for blocked unsafe appends, and a
  sanitized HTTP 500 for operational database failures. Add proportionate
  metadata-only logging and isolated API integration tests.
- **Files created or modified:** `app/api/audit_routes.py`, `app/schemas.py`,
  `tests/test_audit_routes.py`, `docs/requirements.md`,
  `docs/architecture.md`, and this file.
- **AI contribution:** Proposed a thin route adapter, camelCase result schema,
  HTTP error translation, static-message logging, and direct-SQL tampering
  integration coverage.
- **Engineer direction accepted:** The engineer approved Task 10 on
  2026-11-25, including the refined response, logging, and test requirements.
- **Engineer modifications or rejections:** None recorded during
  implementation so far.
- **Validation performed:** `.venv\\Scripts\\python.exe -m pytest
  tests\\test_audit_routes.py tests\\test_chain_verification.py -q` passed:
  80 tests passed. The complete suite `.venv\\Scripts\\python.exe -m pytest
  -q` passed: 145 tests passed. Both runs emitted one existing Starlette
  `TestClient` deprecation warning and had no failures.
- **Manual validation (developer-performed):** Using isolated SQLite databases
  outside the repository, the engineer verified an empty chain in Swagger,
  created and verified three events, and inspected persisted hashes,
  predecessor links, and checkpoint state. The engineer created a healthy
  SQLite backup, directly modified Event 2's payload, and confirmed HTTP 200
  with `isIntact=false`, `checkedRecordCount=2`,
  `firstInconsistencyId=2`, and `CONTENT_HASH_MISMATCH`. In a separate copy of
  the healthy database, trailing deletion produced checkpoint-count detection
  and an unsafe append was rejected with HTTP 409. An unexpected HTTP 409
  occurred during an initial Event 2 creation attempt; subsequent testing
  created and verified three events, but the original cause was not
  established and no diagnosis or fix is claimed.
- **Known limitations:** The endpoint reflects the existing service limits:
  no external checkpoint trust anchor, concurrent-writer coordination, or
  consistent verification snapshot. The separate `AuditEventRead`
  whitespace-normalization concern remains unchanged.
- **Engineer review and conditional approval:** The engineer reviewed and
  approved the V3 foundation and metadata designs on 2026-11-25, subject to a
  final focused review of model definitions, SQLite foreign-key enforcement,
  lifecycle requirements, validation, and staging. The engineer authorized the
  Task 15 commit if those acceptance conditions pass. This approval does not
  claim implementation of lifecycle services, metadata integrity verification,
  retention execution, redaction projection, or export.

## Task 11 - Repository readiness and documentation

- **Assessment requirement addressed:** Repository reproducibility, current
  setup and operational documentation, Scenario A status consistency, and
  transparent AI-assisted engineering evidence.
- **Prompt record:** Make a clean checkout reproducible without the existing
  virtual environment, runtime database, or untracked files. Pin only verified
  direct dependencies, document setup and safe manual testing, correct stale
  Scenario A documentation, and validate in a fresh detached worktree.
- **Files created or modified:** `requirements.txt`, `.gitignore`, package
  initialization files, `README.md`, `docs/requirements.md`,
  `docs/architecture.md`, and this file.
- **AI contribution:** Identified the missing committed dependency manifest,
  stale README/status language, and insufficient runtime database exclusions;
  proposed exact direct pins based on the tested Python 3.12 environment and a
  detached-worktree validation approach.
- **Engineer direction accepted:** The engineer approved Task 11 on
  2026-11-25, with fresh-environment installation and HTTP smoke validation.
- **Engineering decisions:** The manifest pins only direct application and
  test dependencies known to pass, not a full `pip freeze`. This improves
  repeatability but is not a transitive lock file or hash-verified supply
  chain. Existing package versions are retained, including the known
  TestClient deprecation warning.
- **Validation performed:** The existing Python 3.12.7 project environment
  matched the pinned direct dependencies and passed `pip check`. A detached
  worktree outside the repository received the exact staged Task 11 patch and
  used a newly created Python 3.12.7 virtual environment. `python -m pip
  install -r requirements.txt` and `python -m pip check` passed. Importing
  `app.main` passed; a temporary Uvicorn server in that worktree returned HTTP
  200 for `/health`, `/docs`, and `/openapi.json`, with `/audit/verify` present
  in OpenAPI. The first `python -m pytest -q` attempt had 49 setup errors
  because pytest could not enumerate a permission-restricted shared Windows
  temporary directory; this was an environment permission issue, not a test
  failure. Rerunning unchanged tests with `python -m pytest -q --basetemp
  .pytest_cache\\task11-basetemp` confined temporary files to the ignored
  worktree cache and passed: 145 tests passed with one existing Starlette
  `TestClient` deprecation warning.
- **Developer manual regression troubleshooting:** The developer separately
  ran the suite on Windows and observed two filesystem permission failures:
  pytest could not access the default `AppData/Local/Temp/pytest-of-asif2`
  directory, and an override to `.pytest_cache/local-test-temp` also failed.
  Each execution reported 96 passed tests and 49 setup errors. The developer
  then created a fresh writable directory outside the repository and ran
  `mkdir -p /c/Charles_Schwab/pytest-temp` followed by `python -m pytest -q
  -p no:cacheprovider --basetemp
  "C:/Charles_Schwab/pytest-temp/run-$(date +%Y%m%d-%H%M%S)"`. The developer
  confirmed that this regression suite passed. This was developer-performed
  manual troubleshooting, not a Codex execution; the underlying Windows
  permission configuration was not diagnosed or repaired.
- **Engineer review and approval of this implementation:** Pending.

## Task 12 - Evidence-preserving response schemas

- **Engineering improvement:** Supports Scenario A audit-evidence fidelity by
  preserving observable persisted audit evidence in GET responses without
  weakening untrusted create-input validation. It is not recorded as a newly
  stated original assessment requirement.
- **Prompt record:** Separate the four persisted event string response fields
  from create-schema normalization. Preserve API aliases and existing
  verification behavior; add focused schema and isolated API tampering tests.
- **Files created or modified:** `app/schemas.py`, `tests/test_schemas.py`,
  `tests/test_audit_routes.py`, `docs/requirements.md`,
  `docs/architecture.md`, and this file.
- **AI contribution:** Identified that `AuditEventRead` reused
  `strip_whitespace`, nonempty, and maximum-length constraints intended for
  incoming input; proposed plain read-side strings and parameterized coverage.
- **Engineer direction accepted:** The engineer approved Task 12 on
  2026-11-25.
- **Implementation decision:** `AuditEventCreate` retains all constrained
  aliases and extra-field rejection. Only `AuditEventRead`'s event type,
  actor ID, resource type, and resource ID are plain strings, so persisted
  evidence is returned literally. Chain verification remains independent and
  unchanged.
- **Validation performed:** Focused schema and API tests using an external
  disposable pytest base directory passed: 141 tests passed with one existing
  Starlette `TestClient` deprecation warning. The complete suite using a fresh
  external disposable pytest base directory passed: 213 tests passed with the
  same existing warning and no failures.
- **Known limitations:** This preserves the four affected string fields only.
  It does not make malformed JSON, timestamps, nulls, or incompatible database
  types retrievable, and it does not make modified evidence trustworthy.
- **Engineer review and approval of this implementation:** Application code,
  test code, and documentation approved by the engineer on 2026-11-25; final
  validation and commit approval in progress.

## Task 13 - Cryptographically linked chain integrity

- **Engineering improvement:** Resolves the Scenario A reconciliation finding
  that a separate predecessor link did not make downstream hashes
  cryptographically dependent on earlier records.
- **Engineer direction accepted:** The engineer approved Option C: retain the
  independent content hash and add a versioned linked chain hash, with a fresh
  V2 database and no automatic legacy migration.
- **Implementation decision:** `previous_hash` retains predecessor-content
  semantics. V2 adds scheme, predecessor-chain, and chain-hash evidence; the
  checkpoint stores the V2 head chain hash. Startup preflight rejects legacy
  or partial schemas before `create_all` can write.
- **AI contribution:** Designed the canonical chain-link encoding, bounded
  tail validation, deterministic verification precedence, isolated legacy
  schema tests, and additive response contract.
- **Review-driven correction:** The final review found that an explicit empty
  `AUDIT_DB_PATH` produced an invalid SQLite directory URL and that the
  verifier docstring omitted the implemented V2 failure precedence. Empty or
  whitespace-only values now raise a configuration error before URL creation;
  the docstring now names all implemented violation types in precedence order.
- **Configuration coverage:** Added isolated tests for absent, empty,
  whitespace-only, relative, absolute, and space-containing paths. The
  space-containing path test creates and preflights a disposable V2 database.
- **Historical status reconciliation:** Earlier Task 10--12 entries retain
  their contemporaneous pending wording. This prospective record notes that
  Task 11 was committed as `c49914b` and Task 12 as `17a324c`; no historical
  entry has been rewritten.
- **Known limitation:** A fully privileged actor can still rewrite records,
  every linked hash, and checkpoint state in the same database. This test is
  documentation of the trust boundary, not successful attack prevention.
- **Validation performed:** Focused model, hashing, service, verification,
  database, schema, and API tests passed: 232 tests passed with one existing
  Starlette `TestClient` deprecation warning. After the final checkpoint-version
  regression addition, the complete suite using a fresh external disposable
  pytest base directory passed: 233 tests passed with the same warning. An
  isolated application startup using a fresh explicit V2
  database returned HTTP 200 for health, OpenAPI, and verification endpoints.
- **Database review baseline:** The engineer supplied review-stage SHA-256
  `B0401EBDF6E7A1A65B9E6CB4667A7E0A64D12A94D5D28E8AD3755FC5A2DCC96A`
  for the original ignored `audit_log.db`. It establishes a comparison point
  from review onward, not proof of that database's state before Task 13.
- **Correction validation:** The focused database configuration suite passed:
  7 tests passed. The final complete suite passed: 238 tests passed with the
  same existing warning. The five-test increase from 233 covers default-path,
  three explicit empty/whitespace-path cases, and relative/absolute paths with
  a disposable database filename containing spaces.
- **Engineer final approval:** The engineer accepted Scenario A as a
  functional prototype on 2026-11-25, subject to final Git validation and the
  approved Task 13 commit. This records the final status prospectively without
  rewriting earlier historical entries.

## Task 15 - Scenario B V3 database foundation

- **Engineering improvement:** Establishes a fresh V3 persistence boundary for
  later logical archival and non-destructive redaction without changing the
  Scenario A event, content-hash, linked-chain, checkpoint, API, or query
  behavior.
- **Engineer direction accepted:** The engineer approved logical archival,
  separate lifecycle metadata, JSON Pointer redaction overlays, chained future
  lifecycle events, and a fresh V3 database without automatic migration. This
  task is limited to the metadata and safe-startup foundation.
- **AI contribution:** Proposed the minimal metadata keys and references,
  enabled SQLite foreign-key enforcement for application and isolated test
  engines, implemented strict V3 table/column-name preflight, and added
  isolated persistence and incompatible-schema coverage.
- **Implementation decision:** `audit_event_archives` has a surrogate ID, a
  unique non-null target event ID, UTC archive time, and a future archive-action
  event ID.
  `audit_event_redactions` stores a target ID, JSON Pointer, UTC redaction
  time, non-sensitive reason/category, and future redaction-action event ID;
  its target/pointer pair is unique. Neither table stores original sensitive
  values. They remain unused until later approved lifecycle services.
- **Schema safety:** The default database is now `audit_log_v3.db`. Startup
  permits fresh and complete V3 schemas only; it rejects V1, V2, partial V3,
  and mixed `audit_` schemas before `create_all`. Validation checks only table
  names and column-name sets, not types, constraints, indexes, or table SQL.
  No migration, backfill, recalculation, or runtime database modification was
  performed.
- **Validation performed:** Focused model and database tests passed: 30 tests.
  The complete suite using a fresh external disposable pytest base directory
  passed: 254 tests with one existing Starlette `TestClient` deprecation
  warning. An isolated V3 application startup with an explicit temporary path
  containing spaces returned HTTP 200 for `/health`, `/openapi.json`, and
  `/audit/verify`. Final focused review added an assertion that deleting a
  referenced audit event is rejected by SQLite foreign-key enforcement; the
  focused and complete results above were rerun after that addition.
- **Database protection:** Before implementation, the original ignored
  `audit_log.db` matched the supplied review-stage SHA-256
  `B0401EBDF6E7A1A65B9E6CB4667A7E0A64D12A94D5D28E8AD3755FC5A2DCC96A`.
  No V2 runtime database files were present in the repository. Final checksum
  comparison is recorded with final validation; the baseline proves comparison
  from the review stage onward, not the database state before prior work.
- **Known limitations:** Archive execution, redaction projection, lifecycle
  action creation, metadata/action verification, export, authentication,
  authorization, migrations, external checkpoint anchoring, and concurrent
  writer coordination remain unimplemented. Future lifecycle/export HTTP
  endpoints are intended for trusted local assessment use until access control
  is separately approved.
- **Engineer review and approval of this implementation:** Pending.

## Task 16 - Configurable retention and logical archival

- **Engineering improvement:** Implements the approved Scenario B retention
  slice while retaining original audit events and their existing hash evidence.
  It does not implement redaction, export, authentication, authorization, or
  Scenario C.
- **Engineer direction accepted:** The engineer approved a server-owned,
  bounded retention policy; strict UTC cutoff behavior; reserved lifecycle
  event types; one chained archival action per non-empty run; archive-aware
  retrieval; and bidirectional archive/action verification.
- **AI contribution:** Added the bounded `AUDIT_RETENTION_DAYS` parser and
  default, a caller-owned retention service, reserved-type protection at schema
  and ordinary-service boundaries, an empty policy-run API contract, database
  archive filtering, lifecycle metadata verification, and isolated service/API
  regression coverage.
- **Implementation decision:** The default policy is 90 days and the maximum
  is 36,500 days. Eligible targets are strictly earlier than the normalized UTC
  cutoff, unarchived, and not internal lifecycle events. A successful run first
  performs full read-only verification, then appends one
  `AUDIT_RETENTION_APPLIED` event whose payload records duration, cutoff,
  ordered target IDs, count, and action timestamp. Archive metadata receives
  that exact server timestamp. No-op runs append nothing.
- **Integrity decision:** Existing content and linked hashes remain unchanged.
  Lifecycle checks run only after the established event-chain and checkpoint
  checks. `ARCHIVE_MALFORMED_ACTION` identifies malformed action evidence;
  `ARCHIVE_METADATA_MISMATCH` identifies missing, unexpected, duplicate,
  conflicting, ineligible, or timestamp/reference-inconsistent archive state.
  Redaction metadata verification remains deferred.
- **Validation performed:** Initial focused retention/API coverage passed, then
  final focused retention, API, and schema validation passed: 165 tests. The
  complete suite using a fresh external disposable pytest directory passed:
  272 tests with one existing Starlette `TestClient` deprecation warning and no
  failures, skips, or deselections. An isolated V3 startup/no-op retention
  smoke test passed. A separate disposable eligible-event demonstration passed
  successful archival, default query exclusion, explicit inclusion, intact
  full-chain verification, and archive-metadata tampering detection.
- **Known limitations:** Logical archival retains payloads and storage; it is
  not permanent erasure. One retention execution materializes all eligible IDs
  in memory and has no scheduler, batching, concurrency coordination, access
  control, migration path, external anchoring, or production observability.
  The lifecycle endpoint is intended only for trusted local assessment use.
- **Engineer review and conditional approval:** The engineer approved the
  retention architecture in principle and authorized commit after focused
  review of lifecycle metadata verification, rollback behavior, API error
  handling, required adversarial coverage, final validation, and protected
  database checks. The review-driven cutoff/duration consistency check and
  focused tests were added before final validation. This remains an approval of
  logical archival only, not redaction, export, access control, or production
  readiness.

## Task 17 - Sensitive payload redaction and lifecycle integrity

- **Engineering improvement:** Adds non-destructive JSON Pointer redaction
  overlays while preserving original audit payloads, hashes, links, and
  timestamps. This is masking at retrieval, not permanent deletion.
- **Implementation decision:** Valid requests contain at most 50 distinct,
  non-overlapping RFC 6901 paths and an allowlisted non-sensitive reason code.
  One `AUDIT_REDACTION_APPLIED` lifecycle event records the target, ordered new
  paths, count, reason, and action timestamp. Matching metadata uses that exact
  timestamp; repeated existing paths are no-ops and do not rewrite a reason.
- **AI contribution:** Added pointer parsing/projection helpers, service and
  API boundaries, lifecycle verification, projected query responses, focused
  isolated tests, and documentation of the hash/projection trust boundary.
- **Validation performed:** Final focused acceptance coverage added checkpoint,
  fail-closed retrieval, and rollback assertions. The complete regression suite
  using a fresh external disposable pytest base directory passed: 278 tests
  with one existing Starlette `TestClient` deprecation warning and no failures.
- **Known limitations:** Redaction has no authentication or authorization,
  permanent erasure, export, concurrency coordination, scheduler, migration,
  or external trust anchor. The endpoint is for trusted local assessment use.
- **Engineer review and conditional approval:** The engineer approved commit
  after focused confirmation of checkpoint advancement, lifecycle fail-closed
  retrieval, atomic rollback, Scenario A/retention compatibility, final
  regression validation, and database preservation.

## Task 18 - Bulk Export and Independent Verification

- **AI contribution:** Added a read-only export service and `POST /audit/exports`,
  plus a standard-library-only `python -m app.verify_export` utility. Reused
  existing full-chain verification, lifecycle overlays, canonical hashing, and
  redaction projection rather than creating alternate evidence rules.
- **Implementation decision:** Bundles contain masked selected records, related
  lifecycle metadata, a payload-free ordered witness, checkpoint state, fixed
  scheme/genesis values, and a canonical SHA-256 digest. The standalone tool
  distinguishes internal consistency from comparison with an externally
  retained expected digest and labels redacted content as non-recomputable.
- **Validation:** Focused export/API coverage passed: 105 tests with one
  existing Starlette `TestClient` deprecation warning. The complete regression
  suite, using a fresh external disposable pytest base directory, passed: 296
  tests with the same single warning. No manual Swagger testing was performed;
  comprehensive manual API validation remains deferred to Task 19.
- **Engineer approval:** The engineer accepted Task 17 and authorized Task 18
  implementation and commit after the specified integrity, redaction, archive,
  verifier, and regression checks. This entry records the actual completion
  result; it does not claim manual Swagger validation.

## Task 20 - Scenario C requirement clarification and design

- **Planning only:** Recorded ambiguity questions and a proposed normalized
  regulator account-access reporting requirement. No application code, tests,
  database, dependency, or Git changes beyond this planning documentation were
  made.
- **Proposed direction:** A future regulator-only read API would reuse existing
  query, lifecycle validation, redaction, retention, and evidence primitives;
  JWT authentication and RBAC are explicitly deferred to its security task.
  Stakeholders must define access-event taxonomy, identity, outcome, reporting
  range, regulator role, and data-minimization obligations before approval.
- **Task 19 manual status reported by the engineer:** An isolated V3 database
  was used. Repeated redaction and standalone expected-digest verification
  passed. Remaining Swagger/manual acceptance checks are deferred to final
  application acceptance; no claim is made that they were completed.

## Task 21 - Compliance reporting

- **AI contribution:** Implemented a read-only access-report route, explicit
  access-event contract validation, verified filtering/pagination, and isolated
  API coverage for filtering, UTC validation, redaction, archival inclusion,
  invalid input, and corrupt-source rejection.
- **Scope boundary:** The report uses existing verification, lifecycle, archive,
  and redaction behavior. It covers only explicitly recorded access events and
  does not infer outcomes from historical payloads. JWT and regulator RBAC are
  deferred to Task 22; manual validation remains deferred to final testing.
- **Validation:** Focused API coverage passed: 102 tests with one existing
  Starlette `TestClient` warning. The complete regression suite passed: 306
  tests with the same single warning. No database migration or dependency
  change was made.

## Task 22 - JWT authentication and RBAC

- **AI contribution:** Added environment configuration, JWT claim validation,
  Bearer Swagger support, RBAC, local token CLI, and isolated tests.
- **Boundary:** No token issuance endpoint, secrets manager, key rotation,
  revocation, or IdP integration. JWT subject is distinct from business actorId.
- **Validation:** Focused JWT/API coverage passed: 111 tests with one existing
  Starlette `TestClient` warning. After the isolated startup-test configuration
  correction, the complete suite passed: 315 tests with the same warning.

## Task 23 - Essential production hardening

- **AI contribution:** Added safe request telemetry, request IDs, readiness,
  sanitized unexpected errors, and SQLite local write coordination.
- **Quality:** Focused tests passed. Full regression and available checks are
  recorded after execution; no vulnerability scanner is configured.

- **Validation:** Focused readiness/locking/API tests passed: 125 tests. Full
  regression passed: 319 tests, both with one existing TestClient warning.
  `compileall` and `pip check` passed. No vulnerability scanner is installed.

## Task 25 - Lifecycle integrity exposure prevention

- **Finding:** Isolated direct-SQL testing reproduced a narrowed lifecycle
  validation bypass that could expose a redacted original payload.
- **Correction:** Retrieval now fails closed after full verification; `/verify`
  remains available for diagnosis. Focused/full results follow validation.

## Task 26 - Ed25519 signed audit exports

- **AI contribution:** Added optional Ed25519 digest signing, safe local key
  generation, and independent-public-key offline verification.
- **Boundary:** Unsigned bundles remain compatible. Configured signing cannot
  silently downgrade; embedded key IDs are identifiers, not trust anchors.

- **Validation:** Focused signing tests passed: 16 tests. Full regression
  passed: 324 tests with one existing TestClient warning.

- **Validation:** Focused retrieval/redaction tests passed: 117 tests. Full
  regression passed: 321 tests with one existing TestClient warning.

## Task 27 - Transactional write idempotency

- **AI contribution:** Added writer-scoped fingerprints, atomic replay mapping,
  conflict handling, and additive V3 initialization.

## Task 28 - API hardening and OpenAPI documentation

- **AI contribution:** Added bounded offset validation, accurate integrity
  wording, endpoint OpenAPI summaries/error responses, and documentation
  reconciliation. Tests are pending manual execution.

- **Validation:** Developer manual validation passed 223 focused and 341 full
  tests. After the OpenAPI 422-schema correction, Codex reran the full suite:
  341 passed with one existing deprecation warning.

## Task 29 - Secure Docker containerization

- **AI contribution:** Added non-root Python 3.12 image, Compose storage and
  health check, signing override, secure build exclusions, and runtime config
  template. Docker CLI was unavailable locally, so image/runtime checks remain
  unverified pending a Docker-enabled environment.

- **Validation:** Codex ran the full regression suite after documentation
  review: 341 passed with one existing TestClient deprecation warning. Static
  `compileall`, `pip check`, and Git diff validation passed. Docker build,
  Compose parsing, and container runtime validation could not run because the
  local Docker CLI was unavailable.

- **Review correction:** Added genuine concurrent API coverage and narrowed
  idempotency validation error mapping so unrelated internal ValueError cases
  retain sanitized HTTP 500 behavior.

- **Developer validation:** Focused tests passed: 12 in 3.54 seconds. Full
  regression passed: 334 in 36.85 seconds, with one existing deprecation
  warning and zero failures. The developer confirmed concurrent same-key,
  rollback, redacted replay, corruption, isolation, and compatibility coverage.

## Task 30 - CI, dependency scanning, and Docker runtime validation

- **AI contribution:** Added a least-privilege GitHub Actions workflow with
  Python regression, pinned `pip-audit`, and a bounded Compose smoke script.
  The script creates test-only JWT values at runtime and cleans its unique
  containers and volume on exit.
- **Validation status:** Local workflow and shell syntax checks, dependency
  scanning where network access permits, and regression results are recorded
  only after execution. Docker runtime validation is pending the first remote
  GitHub Actions run because local Docker is unavailable.

- **Validation performed:** Shell syntax, application compilation, `pip check`,
  and Git diff checks passed. `pip-audit 2.10.1` reported no known
  vulnerabilities for `requirements.txt`. The complete regression suite passed:
  341 tests with one existing TestClient deprecation warning. Docker image and
  Compose runtime checks remain pending remote execution.

- **Review correction:** Generated CI signing keys and smoke-test bearer tokens
  are now registered with GitHub log masking before use. The smoke test asserts
  exact 200/201/401 response contracts rather than accepting any successful
  2xx response. Remote Docker validation remains pending.

- **Remote CI finding and remediation:** The first remote `pip-audit` job
  failed with 33 findings that included repeated advisory identifiers for PyJWT
  2.10.1 and cryptography 46.0.5. Local and remote results differed because
  the vulnerability advisory data is time-dependent. PyJWT 2.15.0 and
  cryptography 50.0.0 were selected from the reported fixed versions after
  confirming Python 3.12 availability. PYSEC-2025-183 is separately recorded:
  OSV marks versions through 2.10.1 as affected, notes the supplier disputes
  the weak-key characterization, and lists no fixed version. The post-update
  strict scan, focused security tests, and full regression results are recorded
  only after execution; a passing remote CI run remains pending.

- **Validation performed:** Focused JWT/RBAC and export-signing coverage passed:
  30 tests, with 118 unrelated tests deselected and one existing TestClient
  deprecation warning. The complete suite passed: 341 tests with that same
  warning. `compileall` and `pip check` passed. The updated strict `pip-audit`
  scan reported no known vulnerabilities for `requirements.txt`. The historical
  database checksum remained unchanged. A post-remediation remote CI run is
  still required to validate the GitHub-hosted environment.

## Task 31 - Final end-to-end acceptance validation

- **Repository/CI evidence:** Local `main` and `origin/main` matched at
  `82d88adc658b3a55e7bc008ef3023c40cdcf5597`. The developer confirmed a
  successful post-remediation GitHub Actions pipeline. Codex could not retrieve
  a run ID, job breakdown, or Docker logs: the configured GitHub CLI credential
  was invalid and the unauthenticated Actions API returned 404.
- **Acceptance evidence:** A new external disposable pytest base directory ran
  24 selected API, crypto, reporting, and operational tests with temporary
  credentials and isolated SQLite databases: all passed with one existing
  TestClient deprecation warning. Full regression/security results are recorded
  after execution. No historical database is used for tampering tests.

- **Final local validation:** The complete regression suite passed: 341 tests
  with one existing TestClient deprecation warning. `compileall`, `pip check`,
  strict `pip-audit --requirement requirements.txt --strict`, and `git diff
  --check` passed. The local scan reported no known vulnerabilities and the
  historical database checksum matched its baseline. No application defect was
  found; remote CI job-level evidence remains unavailable to this review.

## Task 32.2 - Current high-level architecture documentation

- **AI contribution:** Reorganized `docs/architecture.md` around the current
  implementation after reviewing the actual routes, services, models,
  authentication, deployment configuration, and CI workflow. The document now
  includes implementation-aligned Mermaid architecture, deployment, and CI
  diagrams.
- **Historical preservation:** The prior incremental architecture narrative is
  retained as a clearly labelled historical record. Requirements and this log
  preserve task-era decisions without presenting superseded future-tense plans
  as current behavior.
- **Validation status:** Documentation-focused source cross-checks, Markdown
  links, Mermaid review, diff validation, and database checksum verification
  are recorded after this review. No application code or tests are changed or
  executed for this documentation-only task.

## Task 32.3 - Comprehensive low-level system design documentation

- **AI contribution:** Added `docs/system-design.md` as a low-level design
  document based on source inspection of initialization, configuration,
  routes, schemas, models, services, hashing, verification, lifecycle
  metadata, exports, signing, offline verification, JWT/RBAC, idempotency,
  telemetry, and tests.
- **Documentation decisions:** Kept `docs/architecture.md` as the high-level
  component/deployment view and documented internal algorithms, fields,
  transaction boundaries, error behavior, complexity, trade-offs, and source
  traceability in the new system-design document. Added the ten requested
  implementation-aligned Mermaid diagrams. No application behavior was
  changed.
- **Validation status:** Source cross-check and Markdown structure review were
  performed. The document contains ten Mermaid blocks and no private keys,
  credentials, or database values. No regression tests were run because this
  was documentation-only work. The initial environment check used the system
  Python and could not import SQLAlchemy. The engineer-directed follow-up used
  `.venv\Scripts\python.exe` successfully: Python 3.12.7, SQLAlchemy 2.1.9,
  and `pip check` reported no broken requirements. The real canonicalization
  and hash functions then calculated a fixed three-event example twice with
  identical canonical JSON, content hashes, chain hashes, and checkpoint. A
  one-field modification of event 2 produced a different content hash. No
  database or verifier execution was claimed for that illustrative tamper
  explanation.
- **Engineer review status:** Implementation and factual review are pending;
  no commit or push has been performed.
- **Observed source-comment drift (not changed):** The runtime implementation
  enforces regulator authorization for access reports, but the
  `list_access_reports()` docstring still says authorization is deferred.
  Some older lifecycle model comments also describe now-implemented behavior
  as future work, and the offline verifier module docstring still says it uses
  only the standard library despite importing `cryptography` for trusted
  Ed25519 verification. These comments do not change runtime behavior; they
  are recorded for a separate source-comment maintenance task.

## Task 32.4–32.15 - Consolidated final engineering documentation

- **AI contribution:** Created Scenario A/B/C guides, API reference, security threat model, walkthrough, practical examples, expanded testing evidence, requirements navigation, repository navigation, and engineering-summary documentation. The application remained feature-frozen.
- **Evidence discipline:** Preserved the 341-test full regression baseline and the 24 selected acceptance tests as separate, non-additive evidence. Kept developer-confirmed CI success distinct from unavailable independently retrieved run/job logs. No invented screenshots, benchmark results, remote CI IDs, credentials, private keys, or production claims were added.
- **Focused demonstration:** A disposable temporary-database `TestClient` run using temporary JWT configuration returned 201 for creation, 200 for an identical idempotent replay of the same ID, and 200/intact verification. It emitted the existing TestClient deprecation warning. Windows retained an empty temporary directory after SQLite cleanup; no project database, source, test, dependency, or credential file was changed.
- **Documentation finding:** Existing README duplication/stale deferred statements and historical requirements future-tense wording are reconciled through current-state navigation rather than rewriting historical records. Source-comment drift from Task 32.3 remains outside documentation-only authority.
- **Engineer review status:** Documentation work is complete; no human approval beyond previously recorded approvals is inferred.

## Task 32 final documentation validation

- **Completion:** The approved documentation groups were completed through incremental documentation-only commits. Current navigation distinguishes the evaluator summary, high-level architecture, low-level design, scenarios, API/security references, testing evidence, walkthrough, examples, requirements history, and AI usage history.
- **Validation:** Repository Markdown links were checked, code fences and Mermaid blocks were manually reviewed, and `git diff --check` was run before documentation commits. The historical database checksum remained `B0401EBDF6E7A1A65B9E6CB4667A7E0A64D12A94D5D28E8AD3755FC5A2DCC96A`. No full regression rerun was required after documentation-only changes; the recorded 341-test baseline remains the evidence baseline.
- **Remaining submission work:** Human review of final documentation, optional sanitized screenshot capture and GitHub rendering review, Task 33 attestation, and an approved final push remain outside Task 32. No application, test, dependency, Docker, CI, or database change was made by this workflow.

## Task 33 - Final attestation and submission readiness

- **Attestation preparation:** The engineer supplied their name, email, assignment dates/time, and recovered assessment declaration wording. `ATTESTATION.md` records those engineer-provided details; AI did not invent personal information, dates, or declaration text.
- **Repository validation:** The uncommitted local token-expiry change was restored under explicit engineer authorization after confirming it was the only pending application diff. The feature-frozen source/tests/dependencies/deployment baseline and historical database checksum were then rechecked without rerunning regression.
- **Security and evidence review:** Current tracked files and relevant Git history were checked for private-key headers, JWT-shaped tokens, environment files, database files, and virtual-environment paths; no matching sensitive material was found. GitHub CLI authentication was invalid, so repository privacy and detailed remote CI logs remain developer-manual verification items.
- **Screenshots and submission:** Optional screenshots were intentionally skipped by engineer decision. This task prepares local documentation only; no attestation commit, push, or assessment submission has occurred. Final engineer approval is still required before staging and committing these three files.

## Task 34 - Baseline verification and measured test coverage

- **Engineer-provided objective:** Establish reproducible line and branch
  coverage measurement without changing application business logic,
  authorization, database schemas, hashing, or lifecycle behavior.
- **AI contribution:** Inspected the clean baseline, dependency manifest,
  pytest availability, and CI regression command. Added pinned
  `pytest-cov==7.1.0` and `coverage==7.17.5`, plus branch-coverage pytest
  configuration that reports application-source coverage and writes ignored
  XML, HTML, JSON, and JUnit evidence under `.coverage-reports/`.
- **Files created or modified:** `requirements.txt`, `.gitignore`,
  `pytest.ini`, `.coveragerc`, and this file. No application source, tests,
  database files, CI workflow, or Docker configuration changed.
- **Validation performed:** On Python 3.12.7, the full existing regression
  suite with coverage enabled passed: 341 tests passed with one existing
  Starlette `TestClient` deprecation warning in 56.80 seconds. The measured
  baseline is 85.94% line coverage (1192/1387 statements) and 77.11% branch
  coverage (347/450 branches); coverage's combined percentage is 83.78%.
  `pip check` passed and strict `pip-audit --requirement requirements.txt
  --strict` reported no known vulnerabilities. The historical database
  checksum remained unchanged.
- **Coverage limitations and pending review:** Command-line key/token utilities
  have no automated execution coverage, and the lowest covered security-relevant
  areas are offline export verification, redaction validation/projection, and
  audit-chain/lifecycle error branches. No coverage threshold is enforced in
  this baseline task. Human review is pending before any commit.
- **Engineer review and conditional approval:** The engineer reviewed the
  measured baseline and approved this configuration for commit. Coverage is
  enabled by default through `pytest.ini`; a focused opt-out run using
  `python -m pytest -q -o addopts="" tests/test_hashing.py` passed 14 tests
  without modifying existing coverage evidence. Threshold enforcement and CI
  artifact publication remain pending future approval.

## Task 35 - Resource-level authorization architecture and security analysis

- **AI contribution:** Performed a read-only review of JWT validation,
  role dependencies, event ownership fields, idempotency, audit queries,
  lifecycle operations, exports, verification, and relevant tests. Identified
  that current authorization is role-only and does not establish tenant,
  account, or resource scope.
- **Engineer-provided design review:** A ChatGPT-reviewed, evaluator-derived
  design brief was supplied for documentation. It proposes hybrid
  authorization: verified JWT identity and tenant context plus authoritative
  server-side grants, explicit permissions, deny-by-default behavior, a fresh
  V4 tenant-specific chain schema, and a trusted offline grant CLI.
- **Design findings:** Tenant-specific chains prevent cross-tenant witness
  exposure, but resource grants alone cannot safely receive a full
  independently verifiable witness. The proposal therefore requires a distinct
  tenant-wide witness permission and denies the existing export format without
  it. It also uses opaque public event references and tenant-local sequence
  numbers rather than public global database IDs.
- **Documentation created:** `docs/authorization-design.md` records proposed
  claims, grants, V4 data model, chain behavior, endpoint policy, staged
  implementation plan, adversarial tests, and legacy fail-closed behavior.
- **Status and limitations:** No authorization implementation, database
  migration, dependency change, test execution, or claim of engineer approval
  occurred in this task. Grant administration, V4 rollout, privileged database
  administrator risk, identity-provider integration, and restricted-export
  requirements remain open for engineer approval.
- **Engineer architecture approval:** The engineer approved the V4 hybrid JWT
  and server-grant design, deny-by-default policy, explicit tenant-wide
  permissions, tenant-specific chains/checkpoints, opaque public references,
  tenant-scoped idempotency, witness authorization, SQLite retention, and
  historical-evidence preservation. Future implementation must reject tokens
  without tenant claims, avoid wildcard/global grants, preserve integrity-test
  assertions, and avoid claiming complete tenant isolation until every
  protected endpoint is integrated and tested. Production deployment and
  privileged database-administrator limitations remain unresolved.

## Task 36A - Tenant and resource authorization foundation

- **Engineer-approved scope:** Implement the V4 identity, explicit permission,
  membership, grant, policy-service, and offline-administration foundation
  without integrating existing HTTP routes or tenant hash chains.
- **AI contribution:** Added centralized resource and tenant permission
  definitions; a strict V4 tenant-aware JWT identity path; isolated
  authorization metadata models; live deny-by-default membership and exact
  grant checks; and an explicit-target offline grant CLI. The development token
  CLI can issue a tenant claim for future V4 routes while legacy route tokens
  remain isolated from the V4 authentication path.
- **Isolation decision:** Authorization models use separate metadata and are
  not registered on the existing V3 application `Base`. This prevents current
  startup `create_all` behavior from adding authorization tables to historical
  databases. The offline CLI accepts only an explicit fresh or compatible
  authorization-foundation database and rejects legacy audit targets.
- **Files created or modified:** `app/auth.py`, `app/generate_token.py`,
  `app/permissions.py`, `app/authorization_models.py`,
  `app/authorization_service.py`, `app/manage_grants.py`,
  `tests/test_authorization_foundation.py`, and this file.
- **Validation performed:** Compilation passed. Focused authorization and JWT
  tests passed: 23 tests in 2.61 seconds. The complete regression suite using
  a fresh external pytest temporary directory passed: 362 tests with one
  existing Starlette `TestClient` deprecation warning in 47.74 seconds.
- **Deferred components and limitations:** Existing HTTP endpoints still use
  legacy role-only dependencies; V4 grants are not yet applied to routes,
  queries, lifecycle operations, verification, exports, reports, idempotency,
  or hash chains. The isolated grant CLI is not an integrated V4 application
  database initializer. This transitional state must not be represented as
  complete tenant isolation. Grant-administration deployment trust and
  privileged database-administrator risk remain unresolved.
- **Final security review and conditional approval:** The engineer reviewed the
  Task 36A foundation. Review confirmed that V4 authentication rejects missing,
  blank, malformed, and incorrectly typed tenant claims without legacy
  fallback; common JWT validation remains intact; grants are tenant/subject/
  resource/permission-specific and live; inactive grants and memberships deny;
  admin/regulator roles do not bypass grants; and the isolated CLI rejects
  incompatible legacy targets before writes. The previously recorded focused
  and complete regression evidence remains valid. SEC-03 is not closed:
  existing HTTP routes remain legacy role-only until later V4 stages integrate
  and test every protected endpoint.

## Task 36B - V4 database models, tenant-specific chains and checkpoints

- **Engineer-approved scope:** Implement a fresh, explicit V4 database
  foundation only. V3 application startup, historical databases, existing
  hashes, and HTTP routes remain unchanged.
- **AI contribution:** Added isolated V4 ORM metadata, a strict fresh-or-
  complete V4 schema initializer, tenant-local event sequences and opaque UUID
  references, tenant-specific linked-chain and checkpoint primitives, and
  future lifecycle/idempotency persistence models. Updated the trusted grant
  CLI so its explicit target must be a complete V4 database rather than the
  former authorization-only foundation.
- **Integrity decisions:** V4 content hashes bind tenant ID and public event
  reference; V4 chain hashes bind tenant ID and local sequence. Append and
  checkpoint updates remain caller-transaction-owned. The V4 initializer
  rejects legacy and partial targets before it creates any tables; no tenant
  assignment, migration, or historical hash rewrite occurs.
- **Validation performed:** Focused V4 and existing authorization-foundation
  tests passed: 41 tests in 6.81 seconds. Python compilation and `pip check`
  passed. The complete regression suite using a fresh external disposable
  pytest directory passed: 382 tests with one existing Starlette `TestClient`
  deprecation warning in 43.68 seconds.
- **Final review and engineer approval:** Review confirmed that V4 preflight
  rejects nonempty incompatible targets before schema creation, raw persisted
  events and checkpoints are verified without ORM identity-map normalization,
  malformed evidence fails closed, and composite tenant-bound foreign keys
  prevent lifecycle/idempotency cross-tenant references. A stale-checkpoint
  finding was corrected by reading checkpoint evidence directly from persisted
  columns; its regression test passed. The engineer authorized finalization of
  this Task 36B scope.
- **Limitations:** No V4 HTTP routes, scoped event queries, lifecycle services,
  idempotency workflow, export/report integration, or complete tenant isolation
  is implemented yet. SQLite write serialization and privileged database-
  administrator limitations remain documented for later stages.

## Task 36C - Scoped V4 event creation, retrieval and idempotency

- **Engineer direction:** Keep V4 isolated during incremental rollout. The
  development-only `app.v4_main` mounts only V4 `/audit/events` routes and
  `/health`; it does not mount the legacy V3 application or present it as a
  tenant-secure service.
- **AI contribution:** Added tenant-aware V4 request/response schemas, an
  explicit V4 application/database session boundary, scoped creation and list
  routes, and tenant-scoped idempotency lookup. Create checks the verified V4
  tenant identity, active membership, writer role, and exact `CREATE_EVENT`
  grant inside the SQLite serialized write transaction. Reads constrain tenant
  and active `READ_EVENT` grant pairs in SQL before ordering and pagination.
- **Security decisions:** V4 responses expose opaque `eventRef`, never the
  internal database ID. Replays reauthorize before returning evidence; an
  identical request returns 200 and a first creation returns 201. Errors stay
  generic. Lifecycle, export, report, and legacy-route integration remain out
  of scope.
- **Final review and validation:** Added coverage for cross-resource filtering,
  cross-tenant key isolation, revocation, inactive membership, invalid keys,
  and absence of legacy V3 routes from the isolated application. Review found
  and corrected V4 idempotency-key validation so embedded whitespace is
  rejected consistently with the established API contract. Focused V4 route,
  foundation, and authorization tests passed: 49 tests with one existing
  TestClient deprecation warning in 9.15 seconds. The full regression suite
  passed: 390 tests with the same warning in 46.15 seconds. Engineer review
  and approval remain pending.

## Task 36D - Scoped V4 retention and redaction integrity

- **AI contribution:** Added isolated V4 redaction and retention operations,
  lifecycle action events and tenant-bound metadata, archive filtering before
  retrieval pagination, and lifecycle consistency checks in V4 verification.
  Ordinary retrieval hides internal lifecycle actions and archived records;
  redacted payloads are masked for reads and idempotent replay.
- **Review finding and correction:** Lifecycle tampering initially reached the
  mutation fallback as a sanitized 500. The V4 route now maps integrity
  failures to the fail-closed 409 contract. Internal lifecycle event types are
  rejected for ordinary creation.
- **Validation performed:** Focused V4 route/foundation/authorization tests
  passed: 52 tests with one existing TestClient deprecation warning in 10.57
  seconds. Full regression output was persisted outside pytest's disposable
  base directory: 393 tests passed with the same warning in 46.67 seconds;
  exit code 0.
- **Completion validation:** Added dedicated rollback/no-op, revoked-grant,
  structurally valid unexpected-metadata, cross-tenant foreign-key, and
  independent-session concurrent-redaction tests. The V4 route suite passed
  15 tests in 6.10 seconds. Final full regression output was persisted outside
  pytest's base directory: 397 tests passed with one existing TestClient
  deprecation warning in 47.46 seconds; exit code 0.
- **Limitations:** This remains an isolated V4 application. Full V4 endpoint
  integration, public verification/export/report services, and default-app
  cutover remain later-stage work.

## Task 36E - Scoped V4 verification, exports and reports

- **AI contribution:** Added isolated tenant verification and access reports,
  V4 export generation, a tenant-bound witness format, and a standalone V4
  bundle verifier dispatched by the existing CLI without changing legacy
  verification. Exports require explicit resource grants and tenant witness
  permission; reports constrain tenant/resource scope before filters and
  pagination.
- **Security correction:** Focused export tests found that an explicit resource
  selector without an active export grant could return an empty bundle. The
  V4 route now denies that selector. Witnesses exclude payloads, resource IDs,
  and internal IDs; selected records use redaction masking.
- **Validation:** Focused V4 route/export/verifier tests passed: 30 tests with
  one existing TestClient deprecation warning in 11.67 seconds. Persisted full
  regression output outside pytest's base directory recorded 412 passed tests,
  the same warning, and exit code 0 in 61.33 seconds.
- **Limitations:** V4 export verification establishes bundle consistency, not
  source authenticity or selection completeness. Redacted original content is
  intentionally not recomputable offline. Default-app V4 cutover remains a
  later stage.
- **Final verifier review:** Corrected three V4 verifier defects: witness
  entries now bind opaque event references to selected records; trusted
  expected-digest checks now reach V4 direct and CLI verification; and trusted
  public-key validation checks the declared signature key ID. Affected V4
  route/export/verifier and legacy export tests passed: 46 tests with one
  existing warning in 9.46 seconds. Final persisted regression recorded 412
  passed tests, the same warning, and exit code 0 in 54.99 seconds.

## Task 36F - Secure V4 application integration and cutover

- **AI contribution:** Replaced the supported `app.main:app` entry point with a
  clean V4-only import, retained the committed V3 application in
  `tests/legacy_app.py` solely for historical regression coverage, and removed
  the production `app.legacy_main` module. The remaining historical database
  initializer tests were corrected to import the test-local fixture rather than
  the V4 entry point.
- **Operational correction:** The V4 operational middleware accepts only a
  bounded safe caller-provided request ID and generates a new ID for missing or
  malformed values. It returns the request ID on normal and sanitized error
  responses. V4 startup requires an explicit nonblank `AUDIT_V4_DB_PATH` and
  does not fall back to `AUDIT_DB_PATH`.
- **Deployment and CI contribution:** Updated Docker/Compose to use the
  separate non-root-owned `/var/lib/audit-v4/audit_log_v4.db` location and
  `audit-v4-data` volume. Updated CI configuration and its smoke script for
  tenant-aware tokens, trusted offline grant provisioning, V4 opaque event
  references, scoped verification, denial checks, persistence recreation, and
  masked ephemeral credentials.
- **Validation performed:** Focused default-entry-point integration tests
  passed: 6 tests with one existing TestClient deprecation warning. The complete
  persisted regression passed: 428 tests with the same warning and exit code 0.
  `compileall`, `pip check`, and `git diff --check` passed; the historical
  `audit_log.db` checksum remained unchanged. Static Compose/workflow checks and
  Git Bash shell syntax passed.
- **Limitations:** Docker CLI, actionlint, and ShellCheck were unavailable in
  the local environment. Docker build, Compose runtime, and smoke execution are
  therefore pending a Docker-capable runner. This entry records implementation
  and validation only; no engineer approval or commit is claimed here. During
  documentation command-consistency review, the V4 retention route's unset
  fallback was observed as 30 days while the shared validation helper and
  Compose default are 90 days. No code change was authorized in this
  documentation task; current instructions therefore require explicitly setting
  `AUDIT_RETENTION_DAYS` rather than claiming one runtime default.

### Task 36F.3D - retention configuration consistency correction

- **Correction:** Replaced the V4 route's independent `30`-day environment
  fallback with the existing shared `configured_retention_days()` function.
  Startup validation and every V4 retention execution now use the same bounded
  policy and documented 90-day default.
- **Regression coverage:** Added V4 route tests showing that a 45-day event is
  retained while a 100-day event is archived under an unset configuration, and
  that an explicit 30-day policy archives a 45-day event. Existing operational
  startup coverage continues to assert invalid retention configuration fails
  closed. Focused V4 route, operational, and retention-service validation
  passed: 43 tests with one existing TestClient deprecation warning.

### Task 36F.4 - final V4 integration validation

- **Automated validation:** The complete suite ran with an external disposable
  pytest base directory and persisted output: 430 tests passed with one existing
  TestClient deprecation warning and exit code 0. Coverage reports were produced
  by the configured test run: 87.39% line coverage and 79.24% branch coverage.
  The run also checked the default V4 entry point,
  historical V3 test fixture isolation, retention-policy correction, and V4
  authorization/integrity coverage.
- **Live-validation limitation:** A fresh external V4 database, temporary
  Ed25519 keys, and ephemeral JWT configuration started `app.main:app` under
  Uvicorn successfully; root operational startup reached readiness. The
  disposable Windows PowerShell/curl harness then serialized JSON request bodies
  incorrectly, yielding FastAPI's expected malformed-JSON 422 before the
  authentication path. No application defect was established and the planned
  authenticated live request matrix was not claimed complete. Docker runtime
  validation also remains unavailable locally.
- **Completed HTTP correction:** The incomplete PowerShell/curl attempt was
  replaced by a disposable Python/httpx validator using native JSON request
  serialization, explicit timeouts, subprocess-managed Uvicorn/CLI commands,
  and cleanup. Its sanitized external report recorded 22 passing operations:
  operational endpoints/OpenAPI, missing and legacy-token 401 responses,
  creation, idempotent replay/conflict, scoped retrieval, cross-tenant and
  cross-resource isolation, verification, retention, redaction and masked
  retrieval, signed export, trusted offline verification, compliance reporting,
  and revoked-grant denial. Temporary database, keys, tokens, bundle, server,
  and validator artifacts were kept outside the repository and cleanup was
  requested after shutdown. This is local Uvicorn evidence only; Docker runtime
  validation remains unavailable.

## Task 37B.1 - Bidirectional V4 lifecycle integrity verification

- **Engineer request and AI contribution:** Implemented the focused follow-up
  to the Task 37A read-only review. The V4 lifecycle verifier now reads raw
  persisted action and metadata evidence and requires an exact one-to-one match
  in both directions. A chained archive or redaction action without its
  corresponding metadata is now an integrity failure, as is unexpected,
  duplicate, or mismatched metadata.
- **Defect and correction:** The first implementation exposed a transaction
  ordering issue for multi-path redaction and multi-target retention: a flushed
  lifecycle action could be observed before its newly added metadata during the
  next append's integrity check. The lifecycle services now flush each metadata
  row inside the caller-owned transaction before proceeding to another action.
  No commit or rollback ownership moved into the services.
- **Regression coverage and validation:** Added direct-SQL tampering coverage
  for deleted redaction metadata, partial deletion from multi-path redaction,
  and partial deletion from multi-target archival. The tests assert fail-closed
  retrieval, idempotent replay, mutation, export, and access-report behavior;
  a non-intact verification response; unchanged evidence after denied writes;
  and no return of the redacted sensitive value. Focused V4 route and
  foundation suites passed: 44 tests with one existing TestClient deprecation
  warning in 21.43 seconds.
- **Limitations:** This focused task did not run the complete regression suite,
  change actor-based export selection, or address the separately identified
  authorization read-snapshot race coverage gap. Same-database privileged
  attackers remain within the documented trust boundary.

## Task 37B.2 - Actor export authorization correction

- **Engineer request and AI contribution:** Corrected the Task 37A actor-export
  existence oracle. V4 export generation now applies the caller's exact active
  `EXPORT_RESOURCE` scope before actor matching. Actor-selected exports return
  only authorized records, or an empty valid bundle when no authorized match
  exists; an explicitly requested ungranted `resourceId` remains a generic
  403 denial.
- **Consistency decision:** The export route now begins a SQLite deferred read
  transaction before membership, witness permission, resource-grant, integrity,
  selection, witness, and checkpoint reads. It releases that read-only snapshot
  with rollback after constructing the bundle and rolls back on all failures.
- **Regression coverage and validation:** Added mixed authorized/ungranted
  actor records, hidden-only actor, nonexistent actor, and revoked-grant
  assertions. The tests prove hidden-only and nonexistent actors both return
  HTTP 200 with empty records, while mixed actors receive only authorized
  records and explicit ungranted resources remain 403. Focused V4 route and
  offline export-verification suites passed with coverage disabled: 36 tests,
  one existing TestClient deprecation warning, in 12.41 seconds.
- **Limitations:** A tenant-witness permission still intentionally discloses
  tenant-chain witness metadata permitted by the authorization design; it never
  includes payloads or resource identifiers. This task did not run the complete
  regression suite or change the separate lifecycle-integrity correction.

## Task 37B.3 - Remaining targeted adversarial authorization tests

- **Engineer request and AI contribution:** Added focused V4 adversarial route
  coverage for known ungranted, cross-tenant, and nonexistent opaque redaction
  references; inactive memberships; revoked lifecycle permissions; and
  cross-resource idempotency-key requests. The three redaction denial cases
  return the same 404 response and leave event, lifecycle metadata, and
  checkpoint evidence unchanged. A request that reuses a key on an ungranted
  resource is denied before idempotency lookup with the generic 403 response.
- **Consistency correction:** Extended the explicit SQLite deferred read
  snapshot boundary used by export to event retrieval and compliance reporting.
  Each route now releases its read-only transaction after materializing its
  response and rolls it back on denial or error.
- **Concurrent validation:** Added independent-session, bounded concurrent
  grant-revocation coverage for retrieval, export, and access reporting. Each
  in-flight request observes one consistent authorized snapshot; the revocation
  completes after that response and the following request returns no evidence.
  This establishes the intended SQLite serialization behavior without granting
  a revoked principal access in a later request.
- **Validation:** Focused V4 route and offline export-verification suites ran
  with coverage disabled: 43 tests passed with one existing TestClient
  deprecation warning in 13.52 seconds. No complete regression suite ran.
- **Limitations:** The snapshot guarantee is implemented and tested for the
  current SQLite deployment. Other database backends require an explicit
  isolation-level review. This task did not alter the documented trusted
  database-administrator boundary or run the full suite.

## Task 37C - Full Adversarial Security Regression

Date: 2026-11-27

### Objective

Validate the combined Task 37B.1, 37B.2 and 37B.3
security corrections against the complete regression suite.

### AI Assistance and Developer Ownership

Codex implemented the targeted security corrections and
focused regression tests during Tasks 37B.1 through 37B.3.

Codex reached its usage limit after reporting 43 passing
focused tests for Task 37B.3.

ChatGPT assisted with reviewing the reported results,
preparing manual validation commands and interpreting
coverage measurements.

The developer manually executed the full regression
and repository validation commands using Git Bash
on the local Windows development environment.

### Validation Results

- Baseline commit: 4f823de
- Python version: 3.12.7
- Full regression: 441 passed, 0 failed
- Existing TestClient deprecation warning: 1
- Pytest exit code: 0
- Execution duration: 81.86 seconds
- Line coverage: 1920/2133 (90.01%)
- Branch coverage: 534/678 (78.76%)
- Combined coverage: 87.30%
- Previous full regression: 430 passing tests
- Additional passing tests: 11

### Generated Evidence

- .coverage-reports/task37c-regression.log
- .coverage-reports/task37c-regression.exitcode
- .coverage-reports/coverage.json
- .coverage-reports/coverage.xml
- .coverage-reports/html/index.html

### Limitations and Remaining Work

The complete regression passed with the combined
security changes.

Coverage threshold enforcement, critical-module
coverage assessment, CI artifact publication and
independent security review remain pending.

The regression results do not establish the absence
of all possible security vulnerabilities.

No external evaluation acceptance is claimed.
