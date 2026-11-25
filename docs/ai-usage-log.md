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
