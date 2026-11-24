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
