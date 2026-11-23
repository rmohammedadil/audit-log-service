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
- **Engineer review and approval of this implementation:** Pending.
