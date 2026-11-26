# Engineering Summary — Audit Log Service

## Executive summary

Audit Log Service is a Python/FastAPI functional prototype built for an audit
logging assessment. The supported runtime is a tenant-scoped V4 FastAPI
application: it records structured events, detects ordinary direct tampering,
supports lifecycle retention/redaction, produces independently verifiable
export bundles, reports explicitly recorded account access, and protects audit
endpoints with tenant-aware JWTs and explicit grants. It is not presented as
production-ready, tamper-proof, or regulatory-certified.

## Problem and implemented scope

Scenario A provides append-only API behavior, deterministic content and linked
chain hashes, checkpoint-backed verification, query/filter/pagination, and
idempotent creation. Scenario B adds logical archival, non-destructive JSON
Pointer masking, lifecycle integrity checks, canonical export bundles, and
optional Ed25519 export signatures. Scenario C reports only explicit canonical
client-account access events for regulators. Operational work adds JWT/RBAC,
safe logging/request IDs, readiness, SQLite write coordination, Docker, CI,
and dependency scanning.

## Key engineering decisions

| Decision | Reason and result |
| --- | --- |
| Canonical SHA-256 content hash | Stable event-content evidence independent of JSON formatting/dictionary insertion order. |
| Linked chain plus checkpoint | Detects changed predecessor evidence and tail deletion; checkpoint records expected count/head. |
| SQLite and modular monolith | Simple, inspectable prototype with isolated tests; intentionally limited to a single-node model. |
| Logical archival/redaction overlays | Preserve original evidence while hiding selected values in projections. |
| Tenant JWT plus grants | Requires verified tenant identity, active membership, and exact resource/tenant grants without treating business actorId as caller identity. |
| Idempotency mapping | Writer-scoped retry safety with event/checkpoint mapping committed atomically. |
| Bundle digest plus optional Ed25519 | Offline consistency verification and optional trusted-key signer assurance. |

## Integrity and lifecycle design

Events store event content, UTC time, predecessor content hash, scheme version,
predecessor chain hash, and chain hash. `AuditChainState` stores expected count
and head. Verification reads persisted scalar values in ascending ID order,
recomputes evidence, validates checkpoint/lifecycle metadata, and reports the
first deterministic violation. Retention/redaction create ordinary chained
lifecycle action events and matching metadata in the same transaction. Reads,
reports, exports, and idempotent replay fail closed when evidence cannot be
trusted.

## Exports, reporting, and security

Exports contain selected redacted records, metadata, a payload-free full-chain
witness, checkpoint, and canonical digest. The offline verifier can check
internal consistency, a separately retained digest, and optional Ed25519
signature with an independently trusted public key. Reports contain only
recorded `CLIENT_ACCOUNT_ACCESS` evidence; they do not prove all real-world
accesses were logged. JWT roles are writer, auditor, regulator, and admin.

## Validation and evidence

The latest recorded cutover regression is 428 passing tests with one existing
TestClient deprecation warning. Earlier 24 selected Task 31 acceptance tests
were a subset of the then-current suite, not an additional count. Recorded
checks include
`compileall`, `pip check`, and strict local `pip-audit` with no known
vulnerabilities. The developer confirmed a successful post-remediation GitHub
Actions run; Task 31 could not independently retrieve its run ID or job logs.

## AI-assisted development and human oversight

AI assisted with implementation proposals, code, test design, documentation,
and validation commands. The engineer approved scoped tasks, reviewed code,
performed/confirmed manual validation, controlled commit authorization, and
retained responsibility for the result. The historical record is in
[docs/ai-usage-log.md](docs/ai-usage-log.md).

## Known limitations

- Events, checkpoint, lifecycle metadata, and idempotency mappings share one
  database; a privileged coordinated rewrite can evade detection.
- No external integrity anchor, WORM storage, migration framework, distributed
  coordination, HA deployment, or load-test evidence exists.
- Redaction masks response/export views; originals remain in storage/backups.
- JWT rotation/revocation, external IdP, managed keys, rate limiting,
  monitoring backend, and regulatory certification are not implemented.
- Docker/CI success is developer-confirmed; detailed remote job logs were not
  independently accessible in the recorded final review.

## Repository navigation

| Document | Purpose |
| --- | --- |
| [README.md](README.md) | Setup and operational entry point |
| [docs/architecture.md](docs/architecture.md) | Current high-level architecture |
| [docs/system-design.md](docs/system-design.md) | Low-level algorithms, schema, and transactions |
| [docs/scenarios/](docs/scenarios/) | Scenario A/B/C traceability |
| [docs/api-reference.md](docs/api-reference.md) | Public API contract |
| [docs/security.md](docs/security.md) | Security objectives and residual risks |
| [docs/testing.md](docs/testing.md) | Evidence and test traceability |
| [docs/walkthrough.md](docs/walkthrough.md) | Assessment demonstration guide |
| [docs/examples/](docs/examples/) | Focused safe examples |
