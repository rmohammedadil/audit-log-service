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

Task 51 validated application revision
`3b0eb5d6601e3c74f938ad8afedabf4f99140c2b`: 475 tests passed in 85.09
seconds, exit code 0, with one existing TestClient deprecation warning. It
measured 90.14% line coverage and 79.12% branch coverage; all configured
coverage gates passed. A separate disposable live HTTP run passed 25 checks.
`compileall`, `pip check`, and `git diff --check` passed.

The attested application revision is
`78a19710a9bcd21b9fa5624ea93b83a8bf79116f`; the application, test, dependency,
and CI inputs are byte-identical to the Task 51 revision (`git diff --stat
3b0eb5d..78a1971 -- app/ scripts/ requirements.txt pytest.ini .coveragerc
.github/` is empty). The suite was re-run at `78a1971` on 27 November 2026 with
the same result. The final submission revision is the documentation-only tag
`submission-final`.

Remote CI run
[45934437700](https://github.com/rmohammedadil/audit-log-service/actions/runs/45934437700)
is green: regression (475 tests plus the coverage gate), dependency
vulnerability scan (`pip-audit --strict`), and Docker runtime smoke test all
passed, and the regression-evidence artifact was published.

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
- Docker and CI validation is evidenced by the green run 45934437700 cited
  above; Docker was not replayed on the author's local machine.

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
