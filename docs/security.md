# Security and Threat Model

## Security objectives

The prototype aims to make ordinary audit-evidence tampering detectable,
minimize sensitive payload exposure in API projections, enforce endpoint roles,
provide safe errors/logs, and optionally sign export bundles. It does not claim
tamper-proof storage, complete confidentiality, production readiness, or
regulatory certification.

## Assets and trust boundaries

| Asset | Implemented protection | Residual boundary |
| --- | --- | --- |
| Audit events/checkpoint | Content hashes, linked chain, verification | Privileged same-database rewrite remains possible. |
| Lifecycle metadata | Foreign keys, action/metadata verification, atomic writes | Metadata shares database trust boundary. |
| Idempotency mapping | Subject/key uniqueness and transaction atomicity | Mapping is not an external proof. |
| JWT key | Environment configuration, minimum length validation | No rotation, revocation, IdP, or secret manager. |
| Export private key | External path, ignored files, optional read-only mount | Host/key custody remains trusted. |
| Trusted public key | Explicit offline verifier input | Public-key distribution is external. |
| API payload view | Redaction overlay and fail-closed integrity checks | Originals remain stored and backed up. |

## Authentication and authorization

`app/auth.py` accepts only configured HS256 tokens with valid `exp`, `sub`,
`iss`, `aud`, and unique roles selected from writer, auditor, regulator, and
admin. The exact endpoint matrix is in [api-reference.md](api-reference.md).
The JWT subject identifies the caller. `actorId` is a business assertion from a
trusted writer, not proof that the subject is that business actor.

Missing, malformed, expired, wrongly signed, wrong issuer/audience, or invalid
role tokens return 401. An authenticated caller without route permission gets
403. Local development-token generation has no HTTP token-issuance endpoint.

## Threat matrix

| Threat/failure | Implemented mitigation or detection | Test evidence | Residual risk |
| --- | --- | --- | --- |
| Unauthorized/expired JWT | Required claims and HS256 decode | auth/route token tests | Shared-secret custody. |
| Wrong endpoint role | `require_roles()` dependencies | RBAC test | No external role governance. |
| Event content change | Recomputed canonical hash | content tampering tests | Coordinated rewrite. |
| Intermediate deletion | Broken predecessor/chain link | deletion tests | Detected only when verified. |
| Tail/all deletion | Checkpoint count/head checks | checkpoint/deletion tests | Checkpoint can be rewritten. |
| Lifecycle metadata corruption | Cross-check action evidence and fail closed | retention/redaction tamper tests | Same database trust. |
| Sensitive payload exposure | Redaction overlays and full verification before retrieval/export | fail-closed retrieval tests | Original/backups retain data. |
| Export modification | Bundle digest/witness/checkpoint verifier | verifier tampering tests | Unsigned exports lack signer proof. |
| Wrong key/downgrade | Trusted-key Ed25519 verification requires a valid signature | signing tests | Trusted key distribution. |
| Duplicate retry | Fingerprint + unique mapping + SQLite lock | idempotency/concurrency tests | No distributed coordinator. |
| Database outage | Sanitized 500/503 readiness outcomes | readiness/route tests | No HA/failover. |
| Secret/payload logging | Safe middleware fields and static errors | logging tests | No monitoring backend evidence. |
| Dependency vulnerabilities | Strict `pip-audit` CI/local gate | Task 30/31 records | Advisory data changes over time. |

## Cryptographic trust

Content hashes are SHA-256 of canonical UTF-8 JSON. Linked-chain hashes include
the content hash, domain, scheme version, and predecessor chain digest. The
checkpoint strengthens trailing-deletion detection but remains in the same
database. Digest verification proves bundle internal consistency; an expected
digest proves equality to separately retained data; Ed25519 verification proves
the configured trusted key signed the bundle digest. Neither proves source
completeness or prevents a privileged coordinated database rewrite.

## Data protection and operations

Redaction is a non-destructive response/export mask, not erasure. Logical
archival retains evidence. Middleware supplies a request ID and avoids logging
tokens, payloads, account identifiers, SQL, or exception text. The container
runs as non-root; CI generates/masks disposable values; optional signing keys
are supplied outside the image.

## Residual risks and future hardening

Not implemented: external integrity anchoring, physical append-only storage,
distributed coordination, JWT rotation/revocation/IdP integration, managed key
service, rate limiting, monitoring backend, comprehensive performance testing,
migrations, HA deployment, or regulatory certification. These are limitations,
not implied capabilities.
