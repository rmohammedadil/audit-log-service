# Resource-Level Authorization Design

## Status and scope

This Task 35 architecture was the approved design for V4. Task 36F has made
the supported `app.main:app` entry point tenant-scoped: it requires a tenant
claim, active membership, and exact grants for all seven supported operations.
The earlier planning language below is retained as historical design evidence.
This does not claim that privileged database administration, deployment trust,
or external identity governance are solved.

The proposal retains SQLite for the prototype, uses a fresh V4 database, and
does not alter existing database files, historical event hashes, or chain
evidence.

## Approved implementation constraints

- Tokens without valid tenant claims have no backward-compatible authentication
  bypass.
- No implicit wildcard grant or automatic global resource access is permitted.
- Existing integrity assertions must not be weakened or deleted merely to make
  authorization implementation pass.
- Tenant isolation must not be represented as complete until every protected
  endpoint is integrated and tested.
- Production deployment trust, identity-provider integration, external
  anchoring, and privileged database-administrator limitations remain unresolved
  and must stay documented during implementation.

## Security objectives

- Deny access unless a verified identity has an active, explicit permission.
- Keep authenticated identity distinct from the business `actorId` recorded in
  an event.
- Prevent cross-tenant and same-tenant cross-resource disclosure, including
  disclosure through identifiers, list length, pagination, chain witnesses,
  checkpoints, and integrity errors.
- Preserve deterministic, independently verifiable audit evidence within an
  authorized tenant scope.
- Never infer ownership from caller-supplied event, account, actor, or resource
  fields.

## Recommended hybrid authorization model

JWT validation establishes identity and one active tenant context. Server-side
grants are authoritative for authorization and revocation. A token is not a
portable list of long-lived resource permissions.

Example required claims:

```json
{
  "sub": "user:advisor-17",
  "tenant_id": "tenant-acme",
  "roles": ["writer"],
  "iss": "trusted-issuer",
  "aud": "audit-api",
  "exp": 1790000000
}
```

`tenant_id` must be a nonblank, canonical identifier. One request operates in
one tenant context. Multi-tenant users receive a separately issued token for
each active tenant rather than a caller-selected tenant header.

The authorization dependency constructs an immutable principal:

```text
AuthorizedPrincipal(
  subject,
  tenant_id,
  roles,
  tenant_membership_active,
  resource_permissions,
  tenant_permissions,
)
```

The service loads active grants for the verified `(tenant_id, subject)` pair
from the database. An optional JWT `scope_version` can help diagnose stale
clients, but live server-side grant checks remain authoritative and therefore
do not depend on it for revocation.

### Grant model

Use separate, explicit grant categories:

```text
tenant_principals(
  tenant_id, subject, active, unique(tenant_id, subject)
)

resource_grants(
  tenant_id, subject, resource_type, resource_id, permission, active,
  unique(tenant_id, subject, resource_type, resource_id, permission)
)

tenant_permission_grants(
  tenant_id, subject, permission, active,
  unique(tenant_id, subject, permission)
)
```

Illustrative resource permissions are `CREATE_EVENT`, `READ_EVENT`,
`REDACT_EVENT`, `EXPORT_RESOURCE`, and `READ_ACCESS_REPORT`. Tenant-wide
permissions are intentionally distinct: `VERIFY_TENANT_CHAIN`,
`EXPORT_TENANT_WITNESS`, and `RUN_RETENTION`.

Roles remain coarse capability gates, not ownership grants. Neither `admin`
nor `regulator` implies tenant-wide or global access.

### Grant provisioning and revocation

No public grant-management API is proposed. A trusted offline administrative
CLI provisions, disables, and revokes grants. It must use controlled operator
credentials and environment/configuration outside application users' control.
The CLI must not accept a caller-provided subject or tenant without validating
the administrator's authority through its deployment boundary.

Grant validation occurs in the same database transaction as protected writes.
SQLite `BEGIN IMMEDIATE` serializes grant changes with event, redaction, and
retention mutations. Reads authorize before returning data; a read already
authorized in its transaction may finish during a concurrent revocation, but
subsequent requests see the revoked grant. A privileged database administrator
can still alter grants and evidence; this remains outside the same-database
trust boundary.

## V4 tenant-scoped evidence model

### Events and ordering

V4 uses a fresh schema. It does not add tenant ownership to current records.
Each new event has:

```text
internal_id          internal SQLite surrogate key, never public
event_ref            opaque public UUID/reference, unique
tenant_id            immutable tenant owner
tenant_sequence      positive, tenant-local deterministic sequence
event_type, actor_id, resource_type, resource_id, payload, timestamp
previous_hash, content_hash, previous_chain_hash, chain_hash, scheme_version
```

`tenant_sequence` is unique with `tenant_id` and is allocated while holding
the tenant write transaction. API paths and responses use `event_ref`, not a
globally sequential database ID. Tenant-wide verifiers and authorized export
witnesses may expose the tenant-local sequence because they already have
tenant-wide metadata permission.

V4 canonical event content includes `tenantId` in addition to the existing
business event fields and normalized UTC timestamp. The chain-link canonical
form includes `tenantId` and `tenantSequence`, alongside the scheme version,
content hash, and predecessor chain hash. This makes ownership and position
tamper-evident.

Each tenant has one checkpoint:

```text
tenant_chain_state(
  tenant_id primary key,
  scheme_version,
  event_count,
  head_sequence,
  head_chain_hash
)
```

Tenant-specific genesis material is domain separated and bound to `tenantId`.
Verification reads records in ascending `tenant_sequence` order and compares
the tenant checkpoint. It does not depend on internal SQLite IDs.

### Lifecycle and idempotency data

Archive/redaction metadata and their lifecycle action events must share the
target event's tenant. Verification checks this relationship as well as
existing action/metadata consistency. Retention runs create tenant-local
lifecycle actions only.

Idempotency is unique on `(tenant_id, writer_subject, idempotency_key)`. The
mapped event must belong to the same tenant and still pass current integrity,
redaction, and authorization checks before a replay response is returned.

### Legacy compatibility

V4 startup preflight accepts only a fresh or complete V4 schema. It rejects
legacy, partial, and mixed audit schemas before schema creation can mutate
them. Legacy records have no established tenant owner and therefore fail
closed for tenant-scoped operations. No automatic tenant assignment, hash
rewriting, checkpoint rebuilding, or migration is permitted.

## Same-tenant metadata isolation and exports

Tenant-specific chains remove cross-tenant witness leakage, but resource-level
permission alone must not expose another account's metadata in the same
tenant.

The existing independently verifiable export format requires the complete
ordered chain witness and checkpoint. Therefore a resource-scoped caller must
have both:

1. `EXPORT_RESOURCE` for every selected resource; and
2. `EXPORT_TENANT_WITNESS` for the complete tenant witness.

Without tenant-wide witness permission, deny the independently verifiable
export. Do not silently return a restricted bundle while claiming equivalent
chain verification or source authenticity. A separate restricted export format
would require distinct product requirements and verifier semantics.

Ordinary resource-scoped reads perform full tenant-chain verification internally
after scope authorization. On integrity failure they return a generic safe
conflict response, never record IDs, counts, checkpoint values, or failure
diagnostics outside the caller's authorized resource scope.

## Endpoint authorization contract

| Operation | Required permissions | Non-disclosing behavior |
|---|---|---|
| Create event | role `writer`; active tenant membership; `CREATE_EVENT` for the resource | Missing/malformed tenant claim: 401. Inactive membership/grant: generic 403. |
| Idempotent replay | Same checks as create before mapping lookup | Revoked permission denies replay; no mapped-event disclosure. |
| List events | read-capable role; `READ_EVENT` grants | Broad queries return only granted resources. Explicit ungranted resources return an empty list. |
| Redact event | role `admin`; `REDACT_EVENT` for target resource | Lookup is tenant-scoped by opaque `event_ref`; absent/ungranted target returns the same 404 response. |
| Retention | role `admin`; `RUN_RETENTION` tenant permission | Executes only one tenant policy; result avoids resource IDs unless tenant-wide permission permits them. |
| Verify tenant chain | permitted role; `VERIFY_TENANT_CHAIN` | No global verification endpoint for ordinary tenants. Unauthorized caller receives generic 403. |
| Export | auditor/admin role; resource export grant plus `EXPORT_TENANT_WITNESS` | An explicit ungranted resource is denied. Actor-selected exports are intersected with authorized resource scope first, so hidden-only and nonexistent actors both return an empty valid export; no cross-resource records, resource identifiers, or payloads are disclosed. |
| Access reports | role `regulator`; `READ_ACCESS_REPORT` per account | Broad reports are intersected with grants; cross-tenant/ungranted account filters produce an empty list. |

All protected operations first validate JWT signature, issuer, audience,
expiration, subject, roles, and tenant claim. Valid tokens with invalid or
inactive membership/grants are authorization failures. Resource-specific
denials do not distinguish nonexistent, cross-tenant, or same-tenant
unauthorized identifiers.

## Global versus tenant-specific chains

| Design | Benefit | Security consequence |
|---|---|---|
| Retained global chain | One total system order | Full witness/checkpoint export leaks other tenants' event ordering and counts. |
| Tenant-specific V4 chains | Scoped verification, export witnesses, checkpoints, and sequence values | No global ordering; requires fresh V4 evidence and tenant-local lifecycle/checkpoint handling. |

Tenant-specific chains are recommended because independent verification must
not require revealing other tenants' metadata. Platform-wide integrity
operations, if ever required, need a separately approved privileged system
boundary and must not be inherited from ordinary admin/regulator roles.

## Implementation decomposition

| Stage | Scope and dependency | Expected files | Acceptance criteria and focused tests |
|---|---|---|---|
| 36A | Authorization foundation and grants; no scoped event behavior is advertised yet | `auth.py`, new policy/grant module, models, database, grant CLI, auth tests | Missing/malformed tenant claims, inactive membership, uniqueness, grant revocation, and deny-by-default tests pass. |
| 36B | Fresh V4 tenant model and chains; depends on 36A scope vocabulary | models, database preflight, audit service, hashing/verification tests | Tenant hash vectors, local ordering, checkpoints, no global-ID exposure, and legacy rejection pass. |
| 36C | Scoped creation, retrieval, and idempotency; depends on 36A/36B | schemas, routes, audit service, API tests | Cross-tenant, same-tenant-ungranted, broad query, collision, replay-after-revocation, and valid-scope tests pass. |
| 36D | Scoped redaction and retention; depends on 36B lifecycle structures | redaction/retention services, routes, lifecycle tests | Target/action tenant equality, unauthorized guessed reference, retention isolation, rollback, and lifecycle verification pass. |
| 36E | Scoped verification, export, and reports; depends on all earlier stages | export service/verifier, routes, report tests | Witness-permission denial, tenant-only witness, generic integrity failures, scoped reports, and offline verification pass. |
| 36F | Integrated V4 validation; depends on 36A–36E | test fixtures, documentation, CI coverage configuration | Complete regression, migration/legacy protection, concurrency/revocation, coverage, and security scans pass. |
| 37 | Adversarial authorization testing after complete integration | focused adversarial tests and documentation | Matrix below passes without weakening chain/lifecycle regressions. |

Partial stages must not be represented as a secure multi-tenant implementation.
Before V4 scoped routes are complete, existing role-only behavior remains a
known security limitation.

## Task 36B implementation status

Task 36B implements only the isolated V4 persistence foundation.  It adds a
fresh explicit V4 initializer, tenant-local immutable event references and
sequences, tenant checkpoints, canonical tenant-bound content hashes, linked
tenant chain hashes, and persistence structures for future lifecycle and
idempotency behavior.  The initializer accepts a fresh target or a complete
matching V4 schema; it rejects legacy and partial targets before schema
creation.  The offline grant CLI now uses that initializer, so it cannot add
grant tables to an existing V3 audit database.

V3 application startup remains unchanged and never imports the V4 initializer.
There are still no V4 HTTP routes, response schemas, lifecycle services, or
tenant-scoped API authorization decisions.  Consequently, this foundation is
not complete tenant isolation and does not close the role-only legacy-route
limitation.

### V4 canonical evidence

The explicit V4 scheme version is `audit-tenant-chain-v1`. Content canonical
JSON uses sorted keys, compact separators, UTF-8, JSON-object payloads only,
and UTC timestamps rendered to microseconds with a `Z` suffix. It hashes these
fields exactly: `tenantId`, `eventRef`, `eventType`, `actorId`,
`resourceType`, `resourceId`, `payload`, and `timestamp`. The content genesis
is SHA-256 of the UTF-8 literal `audit-tenant-content-genesis-v1`.

Each tenant has a separate SHA-256 chain genesis over canonical JSON containing
the domain `audit-tenant-chain-hash`, scheme version, tenant ID, and
`genesis: true`. Each subsequent chain hash canonically binds that domain,
scheme version, tenant ID, tenant-local sequence, content hash, and previous
chain hash. A per-tenant checkpoint stores scheme version, count, head
sequence, and head chain hash. Appending validates the applicable tenant chain
and updates its event/checkpoint within the caller-owned transaction; it never
commits or repairs inconsistent evidence.

## Adversarial test matrix

- Same-role, cross-tenant create/read/export/report/redact/retention/verify.
- Same-tenant user without the account or resource permission.
- Broad requests, guessed opaque event references, and colliding resource IDs.
- Missing, malformed, duplicate, expired, or mismatched tenant claims.
- Revocation before idempotent replay and concurrent revoke/write behavior.
- Unauthorized witness, checkpoint, count, pagination, and integrity-detail
  access.
- Valid resource-scoped and tenant-wide operations.
- Existing content-hash, linked-chain, checkpoint, archival, redaction, export,
  report, and offline-verifier regressions.

## Remaining risks and decisions

- The trusted grant-administration boundary and operator authentication model
  need an explicit deployment decision.
- SQLite remains suitable only for the prototype's write-serialization limits.
- A privileged database administrator can still alter grants and same-database
  evidence; external anchoring is not introduced here.
- A future restricted export format requires separate requirements and must not
  reuse independent-verification claims.
- JWT key-management, identity-provider integration, grant auditing, and
  production migration tooling remain future work.
