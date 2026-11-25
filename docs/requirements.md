
# Audit Log Service — Requirements Analysis

## 1. Objective

Build a tamper-evident audit log service that records an append-only
history of events and detects modification or deletion of past records.

The implementation will be developed with AI assistance. The engineer
remains responsible for design, implementation, testing, and validation.

## 2. Scenario A — Core Audit Log Service

### 2.1 Write API

The service must accept an audit event containing:

- `eventType`: what happened
- `actorId`: who or what caused the event
- `resourceType`: type of affected resource
- `resourceId`: specific affected resource
- `payload`: structured event-specific details
- `timestamp`: when the event occurred

Requirements:

- Records must be append-only.
- The API must not expose an update operation.
- The API must not expose a delete operation.
- Timestamp behavior must be documented.

### 2.2 Query API

The service must retrieve events using any combination of:

- `actorId`
- `resourceType`
- `resourceId`
- `eventType`
- Time range (`from` and `to`)

The query API must support pagination.

### 2.3 Hash Chain

Each stored record must contain:

- A hash of its own event content.
- A hash of the immediately preceding record.
- A defined genesis value for the first record.

The hash chain must make modification of earlier records detectable.

### 2.4 Chain Verification

The service must expose:

`GET /audit/verify`

The endpoint must:

- Verify the full chain.
- Report whether the chain is intact.
- Identify the first inconsistent record when verification fails.
- Report the type of violation detected.

### 2.5 Required Validation

Validation must demonstrate:

1. Write audit events.
2. Query the written events.
3. Verify the chain successfully.
4. Modify a record directly in the data store.
5. Verify the chain again and detect the modification.
6. Delete a record directly in the data store.
7. Verify the chain again and detect the inconsistency.

## 3. Initial Design Decisions

These are proposed decisions and must be validated during implementation.

| Area | Proposed decision | Reason |
|---|---|---|
| Timestamp | Server-assigned UTC timestamp | Consistent ordering and avoids trusting client clocks |
| Hash algorithm | SHA-256 | Standard cryptographic hash with broad support |
| Serialization | Canonical JSON | Stable representation before hashing |
| Genesis value | Documented fixed genesis value | Defines the first record's predecessor |
| Database | SQLite for the local prototype | Simple setup and reproducible testing |
| API framework | FastAPI | Provides validation and API documentation |
| Pagination | Limit and offset initially | Simple and suitable for prototype scope |

## 4. Scope Boundary

Scenario A is the first implementation milestone.

Scenario B will address retention, structured redaction, and bulk export.

Scenario C will address compliance reporting and requirement ambiguity.

These scenarios will be documented and validated separately.

## 5. Open Engineering Questions

- How should records be ordered when timestamps are equal?
- What exact fields are included in the record hash?
- How will verification identify modification versus deletion?
- How will archived records remain verifiable?
- How can redaction preserve integrity evidence?
- What metadata must a bulk export contain for independent verification?
- What assumptions are required for the compliance reporting scenario?

These questions will be resolved and documented as the design develops.

## 6. Requirement-to-Implementation Checklist

### Scenario A

- [x] Persist an immutable audit-event model with a monotonic record ID,
  event fields, previous hash, and content hash.
- [x] Define validated request and response schemas, with the server assigning
  UTC timestamps.
- [x] Implement `POST /audit/events` as the sole creation path; do not add
  public update or delete endpoints.
- [x] Implement `GET /audit/events` with all required filters, deterministic
  ordering, and limit/offset pagination.
- [x] Use canonical JSON, SHA-256, and a fixed genesis value to create
  deterministic content hashes and predecessor links.
- [x] Implement `GET /audit/verify` to report an intact chain or the first
  inconsistent record and violation type.
- [x] Test normal writes and queries, direct-database modification detection,
  and direct-database deletion detection.

Scenario A is functionally completed and accepted as a prototype based on
implemented behavior, automated validation, and developer-performed manual
validation. Requirements reconciliation uses the recovered assessment
transcription supplied during review; it does not claim independent parsing of
the original assessment PDF. The documented trust and production limitations
remain part of this acceptance boundary.

### Scenario B

Task 15 establishes the V3 database foundation only: logical-archive and
non-destructive redaction metadata can be persisted against retained audit
events. It does not execute retention, mask API responses, create lifecycle
events, alter verification, or export records.

- [ ] Document and implement a configurable retention policy using a defined
  archive or soft-delete representation.
- [ ] Ensure verification handles legitimately archived records without a
  false-positive integrity failure.
- [ ] Define a structured redaction representation that removes sensitive
  payload values while retaining verifiable integrity evidence.
- [ ] Document redaction trade-offs and limitations.
- [ ] Implement export by exactly one `resourceId` or `actorId`, including
  records, chain boundary values, hash scheme metadata, and verification
  instructions.
- [ ] Test retention, redaction, and independent export verification.

### Scenario C

- [ ] Record clarification questions for the regulator-access requirement.
- [ ] State assumptions and a normalized requirement before coding.
- [ ] Document the resulting technical design and explicit scope boundary.
- [ ] Implement the agreed reporting scope, or document a reasoned partial
  implementation and its limitation.

### Repository Deliverables

- [ ] Keep setup, architecture, API, testing, risk, limitation, and final
  engineering-summary documentation current.
- [ ] Maintain an honest AI usage log linked to actual tasks and commits.
- [ ] Add `ATTESTATION.md` after the engineer supplies their own required
  identity and submission details.

## 7. Additional Working Decisions

The following choices refine the initial design and remain subject to review
when their implementation task is approved:

| Area | Working decision | Reason |
| --- | --- | --- |
| Chain order | Database-assigned increasing record ID | Deterministic even when timestamps are equal. |
| Hash inputs | Required event fields and normalized server timestamp; exclude database ID, `previous_hash`, and mutable operational metadata | Avoids a persistence cycle while keeping content hashing independent from the chain link. |
| Time filtering | Inclusive `from`/`to` UTC bounds | Predictable API semantics. |

## 8. Canonical Content-Hash Rule

The content hash covers exactly `eventType`, `actorId`, `resourceType`,
`resourceId`, `payload`, and `timestamp`. It does not cover the database ID
or `previous_hash`; the latter is stored separately as the chain link.

The hash input is UTF-8 encoded JSON with sorted object keys, compact
separators (`,` and `:`), and non-ASCII characters preserved. The timestamp
must be timezone-aware, is converted to UTC, and is serialized with six
fractional-second digits and a `Z` suffix. SHA-256 of those bytes produces a
lowercase 64-character hexadecimal digest.

### Timestamp persistence invariant

SQLite does not preserve timezone metadata for `DateTime(timezone=True)`.
Audit timestamps are therefore normalized to UTC before persistence and
restored with `timezone.utc` after SQLite retrieval. Naive timestamps are
rejected. This preserves the exact UTC instant and microsecond precision used
by canonical hashing.

Existing SQLite values may be interpreted as UTC only when their origin is
known to follow this service's UTC timestamp invariant. No migration or
automatic repair of unknown existing data is performed.

## 9. Event Write API

`POST /audit/events` accepts the validated event-create contract and returns
`201 Created` only after the append transaction commits. The route delegates
timestamp assignment, predecessor selection, and content hashing to the
append service; it does not duplicate those rules.

The HTTP layer owns commit and rollback because it defines the request
transaction boundary. It returns a camelCase persisted-event response,
including server-owned ID, timestamp, predecessor hash, and content hash.
No update or delete endpoint is exposed.

## 10. Service-Level Append Rule

The creation service assigns the timestamp, reads the highest persisted
record ID, and uses that record's `content_hash` as the new event's
`previous_hash`. When no prior event exists, it uses the fixed genesis value
`AUDIT_LOG_GENESIS_V1`. It calculates the content hash through the canonical
rule above, adds the event, and flushes without committing.

The append service underpins the HTTP write API, which owns commit and rollback
at the request boundary. The prototype does not provide database-level
mutation prevention or coordination for concurrent writers.

## 11. API Schema Boundary

The event-create contract accepts only `eventType`, `actorId`,
`resourceType`, `resourceId`, and object `payload`. These map to the internal
Python names `event_type`, `actor_id`, `resource_type`, and `resource_id`.
The API rejects extra fields, including service-owned `id`, `timestamp`,
`previous_hash`, and `content_hash`.

The persisted-event response exposes camelCase event and hash names
(`previousHash` and `contentHash`), together with the ID and server-assigned
timestamp. Create input trims surrounding whitespace, rejects blank values,
and enforces database-aligned limits: 128 characters for event/resource type
and 256 characters for actor/resource ID.

For persisted response evidence, `eventType`, `actorId`, `resourceType`, and
`resourceId` are plain strings. They preserve stored whitespace, empty values,
and values beyond incoming-request limits rather than applying business-input
normalization during serialization. The OpenAPI create schema retains its
string constraints; the read schema intentionally exposes those four fields as
unconstrained strings. This preserves observable evidence but does not make
every malformed record retrievable: malformed JSON, timestamps, nulls, and
incompatible types remain separate concerns.

## 12. Service-Level Event Querying

The query service accepts optional `actor_id`, `resource_type`, `resource_id`,
`event_type`, `from_timestamp`, and `to_timestamp` filters. Supplied filters
are combined with AND semantics through SQLAlchemy expressions. Resource type
and resource ID may be used independently or together.

Timestamp bounds are timezone-aware, normalized to UTC, and inclusive. Results
are ordered by ascending record ID, then paginated with a default limit of 100,
a maximum limit of 1000, and default offset 0. The service rejects naive or
inverted time bounds and invalid pagination values. It remains read-only and
is exposed through the HTTP query endpoint described below.

## 13. Event Query API

`GET /audit/events` exposes the read-only query service with public
`actorId`, `resourceType`, `resourceId`, `eventType`, `from`, `to`, `limit`,
and `offset` query parameters. All supplied filters combine with AND
semantics. Valid requests return a camelCase array of persisted events in
ascending ID order; no matches return `[]` with HTTP 200.

The route rejects blank or oversized string filters, naive or inverted time
bounds, and invalid pagination with HTTP 422. Pagination defaults to limit
100 and offset 0, with a maximum limit of 1000. Database retrieval failures
return a generic HTTP 500 response without exposing internal details.

## 14. Checkpoint-Backed Chain Verification Foundation

`AuditChainState` is a database-enforced singleton checkpoint containing the
expected event count, chain-head ID, and chain-head content hash. The empty
chain is valid either before any checkpoint exists or with a zero-count
checkpoint whose head fields are null. Each append updates the event and
checkpoint within the caller's transaction; commit and rollback remain the
caller's responsibility.

The verifier reads raw persisted events in ascending ID order, decodes each
event's stored JSON and timestamp text only when that event is examined,
recalculates its content hash, checks its predecessor link, and then compares
count and head metadata with the checkpoint. This per-record decoding means an
earlier hash or predecessor failure takes precedence over malformed content in
a later record. Database IDs establish order but are not required to be
consecutive. The verifier is read-only and reports structured, deterministic
violation results rather than raising for identifiable malformed persisted
content.

Appending to a nonempty chain requires a checkpoint whose count and tail match
the persisted events. Inconsistency raises the domain-specific
`AuditChainIntegrityError`; the write route maps this to HTTP 409 after
rollback. Operational database failures are not classified as
integrity violations and propagate to the caller.

The checkpoint is stored in the same database and is not an external trust
anchor. A privileged attacker able to rewrite records, hashes, links, and the
checkpoint together may evade detection. Existing databases with events but
without trusted checkpoint state are not backfilled automatically; they need
an explicit migration or fresh-database strategy. Future retention or archival
features must retain enough evidence for verification.

## 15. Chain Verification API

`GET /audit/verify` exposes the read-only verification service. It returns
HTTP 200 for both intact and inconsistent chains because an integrity failure
is a completed verification result, not malformed client input. Its camelCase
response includes intact status, checked-record count, an optional first
inconsistency ID, violation type, and safe explanatory detail.

Database execution failures return a sanitized HTTP 500 response. The API
logs only static operational outcome messages and does not log payloads,
resource identifiers, SQL, database paths, credentials, or exception details.
When a checkpoint inconsistency blocks `POST /audit/events`, the route rolls
back and returns HTTP 409 without appending an event. Verification and error
handling do not repair, backfill, or otherwise mutate audit evidence.

## 16. Versioned Linked Chain Hashes

The unchanged `content_hash` is SHA-256 over canonical event content. V2 also
stores `hash_scheme_version` (`audit-chain-v1`), `previous_chain_hash`, and
`chain_hash`. A chain hash is SHA-256 of UTF-8 canonical JSON containing
`contentHash`, `domain` (`audit-log-chain-hash`), `hashSchemeVersion`, and
`previousChainHash`; keys are sorted, separators are compact, non-ASCII text
is preserved, and NaN is rejected. The fixed first predecessor is SHA-256 of
the UTF-8 bytes of `audit-log-chain-genesis-v1`.

`previous_hash` keeps its original meaning: the predecessor event's content
hash (or the documented content genesis value). It is not silently repurposed.
The checkpoint records the version, count, head ID, and head chain hash.
Append validates only bounded tail/checkpoint integrity; full verification is
required to assess the complete history.

The default runtime database is `audit_log_v3.db`, configurable through
`AUDIT_DB_PATH`. Startup inspects existing `audit_` table names and their
column-name sets before `create_all`, then rejects V1, V2, partial V3, and
mixed audit schemas without mutation. This name-based preflight does not
validate column types, constraints, indexes, or SQLite table SQL. The original
`audit_log.db` and any existing V2 database are not migrated, backfilled,
reset, or modified automatically.

## 17. Scenario B Lifecycle Metadata Foundation

V3 adds two unused metadata tables while preserving the original audit-event
content, content hashes, linked-chain hashes, and checkpoint semantics:

- `audit_event_archives` has a surrogate ID, unique target event ID, UTC archive
  timestamp, and the ID of the future chained archival-action event.
- `audit_event_redactions` records a target event, canonical JSON Pointer,
  UTC timestamp, non-sensitive reason/category, and the ID of the future
  chained redaction-action event. Its target-event/pointer pair is unique.

Both tables reference `audit_events`; SQLite foreign keys are enabled for the
application and isolated SQLAlchemy engines so those references are enforced.
They intentionally contain no original sensitive values. Archival and
redaction remain distinct: Task 16 creates and verifies archival metadata only.
Redaction metadata is not created, consumed by queries, applied to payloads,
or verified yet.

SQLite does not enforce declared `VARCHAR` lengths. A future retention or
redaction service/API must explicitly validate canonical JSON Pointer syntax,
the 1024-character pointer limit, and the 256-character non-sensitive reason
limit before persistence.

The approved follow-on contract is that lifecycle metadata must correspond to
chained lifecycle audit-action evidence, and future verification must detect
missing, unexpected, or inconsistent metadata/action relationships. Lifecycle
action events must advance the checkpoint normally, and metadata plus action
events must commit or roll back in one caller-owned transaction. Internal
lifecycle event types will be reserved from ordinary client creation and must
not be recursively archived or redacted in a way that undermines verification.

Future retention, redaction, and export HTTP endpoints are intended for
trusted local assessment use only until authentication and authorization are
implemented. Redaction will be masking, not permanent erasure. Export
verification will distinguish a bundle's internal digest consistency from a
comparison against an externally retained expected digest; it will not claim
independent source authenticity or filtered-result completeness.

## 18. Configurable Retention and Logical Archival

`AUDIT_RETENTION_DAYS` defaults to 90 and must be a positive base-10 integer
no greater than 36,500. Empty, whitespace-only, fractional, negative, zero,
non-numeric, and excessive values are configuration errors; an explicit bad
value never falls back silently. Eligibility uses server-controlled,
timezone-aware UTC time and is strict: an event timestamp must be earlier than
`now - retention_days`. Ordinary callers cannot provide a cutoff or duration.

`POST /audit/retention/run` executes the configured policy in the trusted local
prototype environment. Before writing, it runs full chain and archival-metadata
verification. It selects unarchived, non-lifecycle business events in ascending
ID order, appends one `AUDIT_RETENTION_APPLIED` lifecycle event, and creates one
archive row per selected target. The action payload commits retention days,
cutoff, archived IDs, count, and the action timestamp; metadata uses that exact
server-assigned action timestamp. The service flushes but never commits, while
the route validates its response then commits or rolls back.

Repeated runs with no newly eligible events are no-ops and append no action
event. Logical archival leaves the original row, content hash, chain hash, and
checkpoint history intact; it neither deletes data nor reclaims storage.
Default event queries exclude archived business events through a database-level
anti-join condition before pagination. `includeArchived=true` includes both
archived and active events. Internal lifecycle events remain queryable.

Ordinary create input and the ordinary append service reject reserved internal
types `AUDIT_RETENTION_APPLIED` and `AUDIT_REDACTION_APPLIED`. A narrow internal
append path reuses normal hashing and checkpoint behavior for lifecycle events.
This is application-level boundary protection, not authentication or
authorization.

After the existing event-chain and checkpoint checks succeed, verification
checks archival lifecycle evidence. It reports `ARCHIVE_MALFORMED_ACTION` for
invalid archival action payloads and `ARCHIVE_METADATA_MISMATCH` for missing,
unexpected, duplicate, inconsistent, ineligible, internal, or incorrectly
timestamped archive metadata. Existing Scenario A per-record and checkpoint
precedence remains first; lifecycle checks occur afterward with the full chain
record count and the related action event ID where identifiable.

## 19. Non-destructive Payload Redaction

Redaction stores only target ID, canonical JSON Pointer, UTC action timestamp,
allowlisted non-sensitive reason, and lifecycle action ID. It never changes the
original payload, timestamp, hashes, links, or checkpoint. `POST
/audit/events/{eventId}/redact` accepts up to 50 distinct, non-overlapping RFC
6901 paths and reason codes `SENSITIVE_DATA`, `PRIVACY_REQUEST`, or
`POLICY_REQUIREMENT`. Repeating an existing path is a no-op even with a new
reason; the original evidence remains authoritative.

Retrieval deep-copies payloads, replaces selected values with `"[REDACTED]"`,
and returns `redactedPaths`. It validates lifecycle overlay metadata before
projection and fails closed for lifecycle inconsistency, but preserves Task 12
inspection of ordinary Scenario A content tampering. The original content hash
describes the original payload and cannot be recomputed from a projected
response. Redaction is masking, not permanent erasure.

Verification runs redaction checks after existing event, checkpoint, and
archive checks. `REDACTION_MALFORMED_ACTION` covers malformed action evidence;
`REDACTION_METADATA_MISMATCH` covers missing, unexpected, duplicated,
overlapping, invalid-path, target/reference/reason/timestamp-inconsistent
metadata. Export may reuse this projection later. No access control,
concurrency coordination, or permanent deletion is implemented.
