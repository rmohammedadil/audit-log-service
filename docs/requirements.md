
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

- [ ] Persist an immutable audit-event model with a monotonic record ID,
  event fields, previous hash, and content hash.
- [ ] Define validated request and response schemas, with the server assigning
  UTC timestamps.
- [ ] Implement `POST /audit/events` as the sole creation path; do not add
  public update or delete endpoints.
- [ ] Implement `GET /audit/events` with all required filters, deterministic
  ordering, and limit/offset pagination.
- [ ] Use canonical JSON, SHA-256, and a fixed genesis value to create
  deterministic content hashes and predecessor links.
- [ ] Implement `GET /audit/verify` to report an intact chain or the first
  inconsistent record and violation type.
- [ ] Test normal writes and queries, direct-database modification detection,
  and direct-database deletion detection.

### Scenario B

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

## 9. Service-Level Append Rule

The creation service assigns the timestamp, reads the highest persisted
record ID, and uses that record's `content_hash` as the new event's
`previous_hash`. When no prior event exists, it uses the fixed genesis value
`AUDIT_LOG_GENESIS_V1`. It calculates the content hash through the canonical
rule above, adds the event, and flushes without committing.

This provides a sequential append foundation only. It does not yet offer an
HTTP write API, mutation prevention at the database level, or coordination
for concurrent writers.

## 10. API Schema Boundary

The event-create contract accepts only `eventType`, `actorId`,
`resourceType`, `resourceId`, and object `payload`. These map to the internal
Python names `event_type`, `actor_id`, `resource_type`, and `resource_id`.
The API rejects extra fields, including service-owned `id`, `timestamp`,
`previous_hash`, and `content_hash`.

The persisted-event response exposes camelCase event and hash names
(`previousHash` and `contentHash`), together with the ID and server-assigned
timestamp. Input string limits match the database model: 128 characters for
event/resource type and 256 characters for actor/resource ID.
