
# Architecture Overview

## Initial Scope

The prototype is a FastAPI service backed by SQLite. HTTP routes validate
requests, a service layer owns audit-chain behavior, and SQLAlchemy models
persist records. This separation makes hash-chain rules testable independently
from the HTTP interface.

## Components

| Component | Responsibility |
| --- | --- |
| `app/main.py` | Creates the FastAPI application and registers API routes. |
| `app/api/audit_routes.py` | Defines audit endpoints and translates requests/responses. |
| `app/schemas.py` | Defines request and response validation schemas. |
| `app/services/audit_service.py` | Canonicalizes and hashes event content, appends records with checkpoint updates, queries events, and verifies persisted chains. Concurrent-writer coordination remains deferred. |
| `app/models.py` | Defines persisted audit events and later archival/redaction metadata. |
| `app/database.py` | Configures the SQLite engine, sessions, and declarative base. |
| `tests/` | Covers service rules, API behavior, and direct-database tamper scenarios. |

## Scenario A Data Model (Proposed)

An audit event will have a database ID, event fields, a UTC timestamp, the
previous-record hash, and a SHA-256 content hash. The database ID orders the
chain, but it is not part of the content hash because it is unavailable until
the row is persisted. The content hash covers the required event fields and a
normalized UTC timestamp using canonical JSON. The predecessor hash remains a
separate chain link.

The database is intentionally not assumed to be trusted: verification
recomputes hashes from stored values and checks every predecessor link. The
prototype detects tampering; it does not prevent a privileged attacker from
rewriting the entire database and chain.

The append operation selects the latest persisted event by ID. It uses the
prior content hash as the new predecessor, or `AUDIT_LOG_GENESIS_V1` for the
first record. It flushes rather than commits so an HTTP layer can decide
whether the request transaction should be committed or rolled back.

SQLite does not retain timezone offsets for regular SQLAlchemy datetimes. A
small `UtcDateTime` type normalizes aware values to UTC, stores SQLite values
without offset metadata, and restores `timezone.utc` on retrieval. This is
necessary because a reloaded timestamp must produce the same content hash as
the original event. The invariant applies only to rows known to originate
from this service; unknown legacy values are not migrated or repaired.

## API Direction (Proposed)

- `POST /audit/events`: append one validated event.
- `GET /audit/events`: list events with optional filters and pagination.
- `GET /audit/verify`: validate the complete chain.

There will be no public update or delete route. Scenario B routes will be
designed only after archival, redaction, and export semantics are documented
and reviewed.

## API Contract Boundary

`AuditEventCreate` accepts only client-owned event content using camelCase
field names. It maps those names to the snake_case names used by the model and
service, rejecting timestamps, IDs, hashes, and other unexpected fields.
`AuditEventRead` maps a SQLAlchemy `AuditEvent` back to camelCase and includes
the server-owned timestamp and integrity evidence for later API responses.

## Write Request Lifecycle

`POST /audit/events` validates JSON as `AuditEventCreate`, obtains a
request-scoped SQLAlchemy session through dependency injection, and delegates
record construction to `append_audit_event`. The service flushes to build a
complete record; the route validates the response, then commits. On a
persistence failure, the route rolls back and returns a generic error without
exposing database details. The session dependency closes the session in all
cases.

The application lifespan creates prototype tables through a replaceable
initializer. API tests replace that initializer and the session dependency,
using a temporary SQLite database rather than the project database.

## Query Service Boundary

The query service builds a SQLAlchemy `select` statement with optional,
parameterized predicates for each supported filter. It normalizes time bounds
to UTC, applies filters before ascending-ID offset/limit pagination, and uses
`session.no_autoflush` to avoid flushing a caller's unrelated pending changes.
It returns persisted model objects only; the existing HTTP route parses public
query parameters and serializes those results through `AuditEventRead`.

## Query API Boundary

`GET /audit/events` maps the public camelCase query names to the service's
snake_case parameters. FastAPI documents those aliases in Swagger UI and
performs structural query parsing; the route rejects whitespace-only filters,
translates service validation failures to HTTP 422, and converts retrieval
failures to a generic HTTP 500. It delegates all SQLAlchemy filtering and
ordering to the query service and serializes models through `AuditEventRead`.

Creation schemas normalize and validate untrusted input, while `AuditEventRead`
preserves the persisted `event_type`, `actor_id`, `resource_type`, and
`resource_id` strings exactly as stored. This prevents a GET response from
trimming, rejecting, or silently rewriting direct database tampering. Returning
that evidence does not establish that it is trustworthy: within the existing
same-database checkpoint trust boundary, `verify_audit_chain` reports supported
content-hash, predecessor-link, and checkpoint inconsistencies. This
read-schema boundary does not make malformed JSON, timestamps, nulls, or other
incompatible persisted values serializable.

## Chain Checkpoint and Verification Boundary

`AuditChainState` is a singleton row whose count, head ID, and head hash are
updated with each appended event in the same caller-owned transaction. Before
appending to a nonempty database, the service requires a checkpoint that
matches the current count and tail; it never silently reconstructs missing
state.

`verify_audit_chain` suppresses autoflush and reads raw persisted column values
without passing through API schemas. It retrieves JSON and timestamp text
without ORM type decoding, then decodes and validates them one event at a
time. Its deterministic precedence is: missing checkpoint for a nonempty
chain; then, in ascending ID order, malformed event content, content-hash
mismatch, and predecessor mismatch; then checkpoint count, head-ID, and
head-hash mismatch. IDs need not be gap-free.

Verification selects column mappings rather than ORM entities, so loaded or
locally modified identity-map objects cannot substitute for persisted evidence.
It does not refresh or overwrite those objects. Per-event decoding ensures a
malformed later row cannot mask an earlier detected failure. Checkpoint-only
mismatches use no event ID because no particular surviving event can be proven
inconsistent. Operational SQLAlchemy failures propagate; only identifiable
persistence decoding or canonicalization failures become integrity results.

The checkpoint catches trailing deletion but is stored in the same database,
not externally anchored. Coordinated rewriting by a privileged database actor,
concurrent append coordination, and consistent verification snapshots remain
out of scope.

## Verification API Boundary

`GET /audit/verify` is a thin HTTP adapter around `verify_audit_chain`. It
does not load, normalize, or verify event evidence itself; it serializes the
service's structured result through a camelCase response schema. Both an
intact result and an integrity violation use HTTP 200 because verification ran
successfully in either case. Operational SQLAlchemy failures are rolled back
at the request boundary, logged as static messages without exception detail,
and returned as a generic HTTP 500.

The same route module maps `AuditChainIntegrityError` during event creation to
HTTP 409 after rollback. This distinguishes an unsafe append blocked by the
checkpoint from an operational persistence failure, while leaving chain and
transaction ownership in the service and HTTP layer respectively.

## Key Trade-offs

- SQLite supports a self-contained prototype and test tampering, but is not a
  production multi-writer or high-availability datastore.
- Offset pagination is straightforward but can shift during concurrent writes;
  cursor pagination would be a production-oriented follow-up.
- Stronger tamper resistance would require external hash anchoring or
  write-once storage, beyond this prototype's stated requirement.
