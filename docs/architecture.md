
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
| `app/services/audit_service.py` | Canonicalizes event content and calculates content hashes; later tasks will add chain writes, queries, and verification. |
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

## API Direction (Proposed)

- `POST /audit/events`: append one validated event.
- `GET /audit/events`: list events with optional filters and pagination.
- `GET /audit/verify`: validate the complete chain.

There will be no public update or delete route. Scenario B routes will be
designed only after archival, redaction, and export semantics are documented
and reviewed.

## Key Trade-offs

- SQLite supports a self-contained prototype and test tampering, but is not a
  production multi-writer or high-availability datastore.
- Offset pagination is straightforward but can shift during concurrent writes;
  cursor pagination would be a production-oriented follow-up.
- Stronger tamper resistance would require external hash anchoring or
  write-once storage, beyond this prototype's stated requirement.
