# API Reference

## Base URL and authentication

Default local base URL: `http://127.0.0.1:8000`. Swagger UI is `/docs`; OpenAPI
JSON is `/openapi.json`. Every response includes server-generated
`X-Request-ID` correlation metadata.

All `/audit` routes need `Authorization: Bearer <JWT>`. Validation requires an
HS256 signature, expiration, subject, issuer, audience, and permitted roles.
Invalid/missing credentials return 401; a valid caller without route permission
returns 403. Root, health, readiness, Swagger, and OpenAPI are local public
operational endpoints.

| Role | Authorized operations |
| --- | --- |
| writer | Create events |
| auditor | List events, verify, export |
| regulator | Verify, access reports |
| admin | List, verify, export, retention, redaction |

## Common contract

- Public field names are camelCase.
- Time filters must be timezone-aware; UTC `Z` is recommended.
- `limit`: 1–1,000, default 100. `offset`: 0–1,000,000, default 0.
- HTTP 422 can contain FastAPI structured validation errors or application
  `{"detail":"..."}` validation detail.
- HTTP 409 means integrity cannot be trusted, unsafe append, or idempotency
  conflict. HTTP 500 is sanitized.

Examples are fictional and illustrative, not captured execution evidence.

## Operational endpoints

| Method/path | Purpose | Success | Failure |
| --- | --- | --- | --- |
| `GET /` | Service message | 200 | — |
| `GET /health` | Liveness; no DB read | 200 `{"status":"healthy"}` | — |
| `GET /ready` | DB `SELECT 1` | 200 `{"status":"ready"}` | 503 `{"status":"unavailable"}` |

## `POST /audit/events` — Create event

Role: `writer`. Body must contain exactly:

```json
{
  "eventType": "ACCOUNT_UPDATED",
  "actorId": "advisor-demo",
  "resourceType": "customer_account",
  "resourceId": "account-demo-001",
  "payload": {"field": "mailingAddress", "status": "updated"}
}
```

Event/resource type max length is 128; actor/resource ID max length is 256;
all are nonblank. Payload is an object. ID, timestamp, hash values, lifecycle
types, and unknown fields are rejected. `AuditEventRead` returns event fields,
ID, UTC timestamp, and all content/chain integrity fields.

Optional `Idempotency-Key` is 1–128 permitted characters (letters, digits,
`.`, `:`, `_`, `-`) scoped to the writer subject. Initial creation is 201;
matching replay is 200 with the existing projected event; changed content is
409. Invalid key is 422. Other documented statuses: 401, 403, 409, 422, 500.

## `GET /audit/events` — List events

Roles: `auditor`, `admin`. Parameters: `actorId`, `resourceType`,
`resourceId`, `eventType`, `from`, `to`, `includeArchived` (default false),
`limit`, and `offset`. Filters combine with AND; time boundaries are inclusive;
ascending ID ordering and archive filtering occur before pagination.

```text
/audit/events?actorId=advisor-demo&resourceType=customer_account&limit=25&offset=0
```

HTTP 200 returns `AuditEventQueryRead[]` with `redactedPaths`; no match is
`[]`. Source integrity verification precedes payload release, so untrusted
evidence is 409. Invalid input is 422.

## `GET /audit/verify` — Verify evidence

Roles: `auditor`, `regulator`, `admin`. HTTP 200 represents both intact and
inconsistent completed verification. `AuditChainVerificationRead` contains
`isIntact`, `checkedRecordCount`, nullable `firstInconsistencyId`, nullable
`violationType`, and safe `detail`. Operational failure is 500.

## `POST /audit/retention/run` — Run retention

Role: `admin`. No caller policy is accepted; `AUDIT_RETENTION_DAYS` controls
the server-owned run. HTTP 200 `RetentionRunRead` provides `retentionDays`,
UTC `cutoff`, `archivedEventCount`, `archivedEventIds`, and nullable
`actionEventId`. Integrity rejection is 409; operational failure is 500.

## `POST /audit/events/{eventId}/redact` — Mask payload paths

Role: `admin`.

```json
{"paths":["/customer/contact/email"],"reason":"SENSITIVE_DATA"}
```

Paths are 1–50 unique, non-overlapping existing RFC 6901 pointers. Reasons:
`SENSITIVE_DATA`, `PRIVACY_REQUEST`, `POLICY_REQUIREMENT`. HTTP 200 returns
`targetEventId`, `newlyRedactedPathCount`, `newlyRedactedPaths`, and nullable
`actionEventId`; 404 means absent target, 422 invalid request, 409 untrusted
source.

## `POST /audit/exports` — Export verified evidence

Roles: `auditor`, `admin`.

```json
{"actorId":"advisor-demo","includeArchived":true}
```

Exactly one `actorId` or `resourceId` selector is required. HTTP 200 returns an
unsigned `audit-export-v1` or configured signed `audit-export-v2` bundle with
selected projected records, metadata, full payload-free chain witness,
checkpoint, digest, and optional Ed25519 signature. Selection input is 422;
untrusted source is 409. Export has no ordinary retrieval-pagination limit.

```bash
python -m app.verify_export audit-export.json
python -m app.verify_export audit-export.json --expected-digest <trusted-digest>
python -m app.verify_export audit-export.json --public-key C:/keys/audit-public.pem
```

## `GET /audit/access-reports` — Report recorded access

Role: `regulator`. Required `from` and `to`; optional `accountId`, `actorId`,
`operation`, `outcome`, `limit`, and `offset`. Archived records are included by
default. It reports canonical `CLIENT_ACCOUNT_ACCESS` events for
`customer_account` with accepted operation/outcome values. HTTP 200 returns
`AuditAccessReportRead[]`; invalid input is 422, untrusted source 409, and
operational failure 500.

## Status summary

| Status | Meaning |
| --- | --- |
| 200 | Read/list/verify/export/retention/redaction success or idempotent replay |
| 201 | Initial event creation committed |
| 401 / 403 | Authentication or endpoint-role failure |
| 404 | Redaction target absent |
| 409 | Integrity/idempotency conflict or unsafe operation |
| 422 | Request or application validation error |
| 500 / 503 | Sanitized operational/readiness failure |

Swagger publishes route schemas, response declarations, and Bearer security
metadata. It does not issue a token or bypass authorization. For algorithms
and trust boundaries, see [system-design.md](system-design.md).
