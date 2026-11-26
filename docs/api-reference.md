# API Reference

> **Current supported contract: V4.** `app.main:app` serves only the tenant-
> scoped routes below. Older V3 names, numeric IDs, and role-only behavior in
> historical design records are not a supported runtime interface.

## Supported V4 runtime contract

`app.main:app` is the supported tenant-scoped V4 application. Every `/audit`
request requires a HS256 JWT with valid `exp`, `sub`, `iss`, `aud`, roles, and
canonical `tenant_id`. A role is necessary but not sufficient: the caller must
also have active membership and each required exact resource or tenant grant.
`eventRef` is the public opaque event identifier; internal database IDs and
tenant sequence values are never API fields.

| Method/path | Required role and active grant | Success contract |
| --- | --- | --- |
| `POST /audit/events` | writer + `CREATE_EVENT` | 201 creation or 200 identical idempotent replay; response contains `eventRef` |
| `GET /audit/events` | writer/auditor/admin + `READ_EVENT` | Authorized, redacted, non-archived events only; filters apply after scope |
| `GET /audit/verify` | auditor/regulator/admin + `VERIFY_TENANT_CHAIN` | Tenant-only `isIntact` and `checkedRecordCount` |
| `POST /audit/retention/run` | admin + `RUN_RETENTION` | Tenant archival result with `archivedEventCount` |
| `POST /audit/events/{eventRef}/redact` | admin + `REDACT_EVENT` | `redactedPaths`; unknown/ungranted targets are indistinguishable 404s |
| `POST /audit/exports` | auditor/admin + `EXPORT_RESOURCE` and `EXPORT_TENANT_WITNESS` | V4 scoped masked bundle, digest, optional signature |
| `GET /audit/access-reports` | regulator + `READ_ACCESS_REPORT` | Authorized canonical access evidence only |

Create body:

```json
{"eventType":"ACCOUNT_UPDATED","actorId":"advisor-demo","resourceType":"customer_account","resourceId":"account-demo-001","payload":{"field":"mailingAddress"}}
```

Event type/resource type are nonblank with a 128-character maximum; actor and
resource IDs are nonblank with a 256-character maximum; `payload` must be a
JSON object. Server-owned timestamps, hashes, tenant identity, sequence,
internal IDs, lifecycle event types, and unknown fields are rejected. An
optional `Idempotency-Key` is 1–128 letters, digits, `.`, `:`, `_`, or `-` and
is scoped to `(tenant, authenticated subject)`.

List supports `actorId`, `resourceType`, `resourceId`, `limit` (1–1000), and
`offset` (0–1,000,000). Access reports require UTC-aware `from` and `to` and
optionally support `accountId`, `actorId`, `operation`, `outcome`,
`includeArchived`, `limit`, and `offset`. Exports require exactly one selector:
`actorId` or `resourceId`, with optional `includeArchived`.

HTTP 401 means missing/invalid tenant-aware authentication; 403 means an active
grant is absent; 404 is the non-disclosing redaction target response; 409 is a
generic integrity/idempotency conflict; 422 is request validation; 500/503 are
sanitized operational outcomes. V4 export bundles can be checked using:

```bash
python -m app.verify_export audit-export.json
python -m app.verify_export audit-export.json --expected-digest <trusted-digest>
python -m app.verify_export audit-export.json --public-key C:/keys/audit-public.pem
```

Offline verification proves bundle consistency and, with an independently
trusted public key, signer authenticity. It does not prove source selection
completeness, source-database authenticity, or original redacted values.

Representative V4 lifecycle/report requests and responses:

```text
POST /audit/events/{eventRef}/redact
{"paths":["/customer/contact/email"],"reason":"SENSITIVE_DATA"}
→ 200 {"redactedPaths":["/customer/contact/email"]}

POST /audit/retention/run
→ 200 {"archivedEventCount":1}

POST /audit/exports
{"resourceId":"account-demo-001","includeArchived":true}
→ 200 {"bundleSchemaVersion":"audit-v4-export-v1", "bundleDigest":"...", ...}

GET /audit/access-reports?from=2026-01-01T00:00:00Z&to=2026-12-31T00:00:00Z
→ 200 [{"eventRef":"...", "eventType":"CLIENT_ACCOUNT_ACCESS", ...}]
```

# Historical V3 API record (not a supported runtime interface)

## Base URL and authentication

Default local base URL: `http://127.0.0.1:8000`. Swagger UI is `/docs`; OpenAPI
JSON is `/openapi.json`. Every response includes server-generated
`X-Request-ID` correlation metadata.

All `/audit` routes need `Authorization: Bearer <JWT>`. Validation requires an
HS256 signature, expiration, subject, issuer, audience, permitted roles, and a
canonical `tenant_id`. A valid role must additionally have active membership and
the exact active resource or tenant grant. Invalid/missing credentials return
401; missing grants return 403 or an empty scoped list where appropriate. Root,
health, readiness, Swagger, and OpenAPI are local public operational endpoints.

| Role | Authorized operations |
| --- | --- |
| writer | `CREATE_EVENT` for the target resource |
| auditor | `READ_EVENT`; `VERIFY_TENANT_CHAIN`; or `EXPORT_RESOURCE` plus `EXPORT_TENANT_WITNESS` as applicable |
| regulator | `VERIFY_TENANT_CHAIN` or `READ_ACCESS_REPORT` as applicable |
| admin | `READ_EVENT`, `REDACT_EVENT`, `RUN_RETENTION`, verification/export grants as applicable |

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
all are nonblank. Payload is an object. IDs, timestamps, hash values, lifecycle
types, and unknown fields are rejected. The V4 response returns opaque
`eventRef`, UTC timestamp, and content/chain integrity fields; it never returns
the internal database ID or tenant sequence.

Optional `Idempotency-Key` is 1–128 permitted characters (letters, digits,
`.`, `:`, `_`, `-`) scoped to the writer subject. Initial creation is 201;
matching replay is 200 with the existing projected event; changed content is
409. Invalid key is 422. Other documented statuses: 401, 403, 409, 422, 500.

## `GET /audit/events` — List events

Roles: `writer`, `auditor`, or `admin`, plus active `READ_EVENT` grants.
Parameters: `actorId`, `resourceType`, `resourceId`, `limit`, and `offset`.
Filters combine with AND. Tenant/resource authorization and archive/lifecycle
filtering happen before tenant-sequence ordering and pagination. An ungranted
resource cannot be disclosed through omitted or actor-only filters.

```text
/audit/events?actorId=advisor-demo&resourceType=customer_account&limit=25&offset=0
```

HTTP 200 returns `AuditEventQueryRead[]` with `redactedPaths`; no match is
`[]`. Source integrity verification precedes payload release, so untrusted
evidence is 409. Invalid input is 422.

## `GET /audit/verify` — Verify evidence

Roles: `auditor`, `regulator`, or `admin`, plus `VERIFY_TENANT_CHAIN`. HTTP 200
returns only the caller tenant's `isIntact` and `checkedRecordCount`; it does
not reveal global IDs, other-tenant counts, or detailed diagnostics.

## `POST /audit/retention/run` — Run retention

Role: `admin` plus `RUN_RETENTION`. No caller policy is accepted;
`AUDIT_RETENTION_DAYS` controls the server-owned run. HTTP 200 returns only
`{"archivedEventCount": <number>}`. Integrity rejection is 409; operational
failure is sanitized.

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
