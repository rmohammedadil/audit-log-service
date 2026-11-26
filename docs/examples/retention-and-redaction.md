# Retention and redaction example

## Objective

Demonstrate logical archival and non-destructive masking on disposable data.

Seed historical timestamps only through a service-level test harness; do not
directly edit persisted timestamps. In V4, an active admin needs
`RUN_RETENTION` to call `POST /audit/retention/run`; eligible same-tenant rows
receive action/metadata, not deletion. `GET /audit/events` hides archived
targets. Redaction requires `REDACT_EVENT` for the target resource and uses
`POST /audit/events/{eventRef}/redact` with
`{"paths":["/customer/contact/email"],"reason":"SENSITIVE_DATA"}`. Later
authorized responses show `[REDACTED]` and `redactedPaths`; repeating existing
paths is a no-op.
