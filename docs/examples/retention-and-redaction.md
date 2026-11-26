# Retention and redaction example

## Objective

Demonstrate logical archival and non-destructive masking on disposable data.

Seed historical timestamps only through a service-level test harness; do not directly edit persisted timestamps. With admin role call `POST /audit/retention/run`; eligible non-lifecycle rows receive action/metadata, not deletion. `GET /audit/events` excludes archived targets unless `includeArchived=true`. Redact with `{"paths":["/customer/contact/email"],"reason":"SENSITIVE_DATA"}`. Later responses show `[REDACTED]` and `redactedPaths`; original integrity fields remain unchanged. Repeating existing paths is a no-op. See retention/redaction service and route tests.
