# Compliance-reporting example

## Objective

Report explicitly recorded, fictional client-account access events.

Create a writer-authorized V4 event with `eventType` `CLIENT_ACCOUNT_ACCESS`, `resourceType` `customer_account`, and payload `{"operation":"READ","outcome":"SUCCESS","details":{"screen":"summary"}}`. The writer needs `CREATE_EVENT`; the regulator needs active membership and `READ_ACCESS_REPORT` for the account. Request `/audit/access-reports?from=2026-01-01T00:00:00Z&to=2026-12-31T00:00:00Z&operation=READ`. Expected: HTTP 200 matching only authorized tenant evidence, archives included by default, and current redaction projection. Invalid bounds are 422, corrupt source is 409, and absent grants do not disclose evidence. This reports recorded evidence only; it does not prove complete real-world access capture.
