# Compliance-reporting example

## Objective

Report explicitly recorded, fictional client-account access events.

Create a writer-authorized event with `eventType` `CLIENT_ACCOUNT_ACCESS`, `resourceType` `customer_account`, and payload `{"operation":"READ","outcome":"SUCCESS","details":{"screen":"summary"}}`. With regulator role request `/audit/access-reports?from=2026-01-01T00:00:00Z&to=2026-12-31T00:00:00Z&operation=READ`. Expected: HTTP 200 matching recorded evidence, archives included by default, and current redaction projection. Invalid bounds are 422, corrupt source is 409, and a non-regulator is 403. This reports recorded evidence only; it does not prove complete real-world access capture.
