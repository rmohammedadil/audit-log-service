# Happy-path audit example

## Objective

Create fictional events, retrieve them, and verify an intact chain.

Use tenant-aware writer/auditor tokens and exact `CREATE_EVENT`, `READ_EVENT`,
and `VERIFY_TENANT_CHAIN` grants from the walkthrough. Post the fictional body
in [the API reference](../api-reference.md#supported-v4-runtime-contract), then
post a second distinct body. Retrieve `GET /audit/events?actorId=advisor-demo`
with the authorized auditor and call `GET /audit/verify`. Expected behavior is
HTTP 201 for initial creations, opaque `eventRef` responses, and HTTP 200
`isIntact:true` for that tenant. Use a disposable V4 database only.
