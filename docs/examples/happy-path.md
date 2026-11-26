# Happy-path audit example

## Objective

Create fictional events, retrieve them, and verify an intact chain.

Use writer/auditor tokens from the walkthrough. Post the fictional body in [the API reference](../api-reference.md#post-auditevents--create-event), then post a second distinct body. Retrieve `GET /audit/events?actorId=advisor-demo` with auditor role and call `GET /audit/verify`. Expected behavior is HTTP 201 for initial creations, ascending IDs, predecessor/chain evidence, and HTTP 200 `isIntact:true`. Use a disposable database only. Relevant evidence: creation/link/retrieval/verification tests in `tests/test_audit_routes.py` and `tests/test_chain_verification.py`.
