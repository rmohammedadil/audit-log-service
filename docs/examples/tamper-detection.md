# Tamper-detection example

## Objective

Demonstrate detection without changing preserved evidence.

Seed a disposable database through the API, stop the server, and copy only that disposable database. Directly modify the copy through a local SQLite tool, restart with `AUDIT_DB_PATH` set to the copy, then call `GET /audit/verify` with auditor role. Expected result: HTTP 200 with `isIntact:false` and a relevant violation such as `CONTENT_HASH_MISMATCH`; retrieval/export/reporting should fail closed with 409. Never modify `audit_log.db`. Relevant evidence: `test_direct_event_content_modification_is_detected` and fail-closed API tests.
