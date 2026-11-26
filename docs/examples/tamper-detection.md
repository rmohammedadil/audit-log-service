# Tamper-detection example

## Objective

Demonstrate detection without changing preserved evidence.

Seed a disposable V4 database through the API, stop the server, and copy only
that database. Directly modify the copy through a local SQLite tool, restart
with `AUDIT_V4_DB_PATH` set to the copy, then call `GET /audit/verify` using a
tenant-aware auditor token with `VERIFY_TENANT_CHAIN`. Expected result is a safe
tenant result with `isIntact:false`; retrieval/export/reporting fail closed.
Never modify `audit_log.db`.
