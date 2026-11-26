# Technical Walkthrough

Use fictional data, temporary local credentials, and a fresh V4 database. Never
use `audit_log.db`, a V3 database, or an acceptance database for demonstrations.

## Setup and startup

```bash
cd /c/Charles_Schwab/audit-log-service
source .venv/Scripts/activate
mkdir -p /c/Charles_Schwab/task36f-demo
export AUDIT_V4_DB_PATH="C:/Charles_Schwab/task36f-demo/audit-v4.db"
export AUDIT_JWT_SIGNING_KEY="replace-with-a-unique-local-secret-at-least-32-characters"
export AUDIT_JWT_ISSUER="audit-demo"
export AUDIT_JWT_AUDIENCE="audit-api"
python -m uvicorn app.main:app --reload
```

`AUDIT_V4_DB_PATH` is required. A fresh path initializes V4; a legacy or
partial path is rejected without migration. Open `/health`, `/ready`, and
`http://127.0.0.1:8000/docs`.

## Temporary role tokens

In a second terminal with the same configuration, provision exact grants before
generating tokens. Roles do not grant resource access by themselves:

```bash
DB="$AUDIT_V4_DB_PATH"
python -m app.manage_grants --database "$DB" principal-add --tenant tenant-demo --subject writer-demo
python -m app.manage_grants --database "$DB" resource-grant --tenant tenant-demo --subject writer-demo --resource-type customer_account --resource-id account-demo-001 --permission CREATE_EVENT
python -m app.manage_grants --database "$DB" principal-add --tenant tenant-demo --subject auditor-demo
python -m app.manage_grants --database "$DB" resource-grant --tenant tenant-demo --subject auditor-demo --resource-type customer_account --resource-id account-demo-001 --permission READ_EVENT
python -m app.manage_grants --database "$DB" tenant-grant --tenant tenant-demo --subject auditor-demo --permission VERIFY_TENANT_CHAIN
WRITER_TOKEN=$(python -m app.generate_token --subject writer-demo --role writer --tenant-id tenant-demo)
AUDITOR_TOKEN=$(python -m app.generate_token --subject auditor-demo --role auditor --tenant-id tenant-demo)
```

Do not print, commit, or screenshot tokens.

## Create, retrieve, verify, and replay

```bash
curl -i -X POST http://127.0.0.1:8000/audit/events \
  -H "Authorization: Bearer $WRITER_TOKEN" -H "Content-Type: application/json" \
  -H "Idempotency-Key: demo-create-001" \
  -d '{"eventType":"ACCOUNT_UPDATED","actorId":"advisor-demo","resourceType":"customer_account","resourceId":"account-demo-001","payload":{"field":"address","status":"updated"}}'
curl -sS "http://127.0.0.1:8000/audit/events?actorId=advisor-demo" -H "Authorization: Bearer $AUDITOR_TOKEN"
curl -sS http://127.0.0.1:8000/audit/verify -H "Authorization: Bearer $AUDITOR_TOKEN"
```

Expected: initial POST is 201, identical retry is 200 with the same opaque
`eventRef`, changed payload under the same key is 409, listing is 200, and
intact verification is 200 with `isIntact:true`. A token without `tenant_id`
is rejected; an active same-role caller without `READ_EVENT` receives no rows.

## Lifecycle, export, report, and controlled tampering

For redaction, grant an admin `REDACT_EVENT` on the target resource. For
retention, grant admin `RUN_RETENTION`. For export, grant auditor/admin both
`EXPORT_RESOURCE` and `EXPORT_TENANT_WITNESS`; for a report, grant regulator
`READ_ACCESS_REPORT`. Use opaque `eventRef` in the redaction URL. For direct
tampering, stop the server and modify only a copy of the disposable V4 database.
Restart against the copy; tenant verification reports a safe result while
retrieval/export/reporting fail closed. See [examples](examples/README.md) for
focused historical and current examples.

## Tests, Docker, and cleanup

```bash
mkdir -p /c/Charles_Schwab/pytest-temp
python -m pytest -q -p no:cacheprovider --basetemp "C:/Charles_Schwab/pytest-temp/run-$(date +%Y%m%d-%H%M%S)"
```

The latest recorded cutover regression is 428 passing tests; this walkthrough
does not claim to rerun every scenario. Stop Uvicorn and remove only the checked
disposable `task36f-demo` path. Docker/CI guidance is in
[docker-and-ci.md](examples/docker-and-ci.md); Docker runtime validation remains
pending locally.
