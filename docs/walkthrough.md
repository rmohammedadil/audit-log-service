# Technical Walkthrough

Use fictional data, temporary local credentials, and a disposable database. Never use `audit_log.db` or an acceptance database for tamper demonstrations.

## Setup and startup

```bash
cd /c/Charles_Schwab/audit-log-service
source .venv/Scripts/activate
mkdir -p /c/Charles_Schwab/task32-demo
export AUDIT_DB_PATH="C:/Charles_Schwab/task32-demo/audit-demo.db"
export AUDIT_JWT_SIGNING_KEY="replace-with-a-unique-local-secret-at-least-32-characters"
export AUDIT_JWT_ISSUER="audit-demo"
export AUDIT_JWT_AUDIENCE="audit-api"
python -m uvicorn app.main:app --reload
```

Open `/health`, `/ready`, and `http://127.0.0.1:8000/docs`.

## Temporary role tokens

In a second terminal with the same three JWT variables, run:

```bash
WRITER_TOKEN=$(python -m app.generate_token --subject writer-demo --role writer)
AUDITOR_TOKEN=$(python -m app.generate_token --subject auditor-demo --role auditor)
ADMIN_TOKEN=$(python -m app.generate_token --subject admin-demo --role admin)
REGULATOR_TOKEN=$(python -m app.generate_token --subject regulator-demo --role regulator)
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

Expected: initial POST is 201, identical retry is 200 with the same ID, changed payload under the same key is 409, listing is 200, and intact verification is 200 with `isIntact:true`.

## Lifecycle, export, report, and controlled tampering

Use admin role for redaction/retention and auditor/admin role for export. Use regulator role for `/audit/access-reports` with required UTC `from` and `to`. For direct tampering, stop the server and modify only a copy of the disposable database. Restart against the copy; `/audit/verify` reports an inconsistency, while retrieval/export/reporting fail closed. See [examples](examples/README.md) for safe, focused commands.

## Tests, Docker, and cleanup

```bash
mkdir -p /c/Charles_Schwab/pytest-temp
python -m pytest -q -p no:cacheprovider --basetemp "C:/Charles_Schwab/pytest-temp/run-$(date +%Y%m%d-%H%M%S)"
```

The recorded regression baseline is 341 tests; this walkthrough does not claim to rerun every scenario. Stop Uvicorn and remove only the checked disposable `task32-demo` path. Docker/CI guidance is in [docker-and-ci.md](examples/docker-and-ci.md).
