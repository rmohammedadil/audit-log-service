# Docker and CI example

## Objective

Run the service in Docker and explain CI evidence boundaries.

Copy `.env.example` to an untracked `.env`, replace JWT placeholders, then run
`docker compose up --build`. Compose runs `app.main:app` against the separate
V4 named volume `audit-v4-data` at `/var/lib/audit-v4/audit_log_v4.db`; it does
not open or migrate V3 evidence. Use `docker compose down` to preserve it and
`down -v` only for disposable V4 state. Optional signing uses
`compose.signing.yaml` and a host key outside the repository. GitHub Actions
runs regression, strict dependency scan, and a V4 Docker smoke job. The
container-smoke job passed in CI run
[45934437700](https://github.com/rmohammedadil/audit-log-service/actions/runs/45934437700).
Local Docker replay remains pending because Docker is unavailable on the
author's machine; no local Docker result is claimed.
