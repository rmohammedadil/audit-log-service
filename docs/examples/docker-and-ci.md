# Docker and CI example

## Objective

Run the service in Docker and explain CI evidence boundaries.

Copy `.env.example` to an untracked `.env`, replace JWT placeholders, then run `docker compose up --build`. SQLite persists in named `audit-data`; use `docker compose down` to preserve it and `down -v` only for disposable state. Optional signing uses `compose.signing.yaml` and a host key outside the repository. GitHub Actions runs regression, strict dependency scan, and Docker smoke jobs. A successful post-remediation run was developer-confirmed; Task 31 could not independently retrieve run ID/job logs, so do not describe those details as independently verified.
