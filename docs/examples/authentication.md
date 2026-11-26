# Authentication example

## Objective

Generate temporary local JWTs and demonstrate role-scoped access.

Set a disposable database and `AUDIT_JWT_SIGNING_KEY`, `AUDIT_JWT_ISSUER`, and `AUDIT_JWT_AUDIENCE`; run `python -m app.generate_token --subject writer-demo --role writer` or substitute `auditor`, `regulator`, or `admin`. Send values only in local `Authorization: Bearer` headers. A writer can create but cannot list; an auditor can list/verify/export but cannot create. Missing/invalid tokens are 401 and insufficient role is 403. Source: `app/auth.py`; evidence: `tests/test_auth.py` and route RBAC tests. Close terminals or unset variables; never store generated tokens.
