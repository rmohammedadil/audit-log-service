# Authentication example

## Objective

Generate temporary local JWTs and demonstrate role-scoped access.

Set `AUDIT_V4_DB_PATH` plus `AUDIT_JWT_SIGNING_KEY`, `AUDIT_JWT_ISSUER`, and
`AUDIT_JWT_AUDIENCE`. Create a principal and exact grant with
`python -m app.manage_grants --database "$AUDIT_V4_DB_PATH" principal-add --tenant tenant-demo --subject writer-demo`, then issue
`python -m app.generate_token --subject writer-demo --role writer --tenant-id tenant-demo`.
Send values only in local `Authorization: Bearer` headers. A V4 role alone is
insufficient: active membership and an exact grant are mandatory. Missing or
invalid tenant-aware tokens are 401; missing grants are 403 or a non-disclosing
empty result. Close terminals or unset variables; never store generated tokens.
