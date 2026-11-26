#!/usr/bin/env bash
# Exercise the Compose deployment without printing its JWTs, bearer tokens, or data.
set -euo pipefail

project="audit-ci-${GITHUB_RUN_ID:-local}-$$"
compose=(docker compose --project-name "$project" --file compose.yaml)
response_file="$(mktemp)"

cleanup() {
  "${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
  rm -f "$response_file"
}
trap cleanup EXIT

mask_for_actions() {
  # GitHub consumes this workflow command before normal log output. Local runs
  # intentionally do not print temporary credentials merely to mask them.
  if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
    printf '::add-mask::%s\n' "$1"
  fi
}

expect_status() {
  local expected_status="$1"
  shift
  local actual_status
  actual_status="$(curl --silent --show-error --max-time 10 --output "$response_file" --write-out '%{http_code}' "$@")"
  test "$actual_status" = "$expected_status"
}

grant_admin() {
  "${compose[@]}" exec --no-TTY audit-log-service \
    python -m app.manage_grants --database /var/lib/audit-v4/audit_log_v4.db "$@" >/dev/null
}

# The values exist only in this process and Compose interpolation is checked quietly.
export AUDIT_JWT_SIGNING_KEY
AUDIT_JWT_SIGNING_KEY="$(openssl rand -hex 32)"
mask_for_actions "$AUDIT_JWT_SIGNING_KEY"
export AUDIT_JWT_ISSUER="audit-ci"
export AUDIT_JWT_AUDIENCE="audit-ci-api"
export AUDIT_RETENTION_DAYS="90"

"${compose[@]}" config --quiet
"${compose[@]}" build
"${compose[@]}" up --detach

wait_for_ready() {
  for _ in $(seq 1 30); do
    if [[ "$(curl --silent --show-error --max-time 2 --output /dev/null --write-out '%{http_code}' http://127.0.0.1:8000/ready)" == "200" ]]; then
      return 0
    fi
    sleep 1
  done
  "${compose[@]}" logs >&2
  return 1
}

wait_for_ready
expect_status 200 http://127.0.0.1:8000/health
expect_status 200 http://127.0.0.1:8000/
expect_status 200 http://127.0.0.1:8000/docs
expect_status 200 http://127.0.0.1:8000/openapi.json
expect_status 401 --header 'Content-Type: application/json' --request POST http://127.0.0.1:8000/audit/events \
  --data '{"eventType":"ACCOUNT_UPDATED","actorId":"ci-actor","resourceType":"customer_account","resourceId":"ci-account-001","payload":{"change":"ci"}}'

# The application never provisions identities or grants itself. This trusted
# offline setup grants only the exact disposable CI tenant/resource operations.
grant_admin principal-add --tenant ci-tenant --subject ci-writer
grant_admin resource-grant --tenant ci-tenant --subject ci-writer \
  --resource-type customer_account --resource-id ci-account-001 --permission CREATE_EVENT
grant_admin principal-add --tenant ci-tenant --subject ci-auditor
grant_admin resource-grant --tenant ci-tenant --subject ci-auditor \
  --resource-type customer_account --resource-id ci-account-001 --permission READ_EVENT
grant_admin tenant-grant --tenant ci-tenant --subject ci-auditor --permission VERIFY_TENANT_CHAIN
grant_admin principal-add --tenant ci-tenant --subject ci-ungranted-auditor

writer_token="$("${compose[@]}" exec --no-TTY audit-log-service python -m app.generate_token --subject ci-writer --role writer --tenant-id ci-tenant)"
mask_for_actions "$writer_token"
expect_status 201 --header "Authorization: Bearer $writer_token" \
  --header 'Content-Type: application/json' --request POST http://127.0.0.1:8000/audit/events \
  --data '{"eventType":"ACCOUNT_UPDATED","actorId":"ci-actor","resourceType":"customer_account","resourceId":"ci-account-001","payload":{"change":"ci"}}'
created_event="$(<"$response_file")"
event_ref="$(printf '%s' "$created_event" | python3 -c 'import json, sys; print(json.load(sys.stdin)["eventRef"])')"
test -n "$event_ref"

auditor_token="$("${compose[@]}" exec --no-TTY audit-log-service python -m app.generate_token --subject ci-auditor --role auditor --tenant-id ci-tenant)"
mask_for_actions "$auditor_token"
expect_status 200 --header "Authorization: Bearer $auditor_token" http://127.0.0.1:8000/audit/verify
verification="$(<"$response_file")"
printf '%s' "$verification" | python3 -c 'import json, sys; assert json.load(sys.stdin)["isIntact"] is True'

expect_status 200 --header "Authorization: Bearer $auditor_token" http://127.0.0.1:8000/audit/events
printf '%s' "$(<"$response_file")" | python3 -c 'import json, sys; rows=json.load(sys.stdin); assert len(rows) == 1 and rows[0]["eventRef"] == sys.argv[1] and "id" not in rows[0]' "$event_ref"

ungranted_auditor_token="$("${compose[@]}" exec --no-TTY audit-log-service python -m app.generate_token --subject ci-ungranted-auditor --role auditor --tenant-id ci-tenant)"
mask_for_actions "$ungranted_auditor_token"
expect_status 200 --header "Authorization: Bearer $ungranted_auditor_token" http://127.0.0.1:8000/audit/events
printf '%s' "$(<"$response_file")" | python3 -c 'import json, sys; assert json.load(sys.stdin) == []'

legacy_writer_token="$("${compose[@]}" exec --no-TTY audit-log-service python -m app.generate_token --subject ci-legacy-writer --role writer)"
mask_for_actions "$legacy_writer_token"
expect_status 401 --header "Authorization: Bearer $legacy_writer_token" \
  --header 'Content-Type: application/json' --request POST http://127.0.0.1:8000/audit/events \
  --data '{"eventType":"ACCOUNT_UPDATED","actorId":"ci-actor","resourceType":"customer_account","resourceId":"ci-account-001","payload":{"change":"legacy"}}'

# A Compose recreation without --volumes must retain the event in the named volume.
"${compose[@]}" down
"${compose[@]}" up --detach
wait_for_ready
expect_status 200 --header "Authorization: Bearer $auditor_token" http://127.0.0.1:8000/audit/events
persisted_events="$(<"$response_file")"
printf '%s' "$persisted_events" | python3 -c 'import json, sys; expected = sys.argv[1]; assert expected in {item["eventRef"] for item in json.load(sys.stdin)}' "$event_ref"

image_id="$("${compose[@]}" images --quiet audit-log-service)"
test -n "$image_id"
test "$("${compose[@]}" exec --no-TTY audit-log-service id -u)" != "0"
docker run --rm --entrypoint /bin/sh "$image_id" -c 'test -z "$(find /app -type f \( -name "*.db" -o -name "*.sqlite" -o -name "*.sqlite3" -o -name "*.pem" -o -name "*.key" \) -print -quit)"'
