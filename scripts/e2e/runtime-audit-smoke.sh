#!/usr/bin/env bash

collect_audit_artifacts() {
  local user_bearer=$1
  local ops_bearer=$2
  local user_principal=$3
  local ops_principal=$4
  local status

  status="$(http_status GET "/api/sys/audit?limit=1000" "$user_bearer" "" "$ARTIFACTS/agent-audit.json")"
  assert_status "agent scoped audit export" "$status" 200
  status="$(http_status GET "/api/sys/audit?limit=1000" "$ops_bearer" "" "$ARTIFACTS/operator-audit.json")"
  assert_status "operator scoped audit export" "$status" 200
  json_assert_audit_scope_and_events "$ARTIFACTS/agent-audit.json" "$user_principal" \
    admin.auth.pair.issue:success \
    admin.auth.pair.issue:failure \
    admin.invite.issue:failure
  json_assert_audit_scope_and_events "$ARTIFACTS/operator-audit.json" "$ops_principal" \
    admin.invite.issue:success \
    admin.agent.delete:failure \
    admin.auth.pair.issue:failure \
    admin.caps.grant:failure
}
