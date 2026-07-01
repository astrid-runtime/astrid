#!/usr/bin/env bash

adversarial_capsule_install_dir() {
  local principal=${1:-default}
  printf '%s/home/%s/.local/capsules/astrid-capsule-adversarial\n' "$ASTRID_HOME" "$principal"
}

adversarial_capsule_backup_dir() {
  printf '%s/adversarial-capsule-install-backup\n' "$ARTIFACTS"
}

backup_adversarial_capsule_install() {
  local source_dir
  local backup_dir
  source_dir="$(adversarial_capsule_install_dir)"
  backup_dir="$(adversarial_capsule_backup_dir)"
  [[ -d "$source_dir" ]] || fail "cannot back up adversarial capsule install; missing $source_dir"
  rm -rf "$backup_dir"
  cp -R "$source_dir" "$backup_dir"
}

restore_adversarial_capsule_install() {
  local ops_bearer=$1
  local user_bearer=$2
  local user_principal=${3:-}
  local target_dir
  local backup_dir
  local status
  target_dir="$(adversarial_capsule_install_dir)"
  backup_dir="$(adversarial_capsule_backup_dir)"
  [[ -d "$backup_dir" ]] || fail "cannot restore adversarial capsule install; missing $backup_dir"
  rm -rf "$target_dir"
  mkdir -p "$(dirname "$target_dir")"
  cp -R "$backup_dir" "$target_dir"
  if [[ -n "$user_principal" ]]; then
    target_dir="$(adversarial_capsule_install_dir "$user_principal")"
    rm -rf "$target_dir"
    mkdir -p "$(dirname "$target_dir")"
    cp -R "$backup_dir" "$target_dir"
  fi

  status="$(http_status POST /api/sys/capsules/reload "$ops_bearer" "" \
    "$ARTIFACTS/adversarial-capsule-restore-reload.json")"
  assert_status "adversarial capsule restore reload" "$status" 204
  if [[ -n "$user_principal" ]]; then
    wait_for_readiness_capsules adversarial-capsule-restore "$user_bearer" \
      astrid-capsule-adversarial
  fi
  status="$(http_status GET /api/capsules "$user_bearer" "" \
    "$ARTIFACTS/adversarial-capsule-restore-capsules.json")"
  assert_status "adversarial capsule list after restore" "$status" 200
  json_assert_capsule_list_state "$ARTIFACTS/adversarial-capsule-restore-capsules.json" \
    astrid-capsule-adversarial present
}

run_live_approval_cancel_smoke() {
  local user_bearer=$1
  local user_principal=$2
  local status
  local sse="$ARTIFACTS/adversarial-approval-cancel-requests.sse"
  local out="$ARTIFACTS/adversarial-approval-cancel-cli.txt"

  note "checking live approval cancellation on capsule unload"
  curl -sN --max-time 20 \
    -H "Authorization: Bearer $user_bearer" \
    "$GATEWAY/api/agent/requests" \
    > "$sse" 2>&1 &
  local stream_pid=$!
  wait_for_sse_ready "$sse" || {
    terminate_pid "$stream_pid"
    cat "$sse" >&2 2>/dev/null || true
    fail "approval cancel request stream did not become ready"
  }
  bounded_principal_cli "$user_principal" 12 "$out" \
    capsule run astrid-capsule-adversarial adversarial-approval &
  local cli_pid=$!
  wait_for_approval_request_id "$sse" > "$ARTIFACTS/adversarial-approval-cancel-request-id.txt" || {
    terminate_pid "$cli_pid"
    terminate_pid "$stream_pid"
    cat "$sse" >&2 2>/dev/null || true
    fail "approval cancel request stream did not forward adversarial approval request"
  }

  run_principal_cli "$user_principal" capsule remove astrid-capsule-adversarial --force
  terminate_pid "$stream_pid"

  local cancel_rc=0
  wait "$cli_pid" || cancel_rc=$?
  if [[ "$cancel_rc" -eq 0 ]]; then
    cat "$out" >&2 2>/dev/null || true
    fail "adversarial approval command succeeded after capsule unload cancellation"
  fi
  if [[ "$cancel_rc" -eq 124 ]]; then
    cat "$out" >&2 2>/dev/null || true
    fail "adversarial approval command hung after capsule unload cancellation"
  fi

  status="$(http_status GET /api/capsules "$user_bearer" "" \
    "$ARTIFACTS/adversarial-approval-cancel-capsules.json")"
  assert_status "adversarial capsule list after live approval cancel remove" "$status" 200
  json_assert_capsule_list_state "$ARTIFACTS/adversarial-approval-cancel-capsules.json" \
    astrid-capsule-adversarial absent
}

run_live_elicit_cancel_smoke() {
  local user_bearer=$1
  local user_principal=$2
  local status
  local sse="$ARTIFACTS/adversarial-elicit-cancel-requests.sse"
  local out="$ARTIFACTS/adversarial-elicit-cancel-cli.txt"

  note "checking live elicit cancellation on capsule unload"
  curl -sN --max-time 20 \
    -H "Authorization: Bearer $user_bearer" \
    "$GATEWAY/api/agent/requests" \
    > "$sse" 2>&1 &
  local stream_pid=$!
  wait_for_sse_ready "$sse" || {
    terminate_pid "$stream_pid"
    cat "$sse" >&2 2>/dev/null || true
    fail "elicit cancel request stream did not become ready"
  }
  bounded_principal_cli "$user_principal" 12 "$out" \
    capsule run astrid-capsule-adversarial adversarial-elicit &
  local cli_pid=$!
  wait_for_elicit_request_id "$sse" > "$ARTIFACTS/adversarial-elicit-cancel-request-id.txt" || {
    terminate_pid "$cli_pid"
    terminate_pid "$stream_pid"
    cat "$sse" >&2 2>/dev/null || true
    fail "elicit cancel request stream did not forward adversarial elicit request"
  }

  run_principal_cli "$user_principal" capsule remove astrid-capsule-adversarial --force
  terminate_pid "$stream_pid"

  local cancel_rc=0
  wait "$cli_pid" || cancel_rc=$?
  if [[ "$cancel_rc" -eq 0 ]]; then
    cat "$out" >&2 2>/dev/null || true
    fail "adversarial elicit command succeeded after capsule unload cancellation"
  fi
  if [[ "$cancel_rc" -eq 124 ]]; then
    cat "$out" >&2 2>/dev/null || true
    fail "adversarial elicit command hung after capsule unload cancellation"
  fi
  grep -Eqi 'timed out|timeout|cancelled' "$out" \
    || fail "adversarial elicit command did not report cancellation"

  status="$(http_status GET /api/capsules "$user_bearer" "" \
    "$ARTIFACTS/adversarial-elicit-cancel-capsules.json")"
  assert_status "adversarial capsule list after live elicit cancel remove" "$status" 200
  json_assert_capsule_list_state "$ARTIFACTS/adversarial-elicit-cancel-capsules.json" \
    astrid-capsule-adversarial absent
}
