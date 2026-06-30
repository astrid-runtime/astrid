#!/usr/bin/env bash

terminate_pid() {
  local pid=$1
  [[ -n "$pid" ]] || return 0

  kill "$pid" 2>/dev/null || true
  for _ in {1..50}; do
    if ! kill -0 "$pid" 2>/dev/null; then
      wait "$pid" 2>/dev/null || true
      return 0
    fi
    sleep 0.1
  done
  kill -KILL "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
}

wait_for_http() {
  local url=$1
  local timeout_secs=${2:-${ASTRID_E2E_HTTP_WAIT_SECS:-90}}
  local deadline=$((SECONDS + timeout_secs))
  until curl --connect-timeout 2 --max-time 5 -fsS "$url" >/dev/null 2>&1; do
    if (( SECONDS >= deadline )); then
      return 1
    fi
    sleep 1
  done
}

tail_daemon_diagnostics() {
  local log_file
  printf '\nrecent daemon stdout/stderr:\n' >&2
  tail -n 200 "$ARTIFACTS/daemon.log" >&2 || true
  for log_file in "$ASTRID_HOME"/log/* "$ASTRID_HOME"/home/*/.local/log/*; do
    [[ -f "$log_file" ]] || continue
    printf '\nrecent runtime log (%s):\n' "$log_file" >&2
    tail -n 120 "$log_file" >&2 || true
  done
}

start_daemon() {
  local label=$1
  note "$label"
  printf '\n==> %s\n' "$label" >> "$ARTIFACTS/daemon.log"
  "$CORE_DIR/target/debug/astrid-daemon" >> "$ARTIFACTS/daemon.log" 2>&1 &
  DAEMON_PID=$!
  wait_for_http "$GATEWAY/healthz" || {
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
      wait "$DAEMON_PID" 2>/dev/null || true
      DAEMON_PID=""
    fi
    tail_daemon_diagnostics
    fail "daemon did not become healthy"
  }
}

stop_daemon() {
  terminate_pid "$DAEMON_PID"
  DAEMON_PID=""
}

wait_for_fake_port() {
  local file=$1
  local deadline=$((SECONDS + 10))
  until grep -q '^PORT=' "$file" 2>/dev/null; do
    if (( SECONDS >= deadline )); then
      return 1
    fi
    sleep 0.2
  done
}
