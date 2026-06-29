#!/usr/bin/env bash

pick_loopback_port() {
  "$PYTHON" - <<'PY'
import socket

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

multi_http_status() {
  local gateway=$1
  local method=$2
  local path=$3
  local bearer=$4
  local body=$5
  local out=$6
  local args=(
    --connect-timeout 2
    --max-time 25
    -sS
    -o "$out"
    -w "%{http_code}"
    -X "$method"
    "$gateway$path"
  )
  if [[ -n "$bearer" ]]; then
    args+=(-H "Authorization: Bearer $bearer")
  fi
  if [[ -n "$body" ]]; then
    args+=(-H "Content-Type: application/json" -d "$body")
  fi
  LAST_HTTP_OUT="$out"
  curl "${args[@]}"
}

multi_run_cli() {
  local home=$1
  local artifacts=$2
  shift 2
  printf '$ ASTRID_HOME=%s astrid %s\n' "$home" "$*" >> "$artifacts/cli-transcript.log"
  env ASTRID_HOME="$home" HOME="$POISON_HOME" "$CORE_DIR/target/debug/astrid" "$@" \
    > >(tee -a "$artifacts/cli-transcript.log") \
    2> >(tee -a "$artifacts/cli-transcript.log" >&2)
}

multi_redeem_invite() {
  local home=$1
  local gateway=$2
  local invite=$3
  local display_name=$4
  local out=$5
  local artifacts=$6
  local pubkey
  multi_run_cli "$home" "$artifacts" keypair generate --name "$display_name" --force --raw \
    > "$artifacts/$display_name-pubkey.hex"
  pubkey="$(<"$artifacts/$display_name-pubkey.hex")"
  local status
  status="$(multi_http_status "$gateway" POST /api/auth/redeem "" \
    "{\"token\":\"$invite\",\"public_key\":\"$pubkey\",\"display_name\":\"$display_name\"}" \
    "$out")"
  assert_status "$display_name secondary redeem" "$status" 200
  mkdir -p "$home/keys"
  install -m 600 "$home/keys/local/$display_name.ed25519" \
    "$home/keys/$(json_field "$out" principal).key"
}

run_multi_home_smoke() {
  local fake_base_url=$1
  local primary_bearer=$2
  local primary_principal=$3
  note "checking independent Astrid home isolation"

  SECONDARY_HOME="$(mktemp -d /tmp/astrid-b.XXXXXX)"
  local secondary_home="$SECONDARY_HOME"
  local secondary_artifacts="$ARTIFACTS/secondary-home"
  local secondary_port
  local secondary_gateway
  local fake_addr="${fake_base_url#http://}"
  secondary_port="$(pick_loopback_port)"
  secondary_gateway="http://$GATEWAY_HOST:$secondary_port"

  mkdir -p "$secondary_home/etc" "$secondary_artifacts"
  cat > "$secondary_home/etc/gateway-http.toml" <<EOF
enabled = true
listen = "$GATEWAY_HOST:$secondary_port"
session-lifetime-secs = 3600
redeem-rate-limit-secs = 0
EOF
  cat > "$secondary_home/config.toml" <<EOF
[logging]
directives = ["astrid_gateway::routes::sessions=debug", "astrid_events=debug"]
[security.capsule_local_egress]
"astrid-capsule-openai-compat" = ["$fake_addr"]
"openai-compat" = ["$fake_addr"]
EOF

  local secondary_capsules="${ASTRID_E2E_SECONDARY_CAPSULES:-astrid-capsule-cli astrid-capsule-registry astrid-capsule-openai-compat}"
  local capsule
  for capsule in $secondary_capsules; do
    multi_run_cli "$secondary_home" "$secondary_artifacts" capsule install "$CAPSULES_DIR/$capsule"
  done

  printf '$ ASTRID_HOME=%s astrid capsule config astrid-capsule-openai-compat --set base_url=<fake> --set model=fake-echo\n' \
    "$secondary_home" >> "$secondary_artifacts/cli-transcript.log"
  printf 'y\n' | env ASTRID_HOME="$secondary_home" HOME="$POISON_HOME" \
    "$CORE_DIR/target/debug/astrid" capsule config astrid-capsule-openai-compat \
    --set "base_url=$fake_base_url" \
    --set "model=fake-echo" \
    > "$secondary_artifacts/openai-config.out" \
    2> "$secondary_artifacts/openai-config.err"

  local secondary_default_secret="ASTRID_E2E_SECONDARY_DEFAULT_SECRET_DO_NOT_LEAK_$RANDOM$RANDOM"
  register_redaction_sentinel "$secondary_default_secret"
  printf '$ ASTRID_HOME=%s astrid secret set api_key <redacted> --capsule astrid-capsule-openai-compat\n' \
    "$secondary_home" >> "$secondary_artifacts/cli-transcript.log"
  env ASTRID_HOME="$secondary_home" HOME="$POISON_HOME" \
    "$CORE_DIR/target/debug/astrid" secret set api_key "$secondary_default_secret" \
    --capsule astrid-capsule-openai-compat \
    > "$secondary_artifacts/openai-secret.out" \
    2> "$secondary_artifacts/openai-secret.err"

  env ASTRID_HOME="$secondary_home" HOME="$POISON_HOME" \
    "$CORE_DIR/target/debug/astrid-daemon" >> "$secondary_artifacts/daemon.log" 2>&1 &
  SECONDARY_DAEMON_PID=$!
  wait_for_http "$secondary_gateway/healthz" || {
    tail -n 200 "$secondary_artifacts/daemon.log" >&2 || true
    fail "secondary daemon did not become healthy"
  }

  local status
  status="$(multi_http_status "$secondary_gateway" GET /api/auth/me "$primary_bearer" "" \
    "$secondary_artifacts/primary-token-on-secondary.json")"
  assert_status "primary bearer denied by secondary home" "$status" 401

  local secondary_invite
  secondary_invite="$(env ASTRID_HOME="$secondary_home" HOME="$POISON_HOME" \
    "$CORE_DIR/target/debug/astrid" invite issue --group agent --max-uses 1 --expires-secs 600 --raw \
    2>> "$secondary_artifacts/cli-transcript.log")"
  printf '$ ASTRID_HOME=%s astrid invite issue --group agent --max-uses 1 --expires-secs 600 --raw\n<redacted invite token>\n' \
    "$secondary_home" >> "$secondary_artifacts/cli-transcript.log"
  multi_redeem_invite "$secondary_home" "$secondary_gateway" "$secondary_invite" regular-user \
    "$secondary_artifacts/secondary-agent-redeem.json" "$secondary_artifacts"

  local secondary_bearer
  local secondary_principal
  secondary_bearer="$(json_field "$secondary_artifacts/secondary-agent-redeem.json" session_token)"
  secondary_principal="$(json_field "$secondary_artifacts/secondary-agent-redeem.json" principal)"
  [[ "$secondary_principal" == "$primary_principal" ]] \
    || fail "secondary home principal $secondary_principal did not match same-name primary $primary_principal"

  status="$(http_status GET /api/auth/me "$secondary_bearer" "" \
    "$ARTIFACTS/secondary-token-on-primary.json")"
  assert_status "secondary bearer denied by primary home" "$status" 401

  local prompt_capsules=(
    --add-capsule astrid-capsule-registry
    --add-capsule astrid-capsule-openai-compat
  )
  multi_run_cli "$secondary_home" "$secondary_artifacts" agent modify "$secondary_principal" "${prompt_capsules[@]}"

  multi_run_cli "$secondary_home" "$secondary_artifacts" quota set \
    --agent "$secondary_principal" --processes 2 --ipc-rate "512KB/s"
  status="$(multi_http_status "$secondary_gateway" GET "/api/sys/principals/$secondary_principal/quotas" \
    "$secondary_bearer" "" "$secondary_artifacts/secondary-quota.json")"
  assert_status "secondary quota self-read" "$status" 200
  json_assert_field_equals "$secondary_artifacts/secondary-quota.json" max_background_processes 2
  status="$(http_status GET "/api/sys/principals/$primary_principal/quotas" "$primary_bearer" "" \
    "$ARTIFACTS/primary-quota-after-secondary.json")"
  assert_status "primary quota unchanged after secondary write" "$status" 200
  json_assert_field_equals "$ARTIFACTS/primary-quota-after-secondary.json" max_background_processes 4

  local secondary_user_secret="ASTRID_E2E_SECONDARY_USER_SECRET_DO_NOT_LEAK_$RANDOM$RANDOM"
  register_redaction_sentinel "$secondary_user_secret"
  status="$(multi_http_status "$secondary_gateway" POST \
    /api/capsules/astrid-capsule-openai-compat/env/base_url "$secondary_bearer" \
    "{\"value\":\"$fake_base_url\"}" "$secondary_artifacts/secondary-openai-base-url-write.json")"
  assert_status "secondary env base_url write" "$status" 204
  status="$(multi_http_status "$secondary_gateway" POST \
    /api/capsules/astrid-capsule-openai-compat/env/api_key "$secondary_bearer" \
    "{\"value\":\"$secondary_user_secret\"}" "$secondary_artifacts/secondary-openai-secret-write.json")"
  assert_status "secondary secret write" "$status" 204

  local deadline=$((SECONDS + 45))
  until status="$(multi_http_status "$secondary_gateway" GET /api/models "$secondary_bearer" "" \
    "$secondary_artifacts/secondary-models.json")" \
    && [[ "$status" == 200 ]] \
    && grep -q 'openai-compat:fake-echo' "$secondary_artifacts/secondary-models.json"; do
    if (( SECONDS >= deadline )); then
      cat "$secondary_artifacts/secondary-models.json" >&2 2>/dev/null || true
      fail "secondary registry did not discover fake-echo"
    fi
    sleep 2
  done
  status="$(multi_http_status "$secondary_gateway" PUT /api/models/active "$secondary_bearer" \
    '{"id":"openai-compat:fake-echo"}' "$secondary_artifacts/secondary-set-active-model.json")"
  assert_status "secondary set active model" "$status" 200
  json_assert_model_id "$secondary_artifacts/secondary-set-active-model.json" "openai-compat:fake-echo"
  status="$(http_status GET /api/models/active "$primary_bearer" "" "$ARTIFACTS/primary-active-model-after-secondary.json")"
  assert_status "primary active model unchanged after secondary write" "$status" 200
  json_assert_model_id "$ARTIFACTS/primary-active-model-after-secondary.json" "openai-compat:fake-slow"
  redaction_check "$secondary_default_secret"
  redaction_check "$secondary_user_secret"

  terminate_pid "$SECONDARY_DAEMON_PID"
  SECONDARY_DAEMON_PID=""
}
