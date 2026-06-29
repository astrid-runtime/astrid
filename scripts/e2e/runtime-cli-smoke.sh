#!/usr/bin/env bash

run_cli_semantic_smoke() {
  local user_principal=$1 ops_principal=$2
  note "checking built-in CLI semantic read paths"

  run_cli agent list --format json > "$ARTIFACTS/cli-agent-list.json"
  json_assert_cli_agent_list "$ARTIFACTS/cli-agent-list.json" "$user_principal" "$ops_principal"
  run_cli agent show "$user_principal" --format json > "$ARTIFACTS/cli-agent-show-user.json"
  json_assert_cli_agent_show "$ARTIFACTS/cli-agent-show-user.json" "$user_principal" agent
  run_cli agent show "$ops_principal" --format json > "$ARTIFACTS/cli-agent-show-ops.json"
  json_assert_cli_agent_show "$ARTIFACTS/cli-agent-show-ops.json" "$ops_principal" ops-team
  run_cli agent create e2e-cli-lifecycle -y
  run_cli agent disable e2e-cli-lifecycle
  run_cli agent show e2e-cli-lifecycle --format json > "$ARTIFACTS/cli-agent-lifecycle-disabled.json"
  json_assert_cli_agent_enabled "$ARTIFACTS/cli-agent-lifecycle-disabled.json" e2e-cli-lifecycle false
  run_cli agent enable e2e-cli-lifecycle
  run_cli agent show e2e-cli-lifecycle --format json > "$ARTIFACTS/cli-agent-lifecycle-enabled.json"
  json_assert_cli_agent_enabled "$ARTIFACTS/cli-agent-lifecycle-enabled.json" e2e-cli-lifecycle true
  run_cli agent delete e2e-cli-lifecycle -y
  if run_cli agent show e2e-cli-lifecycle --format json > "$ARTIFACTS/cli-agent-lifecycle-deleted.json"; then
    fail "deleted agent e2e-cli-lifecycle remained visible"
  fi
  run_cli caps grant "$ops_principal" caps:token:mint
  run_cli caps grant "$ops_principal" caps:token:list
  run_cli caps grant "$ops_principal" caps:token:revoke
  run_cli agent switch "$user_principal" > "$ARTIFACTS/cli-agent-switch-user.txt"
  run_cli agent current > "$ARTIFACTS/cli-agent-current-user.txt"
  grep -qx "$user_principal" "$ARTIFACTS/cli-agent-current-user.txt" || fail "agent current did not reflect switch"
  run_cli agent switch default > "$ARTIFACTS/cli-agent-switch-default.txt"
  rm -f "$ASTRID_HOME/run/cli-context.toml"
  export ASTRID_PRINCIPAL=default
  local cli_session_id
  cli_session_id="$("$PYTHON" -c 'import uuid; print(uuid.uuid4())')"
  local cli_session_display_id="${cli_session_id:0:8}"
  mkdir -p "$ASTRID_HOME/run/$cli_session_id"
  run_cli session list > "$ARTIFACTS/cli-session-list.txt"
  grep -q "$cli_session_display_id" "$ARTIFACTS/cli-session-list.txt" || fail "session list missed test session"
  run_cli session show "$cli_session_id" > "$ARTIFACTS/cli-session-show.txt"
  grep -q "$cli_session_display_id" "$ARTIFACTS/cli-session-show.txt" || fail "session show missed test session"
  run_cli session delete "$cli_session_id"
  if [[ -d "$ASTRID_HOME/run/$cli_session_id" ]]; then
    fail "session delete left test session directory behind"
  fi

  run_cli group list --format json > "$ARTIFACTS/cli-group-list.json"
  json_assert_cli_group "$ARTIFACTS/cli-group-list.json" ops-team invite:issue
  run_cli group show ops-team --format json > "$ARTIFACTS/cli-group-show-ops.json"
  json_assert_cli_group "$ARTIFACTS/cli-group-show-ops.json" ops-team capsule:install
  run_cli group modify ops-team --add-caps system:status
  run_cli group show ops-team --format json > "$ARTIFACTS/cli-group-show-ops-after-add.json"
  json_assert_cli_group "$ARTIFACTS/cli-group-show-ops-after-add.json" ops-team system:status
  run_cli group modify ops-team --remove-caps system:status
  run_cli group show ops-team --format json > "$ARTIFACTS/cli-group-show-ops-after-remove.json"
  json_assert_cli_group_lacks_cap "$ARTIFACTS/cli-group-show-ops-after-remove.json" ops-team system:status

  run_cli caps show "$user_principal" --format json > "$ARTIFACTS/cli-caps-show-user.json"
  json_assert_cli_caps_show "$ARTIFACTS/cli-caps-show-user.json" "$user_principal" agent
  run_cli caps check "$ops_principal" invite:issue > "$ARTIFACTS/cli-caps-check-ops.txt"
  grep -q "allowed" "$ARTIFACTS/cli-caps-check-ops.txt" || fail "caps check did not allow ops invite:issue"
  run_principal_cli "$ops_principal" caps token list "$user_principal" > "$ARTIFACTS/cli-caps-token-list-before.txt"
  grep -q "no tokens" "$ARTIFACTS/cli-caps-token-list-before.txt" || fail "initial token list was not empty"
  local token_resource token_id token_ids
  token_resource="mcp://astrid-e2e:capability-token"
  run_principal_cli "$ops_principal" caps token mint "$user_principal" "$token_resource" --ttl 5m \
    > "$ARTIFACTS/cli-caps-token-mint.txt"
  token_ids="$(grep -Eo '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' \
    "$ARTIFACTS/cli-caps-token-mint.txt")"
  token_id="${token_ids%%$'\n'*}"
  [[ -n "$token_id" ]] || fail "caps token mint did not print a token id"
  run_principal_cli "$ops_principal" caps token list "$user_principal" > "$ARTIFACTS/cli-caps-token-list-after-mint.txt"
  grep -Fq "$token_id" "$ARTIFACTS/cli-caps-token-list-after-mint.txt" || fail "token list missed minted token id"
  grep -Fq "$token_resource" "$ARTIFACTS/cli-caps-token-list-after-mint.txt" || fail "token list missed minted token resource"
  assert_principal_cli_failure "$user_principal" "cli-caps-token-user-mint-denied" \
    caps token mint "$user_principal" "$token_resource"
  assert_principal_cli_failure "$user_principal" "cli-caps-token-user-list-denied" \
    caps token list "$user_principal"
  assert_principal_cli_failure "$user_principal" "cli-caps-token-user-revoke-denied" \
    caps token revoke "$token_id"
  run_principal_cli "$ops_principal" caps token revoke "$token_id" > "$ARTIFACTS/cli-caps-token-revoke.txt"
  grep -Fq "$token_id" "$ARTIFACTS/cli-caps-token-revoke.txt" || fail "token revoke output missed token id"
  run_principal_cli "$ops_principal" caps token list "$user_principal" > "$ARTIFACTS/cli-caps-token-list-after-revoke.txt"
  if grep -Fq "$token_id" "$ARTIFACTS/cli-caps-token-list-after-revoke.txt"; then
    fail "revoked token remained visible in token list"
  fi
  assert_principal_cli_failure "$user_principal" "cli-daemon-stop-user-denied" stop
  run_cli status > "$ARTIFACTS/cli-daemon-status-after-user-stop-denied.txt"
  grep -q "Astrid daemon" "$ARTIFACTS/cli-daemon-status-after-user-stop-denied.txt" \
    || fail "daemon did not remain running after denied regular stop"
  assert_cli_deferred "cli-agent-discover" "remote agent / Agent Card management" agent discover example.invalid
  assert_cli_deferred "cli-agent-add" "remote agent / Agent Card management" agent add example.invalid
  assert_cli_deferred "cli-agent-card" "remote agent / Agent Card management" agent card example.invalid
  assert_cli_deferred "cli-agent-export" "remote agent / Agent Card management" agent export example.invalid
  assert_cli_deferred "cli-agent-import" "remote agent / Agent Card management" agent import example.invalid
  assert_cli_deferred "cli-agent-delegate" "agent delegation" agent delegate example.invalid
  assert_cli_deferred "cli-voucher-create" "capability voucher management" voucher create example --future-flag
  assert_cli_deferred "cli-voucher-list" "capability voucher management" voucher list --future-flag
  assert_cli_deferred "cli-voucher-show" "capability voucher management" voucher show example --future-flag
  assert_cli_deferred "cli-voucher-revoke" "capability voucher management" voucher revoke example --future-flag
  assert_cli_deferred "cli-voucher-history" "capability voucher management" voucher history --future-flag
  assert_cli_deferred "cli-trust-add" "cross-host trust management" trust add example.invalid --future-flag
  assert_cli_deferred "cli-trust-list" "cross-host trust management" trust list --future-flag
  assert_cli_deferred "cli-trust-remove" "cross-host trust management" trust remove example.invalid --future-flag
  assert_cli_deferred "cli-audit" "audit trail inspection" audit "$user_principal" --future-filter

  local invite_token redeem_key pair_token pair_pubkey pair_key_id
  invite_token="$("$CORE_DIR/target/debug/astrid" invite issue --group agent --max-uses 1 \
    --expires-secs 600 --metadata e2e-cli-revoke --raw 2>> "$ARTIFACTS/cli-transcript.log")"
  printf '$ astrid invite issue --group agent --max-uses 1 --expires-secs 600 --metadata e2e-cli-revoke --raw\n<redacted invite token>\n' \
    >> "$ARTIFACTS/cli-transcript.log"
  run_cli invite list --json > "$ARTIFACTS/cli-invite-list-before-revoke.json"
  json_assert_invite_metadata "$ARTIFACTS/cli-invite-list-before-revoke.json" e2e-cli-revoke present
  printf '$ astrid invite revoke <redacted invite token>\n' >> "$ARTIFACTS/cli-transcript.log"
  "$CORE_DIR/target/debug/astrid" invite revoke "$invite_token" \
    > "$ARTIFACTS/cli-invite-revoke.txt" 2>> "$ARTIFACTS/cli-transcript.log"
  run_cli invite list --json > "$ARTIFACTS/cli-invite-list-after-revoke.json"
  json_assert_invite_metadata "$ARTIFACTS/cli-invite-list-after-revoke.json" e2e-cli-revoke absent
  run_cli keypair generate --name e2e-cli-redeem-key --force --raw \
    > "$ARTIFACTS/cli-invite-redeem-key.pub"
  redeem_key="$("$CORE_DIR/target/debug/astrid" invite issue --group agent --max-uses 1 \
    --expires-secs 600 --metadata e2e-cli-redeem --raw 2>> "$ARTIFACTS/cli-transcript.log")"
  printf '$ astrid invite issue --group agent --max-uses 1 --expires-secs 600 --metadata e2e-cli-redeem --raw\n<redacted invite token>\n' \
    >> "$ARTIFACTS/cli-transcript.log"
  printf '$ astrid invite redeem <redacted invite token> --keypair e2e-cli-redeem-key --display-name e2e-cli-redeemed\n' \
    >> "$ARTIFACTS/cli-transcript.log"
  "$CORE_DIR/target/debug/astrid" invite redeem "$redeem_key" --keypair e2e-cli-redeem-key \
    --display-name e2e-cli-redeemed > "$ARTIFACTS/cli-invite-redeem.txt" \
    2>> "$ARTIFACTS/cli-transcript.log"
  run_cli agent show e2e-cli-redeemed --format json > "$ARTIFACTS/cli-invite-redeemed-agent.json"
  json_assert_cli_agent_show "$ARTIFACTS/cli-invite-redeemed-agent.json" e2e-cli-redeemed agent
  run_cli agent delete e2e-cli-redeemed -y
  run_cli keypair delete e2e-cli-redeem-key --yes

  run_cli quota show --agent "$user_principal" --format json > "$ARTIFACTS/cli-quota-show-user.json"
  json_assert_cli_quota "$ARTIFACTS/cli-quota-show-user.json" "$user_principal" 4
  run_cli secret list --agent "$user_principal" --format json > "$ARTIFACTS/cli-secret-list-user.json"
  json_assert_secret_list_metadata "$ARTIFACTS/cli-secret-list-user.json" astrid-capsule-openai-compat api_key
  run_cli secret set e2e_cli_delete_marker e2e-value --agent "$user_principal"
  run_cli secret list --agent "$user_principal" --format json > "$ARTIFACTS/cli-secret-list-with-delete-marker.json"
  json_assert_secret_present "$ARTIFACTS/cli-secret-list-with-delete-marker.json" default e2e_cli_delete_marker
  run_cli secret delete e2e_cli_delete_marker --agent "$user_principal"
  run_cli secret list --agent "$user_principal" --format json > "$ARTIFACTS/cli-secret-list-after-delete.json"
  json_assert_secret_absent "$ARTIFACTS/cli-secret-list-after-delete.json" default e2e_cli_delete_marker
  local capsule_new_parent="$ARTIFACTS/capsule-new"
  mkdir -p "$capsule_new_parent"
  run_cli capsule new e2e-capsule-smoke --path "$capsule_new_parent" < /dev/null
  [[ -f "$capsule_new_parent/e2e-capsule-smoke/Capsule.toml" ]] \
    || fail "capsule new did not write Capsule.toml"
  [[ -f "$capsule_new_parent/e2e-capsule-smoke/src/lib.rs" ]] \
    || fail "capsule new did not write src/lib.rs"
  run_cli capsule tree > "$ARTIFACTS/cli-capsule-tree.txt"
  grep -q "astrid-capsule-openai-compat" "$ARTIFACTS/cli-capsule-tree.txt" \
    || fail "capsule tree missed installed openai-compat capsule"
  mkdir -p "$ASTRID_HOME/wit"
  printf 'orphan wit fixture\n' > "$ASTRID_HOME/wit/e2e-orphan.wit"
  run_cli gc > "$ARTIFACTS/cli-gc-dry-run.txt"
  grep -q "e2e-orphan.wit" "$ARTIFACTS/cli-gc-dry-run.txt" || fail "gc dry-run missed orphaned WIT blob"
  [[ -f "$ASTRID_HOME/wit/e2e-orphan.wit" ]] || fail "gc dry-run deleted orphaned WIT blob"
  run_cli gc --force > "$ARTIFACTS/cli-gc-force.txt"
  [[ ! -f "$ASTRID_HOME/wit/e2e-orphan.wit" ]] || fail "gc --force kept orphaned WIT blob"
  assert_cli_exit_contains "cli-distro-show" 2 "is not yet wired" distro show
  run_cli completions bash > "$ARTIFACTS/cli-completions-bash.txt"
  grep -q "_astrid" "$ARTIFACTS/cli-completions-bash.txt" || fail "bash completions missed _astrid function"
  run_cli keypair generate --name e2e-cli-key --force --raw > "$ARTIFACTS/cli-keypair-generated.pub"
  run_cli keypair list --json > "$ARTIFACTS/cli-keypair-list.json"
  json_assert_cli_keypair_list "$ARTIFACTS/cli-keypair-list.json" e2e-cli-key
  run_cli keypair show e2e-cli-key > "$ARTIFACTS/cli-keypair-show.txt"
  grep -q "public key (hex):" "$ARTIFACTS/cli-keypair-show.txt" || fail "keypair show missed public key"
  run_cli keypair pubkey e2e-cli-key > "$ARTIFACTS/cli-keypair-pubkey.txt"
  json_assert_cli_keypair_pubkey "$ARTIFACTS/cli-keypair-pubkey.txt"
  run_cli keypair delete e2e-cli-key --yes
  if run_cli keypair show e2e-cli-key > "$ARTIFACTS/cli-keypair-show-after-delete.txt"; then
    fail "deleted keypair e2e-cli-key remained visible"
  fi
  pair_token="$("$CORE_DIR/target/debug/astrid" pair-device issue --scope use-only \
    --label e2e-cli-pair --expires-secs 120 --raw 2>> "$ARTIFACTS/cli-transcript.log")"
  printf '$ astrid pair-device issue --scope use-only --label e2e-cli-pair --expires-secs 120 --raw\n<redacted pair token>\n' \
    >> "$ARTIFACTS/cli-transcript.log"
  pair_pubkey="$("$PYTHON" - <<'PY'
import secrets
print(secrets.token_hex(32))
PY
)"
  status="$(http_status POST /api/auth/pair-device/redeem "" \
    "{\"token\":\"$pair_token\",\"public_key\":\"$pair_pubkey\"}" \
    "$ARTIFACTS/cli-pair-device-redeem.json")"
  assert_status "CLI-issued pair token redeem" "$status" 200
  pair_key_id="$(json_field "$ARTIFACTS/cli-pair-device-redeem.json" key_id)"
  run_cli pair-device list --agent default --json > "$ARTIFACTS/cli-pair-device-list.json"
  json_assert_pair_device_list "$ARTIFACTS/cli-pair-device-list.json" "$pair_key_id" present
  run_cli pair-device revoke "$pair_key_id" --agent default
  run_cli pair-device list --agent default --json > "$ARTIFACTS/cli-pair-device-list-after-revoke.json"
  json_assert_pair_device_list "$ARTIFACTS/cli-pair-device-list-after-revoke.json" "$pair_key_id" absent

  run_cli capsule show astrid-capsule-openai-compat --format json \
    > "$ARTIFACTS/cli-capsule-show-openai-user.json"
  json_assert_cli_capsule_show "$ARTIFACTS/cli-capsule-show-openai-user.json" astrid-capsule-openai-compat
  run_cli capsule list > "$ARTIFACTS/cli-capsule-list.txt"
  grep -q "astrid-capsule-openai-compat" "$ARTIFACTS/cli-capsule-list.txt" || fail "capsule list missed openai-compat"
  run_cli capsule config astrid-capsule-openai-compat --agent "$user_principal" --show --format json \
    > "$ARTIFACTS/cli-capsule-config-openai-user.json"
  json_assert_cli_capsule_config "$ARTIFACTS/cli-capsule-config-openai-user.json" fake-slow
  run_cli logs --lines 1 > "$ARTIFACTS/cli-logs.txt"
  [[ -s "$ARTIFACTS/cli-logs.txt" ]] || fail "logs did not emit daemon log tail"
  run_cli ps --format json > "$ARTIFACTS/cli-ps.json"
  json_assert_cli_capsule_rows "$ARTIFACTS/cli-ps.json" astrid-capsule-openai-compat
  run_cli who --format json > "$ARTIFACTS/cli-who.json"
  json_assert_cli_connections "$ARTIFACTS/cli-who.json"
  run_cli top > "$ARTIFACTS/cli-top.txt"
  grep -q "one-shot snapshot" "$ARTIFACTS/cli-top.txt" || fail "top did not emit bounded snapshot header"

  run_cli version --format json > "$ARTIFACTS/cli-version.json"
  json_assert_cli_version "$ARTIFACTS/cli-version.json"
  run_cli config show --format json > "$ARTIFACTS/cli-config-show.json"
  json_assert_cli_config_show "$ARTIFACTS/cli-config-show.json"
  run_cli config path > "$ARTIFACTS/cli-config-path.txt"
  grep -q "$ASTRID_HOME" "$ARTIFACTS/cli-config-path.txt" || fail "config path did not include ASTRID_HOME"
  run_cli status > "$ARTIFACTS/cli-status.txt"
  grep -q "Astrid daemon" "$ARTIFACTS/cli-status.txt" || fail "status did not report running daemon"
  printf '$ astrid doctor\n' >> "$ARTIFACTS/cli-transcript.log"
  "$CORE_DIR/target/debug/astrid" doctor > "$ARTIFACTS/cli-doctor.txt" \
    2> >(tee -a "$ARTIFACTS/cli-transcript.log" >&2) || true
  sed -n '1,120p' "$ARTIFACTS/cli-doctor.txt" >> "$ARTIFACTS/cli-transcript.log"
  grep -q "ASTRID_HOME" "$ARTIFACTS/cli-doctor.txt" || fail "doctor did not inspect ASTRID_HOME"
  printf '$ ASTRID_HOME=relative-home astrid doctor --no-daemon\n' >> "$ARTIFACTS/cli-transcript.log"
  set +e
  env ASTRID_HOME=relative-home HOME="$POISON_HOME" "$CORE_DIR/target/debug/astrid" doctor --no-daemon \
    > "$ARTIFACTS/cli-doctor-relative-home.out" \
    2> "$ARTIFACTS/cli-doctor-relative-home.err"
  status=$?
  set -e
  tee -a "$ARTIFACTS/cli-transcript.log" < "$ARTIFACTS/cli-doctor-relative-home.out"
  tee -a "$ARTIFACTS/cli-transcript.log" < "$ARTIFACTS/cli-doctor-relative-home.err" >&2
  [[ "$status" -eq 1 ]] || fail "doctor relative ASTRID_HOME expected exit 1, got $status"
  grep -Fq "ASTRID_HOME must be an absolute path" \
    "$ARTIFACTS/cli-doctor-relative-home.out" \
    "$ARTIFACTS/cli-doctor-relative-home.err" \
    || fail "doctor relative ASTRID_HOME missed bounded diagnostic"
  run_cli_stdin_timeout "cli-chat-eof" 20 --format json chat
  grep -q "Goodbye" "$ARTIFACTS/cli-chat-eof.out" || fail "chat EOF path did not exit cleanly"
  run_cli_mcp_stdio_smoke "cli-mcp-serve-handshake" 20 --principal anonymous mcp serve
  run_cli_daemon_lifecycle_smoke
}

run_cli_offline_init_smoke() {
  local registry_archive=$1
  local home="$ARTIFACTS/cli-init-home"
  local cwd="$ARTIFACTS/cli-init-cwd"
  local distro="$ARTIFACTS/cli-init-distro.toml"
  mkdir -p "$home/etc" "$cwd"
  cat > "$distro" <<EOF
schema-version = 1

[distro]
id = "e2e"
name = "E2E"
version = "0.1.0"

[[capsule]]
name = "astrid-capsule-registry"
source = "$registry_archive"
version = "0.8.0"
role = "uplink"
EOF
  run_isolated_cli "$home" "$cwd" init --distro "$distro" --offline --yes --allow-unsigned \
    > "$ARTIFACTS/cli-init-offline.txt" 2>&1
  grep -Eq "Installation complete|Installed [0-9]+ capsule" "$ARTIFACTS/cli-init-offline.txt" \
    || fail "offline init did not complete"
  [[ -f "$home/home/default/.config/distro.lock" ]] || fail "offline init did not write Distro.lock"
  [[ -f "$home/home/default/.local/capsules/astrid-capsule-registry/meta.json" ]] \
    || fail "offline init did not install registry capsule metadata"
}

run_cli_distro_seal_smoke() {
  local registry_archive=$1
  local distro_dir="$ARTIFACTS/cli-distro-seal"
  local key="$distro_dir/signing.key"
  mkdir -p "$distro_dir"
  cat > "$distro_dir/Distro.toml" <<EOF
schema-version = 1

[distro]
id = "e2e-seal"
name = "E2E Seal"
version = "0.1.0"

[[capsule]]
name = "astrid-capsule-registry"
source = "$registry_archive"
version = "0.8.0"
role = "uplink"
EOF
  "$PYTHON" - "$key" <<'PY'
import sys
open(sys.argv[1], "wb").write(bytes(range(32)))
PY
  assert_cli_exit_contains "cli-distro-seal-local-source" 1 \
    "seal can only resolve GitHub-backed capsule sources" \
    distro seal "$distro_dir/Distro.toml" --output "$distro_dir/e2e.shuttle" --key "$key"
}

run_cli_daemon_lifecycle_smoke() {
  run_cli start > "$ARTIFACTS/cli-daemon-start-already-running.txt"
  grep -q "already running" "$ARTIFACTS/cli-daemon-start-already-running.txt" \
    || fail "daemon start did not report existing running daemon"
  run_cli status > "$ARTIFACTS/cli-daemon-status.txt"
  grep -q "Astrid daemon" "$ARTIFACTS/cli-daemon-status.txt" \
    || fail "daemon status missed running daemon"
}

run_isolated_cli() {
  local home=$1 cwd=$2
  shift 2
  printf '$ ASTRID_HOME=%s astrid %s\n' "$home" "$*" >> "$ARTIFACTS/cli-transcript.log"
  (
    cd "$cwd"
    env ASTRID_HOME="$home" HOME="$POISON_HOME" "$CORE_DIR/target/debug/astrid" "$@" < /dev/null
  ) > >(tee -a "$ARTIFACTS/cli-transcript.log") \
    2> >(tee -a "$ARTIFACTS/cli-transcript.log" >&2)
}

run_cli_stdin_timeout() {
  local label=$1 timeout=$2
  shift 2
  printf '$ astrid %s < /dev/null\n' "$*" >> "$ARTIFACTS/cli-transcript.log"
  "$PYTHON" - "$CORE_DIR/target/debug/astrid" "$ARTIFACTS/$label.out" \
    "$ARTIFACTS/$label.err" "$timeout" "$@" <<'PY'
import os
import subprocess
import sys

binary, stdout_path, stderr_path, timeout_s, *args = sys.argv[1:]
with open(stdout_path, "wb") as stdout, open(stderr_path, "wb") as stderr:
    try:
        proc = subprocess.run(
            [binary, *args],
            input=b"",
            stdout=stdout,
            stderr=stderr,
            timeout=float(timeout_s),
            env=os.environ.copy(),
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise SystemExit(f"command timed out after {timeout_s}s: {args!r}") from exc
if proc.returncode != 0:
    raise SystemExit(f"command returned {proc.returncode}: {args!r}")
PY
  tee -a "$ARTIFACTS/cli-transcript.log" < "$ARTIFACTS/$label.out"
  tee -a "$ARTIFACTS/cli-transcript.log" < "$ARTIFACTS/$label.err" >&2
}

run_cli_mcp_stdio_smoke() {
  local label=$1 timeout=$2
  shift 2
  printf '$ astrid %s < fake MCP initialize/initialized\n' "$*" >> "$ARTIFACTS/cli-transcript.log"
  "$PYTHON" - "$CORE_DIR/target/debug/astrid" "$ARTIFACTS/$label.out" \
    "$ARTIFACTS/$label.err" "$timeout" "$@" <<'PY'
import json
import os
import subprocess
import sys

binary, stdout_path, stderr_path, timeout_s, *args = sys.argv[1:]
frames = [
    {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "astrid-runtime-e2e", "version": "0"},
        },
    },
    {"jsonrpc": "2.0", "method": "notifications/initialized"},
]
stdin = "".join(json.dumps(frame, separators=(",", ":")) + "\n" for frame in frames)
try:
    proc = subprocess.run(
        [binary, *args],
        input=stdin.encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=float(timeout_s),
        env=os.environ.copy(),
        check=False,
    )
except subprocess.TimeoutExpired as exc:
    raise SystemExit(f"command timed out after {timeout_s}s: {args!r}") from exc

open(stdout_path, "wb").write(proc.stdout)
open(stderr_path, "wb").write(proc.stderr)

if proc.returncode != 0:
    raise SystemExit(f"command returned {proc.returncode}: {args!r}")

messages = []
for raw in proc.stdout.splitlines():
    if raw.strip():
        messages.append(json.loads(raw))
init = next((msg for msg in messages if msg.get("id") == 1), None)
if not init or "result" not in init:
    raise SystemExit(f"MCP initialize response missing from stdout: {messages!r}")
tools = init["result"].get("capabilities", {}).get("tools")
if not isinstance(tools, dict):
    raise SystemExit(f"MCP initialize response missing tools capability: {init!r}")
PY
  tee -a "$ARTIFACTS/cli-transcript.log" < "$ARTIFACTS/$label.out"
  tee -a "$ARTIFACTS/cli-transcript.log" < "$ARTIFACTS/$label.err" >&2
}

assert_cli_deferred() {
  local label=$1 feature=$2 stdout stderr status
  shift 2
  stdout="$ARTIFACTS/$label.out"
  stderr="$ARTIFACTS/$label.err"
  printf '$ astrid %s\n' "$*" >> "$ARTIFACTS/cli-transcript.log"
  set +e
  "$CORE_DIR/target/debug/astrid" "$@" >"$stdout" 2>"$stderr"
  status=$?
  set -e
  tee -a "$ARTIFACTS/cli-transcript.log" < "$stdout"
  tee -a "$ARTIFACTS/cli-transcript.log" < "$stderr" >&2
  if [[ "$status" -ne 2 ]]; then
    fail "$label expected deferred exit 2, got $status"
  fi
  grep -Fq "astrid: $feature is not available in this release." "$stderr" \
    || fail "$label missed deferred feature message"
  grep -Fq "Tracking issue" "$stderr" \
    || fail "$label missed tracking issue reference"
}

assert_cli_exit_contains() {
  local label=$1 want=$2 needle=$3 stdout stderr status
  shift 3
  stdout="$ARTIFACTS/$label.out"
  stderr="$ARTIFACTS/$label.err"
  printf '$ astrid %s\n' "$*" >> "$ARTIFACTS/cli-transcript.log"
  set +e
  "$CORE_DIR/target/debug/astrid" "$@" >"$stdout" 2>"$stderr"
  status=$?
  set -e
  tee -a "$ARTIFACTS/cli-transcript.log" < "$stdout"
  tee -a "$ARTIFACTS/cli-transcript.log" < "$stderr" >&2
  if [[ "$status" -ne "$want" ]]; then
    fail "$label expected exit $want, got $status"
  fi
  if ! grep -Fq "$needle" "$stdout" "$stderr"; then
    fail "$label missed expected output: $needle"
  fi
}

assert_principal_cli_failure() {
  local principal=$1 label=$2 stdout stderr
  shift 2
  stdout="$ARTIFACTS/$label.out"
  stderr="$ARTIFACTS/$label.err"
  printf '$ astrid --principal %s %s\n' "$principal" "$*" >> "$ARTIFACTS/cli-transcript.log"
  if ! "$PYTHON" - "$stdout" "$stderr" "$CORE_DIR/target/debug/astrid" "$principal" "$@" <<'PY'
import os
import subprocess
import sys

stdout_path, stderr_path, binary, principal, *args = sys.argv[1:]
with open(stdout_path, "wb") as stdout, open(stderr_path, "wb") as stderr:
    env = os.environ.copy()
    env["ASTRID_PRINCIPAL"] = principal
    proc = subprocess.run(
        [binary, "--principal", principal, *args],
        stdin=subprocess.DEVNULL,
        stdout=stdout,
        stderr=stderr,
        env=env,
        check=False,
    )
raise SystemExit(0 if proc.returncode != 0 else 1)
PY
  then
    tee -a "$ARTIFACTS/cli-transcript.log" < "$stdout"
    tee -a "$ARTIFACTS/cli-transcript.log" < "$stderr" >&2
    fail "$label unexpectedly succeeded"
  fi
  tee -a "$ARTIFACTS/cli-transcript.log" < "$stdout"
  tee -a "$ARTIFACTS/cli-transcript.log" < "$stderr" >&2
  printf '✓ Expected CLI denial: %s\n' "$label" | tee -a "$ARTIFACTS/cli-transcript.log"
  return 0
}

json_assert_cli_agent_list() {
  local file=$1 user=$2 ops=$3
  "$PYTHON" - "$file" "$user" "$ops" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
principals = {entry.get("principal"): entry for entry in data}
for principal in sys.argv[2:]:
    entry = principals.get(principal)
    if not entry:
        raise SystemExit(f"missing principal {principal!r}: {list(principals)}")
    if entry.get("enabled") is not True:
        raise SystemExit(f"principal {principal!r} not enabled: {entry!r}")
PY
}

json_assert_cli_agent_show() {
  local file=$1 principal=$2 group=$3
  "$PYTHON" - "$file" "$principal" "$group" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
if data.get("principal") != sys.argv[2]:
    raise SystemExit(f"unexpected principal: {data!r}")
if sys.argv[3] not in data.get("groups", []):
    raise SystemExit(f"missing expected group {sys.argv[3]!r}: {data!r}")
PY
}

json_assert_cli_agent_enabled() {
  local file=$1 principal=$2 enabled=$3
  "$PYTHON" - "$file" "$principal" "$enabled" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
want = sys.argv[3].lower() == "true"
if data.get("principal") != sys.argv[2]:
    raise SystemExit(f"unexpected principal: {data!r}")
if data.get("enabled") is not want:
    raise SystemExit(f"unexpected enabled state: {data!r}")
PY
}

json_assert_cli_group() {
  local file=$1 name=$2 cap=$3
  "$PYTHON" - "$file" "$name" "$cap" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
if isinstance(data, list):
    data = next((entry for entry in data if entry.get("name") == sys.argv[2]), None)
if not data or data.get("name") != sys.argv[2]:
    raise SystemExit(f"group {sys.argv[2]!r} missing: {data!r}")
if sys.argv[3] not in data.get("capabilities", []):
    raise SystemExit(f"group missing capability {sys.argv[3]!r}: {data!r}")
PY
}

json_assert_cli_group_lacks_cap() {
  local file=$1 name=$2 cap=$3
  "$PYTHON" - "$file" "$name" "$cap" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
if isinstance(data, list):
    data = next((entry for entry in data if entry.get("name") == sys.argv[2]), None)
if not data or data.get("name") != sys.argv[2]:
    raise SystemExit(f"group {sys.argv[2]!r} missing: {data!r}")
if sys.argv[3] in data.get("capabilities", []):
    raise SystemExit(f"group still has capability {sys.argv[3]!r}: {data!r}")
PY
}

json_assert_invite_metadata() {
  local file=$1 metadata=$2 expected=$3
  "$PYTHON" - "$file" "$metadata" "$expected" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
found = any(item.get("metadata") == sys.argv[2] for item in data)
want = sys.argv[3] == "present"
if found is not want:
    raise SystemExit(f"invite metadata {sys.argv[2]!r} presence {found}, want {want}: {data!r}")
PY
}

json_assert_cli_caps_show() {
  local file=$1 principal=$2 group=$3
  "$PYTHON" - "$file" "$principal" "$group" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
if data.get("principal") != sys.argv[2]:
    raise SystemExit(f"unexpected caps principal: {data!r}")
if sys.argv[3] not in data.get("groups", []):
    raise SystemExit(f"missing caps group {sys.argv[3]!r}: {data!r}")
PY
}

json_assert_secret_absent() {
  local file=$1 capsule=$2 key=$3
  "$PYTHON" - "$file" "$capsule" "$key" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
for item in data:
    if item.get("capsule") == sys.argv[2] and item.get("key") == sys.argv[3]:
        raise SystemExit(f"secret was not deleted: {item!r}")
PY
}

json_assert_secret_present() {
  local file=$1 capsule=$2 key=$3
  "$PYTHON" - "$file" "$capsule" "$key" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
if not any(item.get("capsule") == sys.argv[2] and item.get("key") == sys.argv[3] for item in data):
    raise SystemExit(f"secret metadata entry missing for {sys.argv[2]!r}/{sys.argv[3]!r}: {data!r}")
PY
}

json_assert_cli_keypair_list() {
  local file=$1 name=$2
  "$PYTHON" - "$file" "$name" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
entry = next((item for item in data if item.get("name") == sys.argv[2]), None)
if not entry:
    raise SystemExit(f"keypair {sys.argv[2]!r} missing from list: {data!r}")
if entry.get("backend") != "file":
    raise SystemExit(f"unexpected keypair backend: {entry!r}")
if not entry.get("fingerprint"):
    raise SystemExit(f"keypair list missed fingerprint: {entry!r}")
PY
}

json_assert_pair_device_list() {
  local file=$1 key_id=$2 expected=$3
  "$PYTHON" - "$file" "$key_id" "$expected" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
found = any(item.get("key_id") == sys.argv[2] for item in data)
want = sys.argv[3] == "present"
if found is not want:
    raise SystemExit(f"pair device {sys.argv[2]!r} presence {found}, want {want}: {data!r}")
PY
}

json_assert_cli_keypair_pubkey() {
  local file=$1
  "$PYTHON" - "$file" <<'PY'
import re
import sys

text = open(sys.argv[1], encoding="utf-8").read().strip()
if not re.fullmatch(r"[0-9a-f]{64}", text):
    raise SystemExit(f"unexpected keypair public key output: {text!r}")
PY
}

json_assert_cli_quota() {
  local file=$1 principal=$2 processes=$3
  "$PYTHON" - "$file" "$principal" "$processes" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
if data.get("principal") != sys.argv[2]:
    raise SystemExit(f"unexpected quota principal: {data!r}")
if data.get("max_background_processes") != int(sys.argv[3]):
    raise SystemExit(f"unexpected process quota: {data!r}")
PY
}

json_assert_cli_capsule_show() {
  local file=$1 name=$2
  "$PYTHON" - "$file" "$name" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
if data.get("name") != sys.argv[2]:
    raise SystemExit(f"unexpected capsule: {data!r}")
manifest = data.get("manifest", "")
if 'name = "astrid-capsule-openai-compat"' not in manifest:
    raise SystemExit("capsule manifest body missing package identity")
PY
}

json_assert_cli_capsule_config() {
  local file=$1 model=$2
  "$PYTHON" - "$file" "$model" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
if data.get("model") != sys.argv[2]:
    raise SystemExit(f"unexpected capsule model config: {data!r}")
if "api_key" in data:
    raise SystemExit(f"capsule config leaked secret key metadata/value: {data!r}")
PY
}

json_assert_cli_capsule_rows() {
  local file=$1 capsule=$2
  "$PYTHON" - "$file" "$capsule" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
entry = next((item for item in data if item.get("capsule") == sys.argv[2]), None)
if not entry:
    raise SystemExit(f"capsule {sys.argv[2]!r} missing from ps rows: {data!r}")
if entry.get("state") != "ready":
    raise SystemExit(f"capsule row not ready: {entry!r}")
PY
}

json_assert_cli_connections() {
  local file=$1
  "$PYTHON" - "$file" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
if not isinstance(data, list):
    raise SystemExit(f"who output is not a list: {data!r}")
if not data:
    raise SystemExit("who output had no live CLI connection rows")
for item in data:
    if not item.get("agent") or item.get("platform") != "cli":
        raise SystemExit(f"unexpected who row: {item!r}")
PY
}

json_assert_cli_version() {
  local file=$1
  "$PYTHON" - "$file" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
for key in ("version", "commit", "target"):
    if not data.get(key):
        raise SystemExit(f"version output missing {key}: {data!r}")
PY
}

json_assert_cli_config_show() {
  local file=$1
  "$PYTHON" - "$file" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
if not isinstance(data, dict):
    raise SystemExit(f"config output is not an object: {data!r}")
if "security" not in data:
    raise SystemExit(f"config output missing security section: {data!r}")
PY
}
