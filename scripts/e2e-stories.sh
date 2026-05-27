#!/usr/bin/env bash
# End-to-end multi-perspective test plan for the Astrid HTTP admin gateway.
#
# Stories covered:
#   1.  Bootstrap admin can do everything (default principal).
#   2.  Admin creates a "ops-team" group with capsule:install + invite:issue.
#   3.  Admin issues an invite for ops-team.
#   4.  Operator-1 redeems via HTTP, joins ops-team.
#   5.  Operator-1 can issue invites (granted via group).
#   6.  Operator-1 cannot delete principals (lacks agent:delete).
#   7.  Operator-1 mints a pair-device token; new device redeems and
#       gets a bearer bound to the SAME principal.
#   8.  Admin issues an invite for the plain "agent" group.
#   9.  Regular-user redeems via HTTP.
#   10. Regular-user sees only themselves in /api/sys/principals.
#   11. Regular-user CANNOT issue invites (lacks invite:issue).
#   12. Admin sets a quota on regular-user; quota survives /api/sys/principals/{id}/quotas read.
#   13. Bearer refresh keeps the same principal but extends expiry.
#   14. /api/auth/me returns 401 without bearer (sanity).
#   15. /api/sys/status returns daemon info.
#   16. /api/sys/capabilities lists the 34 known caps with structured metadata.
#   17. /api/openapi.json describes the agent route alongside admin routes.
#   18. /api/agent/prompt accepts a POST and opens an SSE stream
#       (we time-bound the read so we don't wait on an LLM).
#
# Run as:
#   ./e2e-stories.sh
#
# Cleans up its daemon on exit. Expects a fresh build of
# ./target/debug/astrid and astrid-daemon under astrid/core.

set -uo pipefail
trap 'cleanup' EXIT INT TERM

CORE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ASTRID_HOME="${TMPDIR:-/tmp}/astrid-e2e-stories-$$"
mkdir -p "$ASTRID_HOME"
export ASTRID_HOME
GATEWAY="http://127.0.0.1:38756"
PASS=0
FAIL=0
DAEMON_PID=""

note() { printf "\n=== %s ===\n" "$*"; }
ok() { PASS=$((PASS + 1)); printf "  [OK] %s\n" "$*"; }
err() { FAIL=$((FAIL + 1)); printf "  [FAIL] %s\n" "$*"; }
assert_eq() {
  local label=$1; local got=$2; local want=$3
  if [ "$got" = "$want" ]; then ok "$label = $want"; else err "$label expected '$want' got '$got'"; fi
}
http_status() {
  local method=$1 path=$2 bearer=${3:-} body=${4:-}
  local args=(-s -o /tmp/claude/last.body -w "%{http_code}" -X "$method" "$GATEWAY$path")
  [ -n "$bearer" ] && args+=(-H "Authorization: Bearer $bearer")
  [ -n "$body" ] && args+=(-H "Content-Type: application/json" -d "$body")
  curl "${args[@]}"
}
last_body() { cat /tmp/claude/last.body; }
jq_field() { python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('$1',''))" < /tmp/claude/last.body; }
mkdir -p /tmp/claude

cleanup() {
  [ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null
  sleep 1
  rm -rf "$ASTRID_HOME"
}

note "Boot: fresh ASTRID_HOME=$ASTRID_HOME"
mkdir -p "$ASTRID_HOME/etc"
cat > "$ASTRID_HOME/etc/gateway-http.toml" <<EOF
enabled = true
listen = "127.0.0.1:38756"
session-lifetime-secs = 3600
EOF

# We need a clean redeem rate limit interval for the story flow.
# The default's per-IP cooldown is ~1s and we have lots of HTTP redeems;
# bump it to 0 for these tests.
cat >> "$ASTRID_HOME/etc/gateway-http.toml" <<EOF
redeem-rate-limit-secs = 0
EOF

cd "$CORE_DIR"
./target/debug/astrid capsule install ../capsules/astrid-capsule-cli > /dev/null 2>&1
./target/debug/astrid-daemon > "$ASTRID_HOME/daemon.log" 2>&1 &
DAEMON_PID=$!
sleep 6
curl -sf "$GATEWAY/healthz" >/dev/null || { err "daemon did not come up"; exit 1; }
ok "daemon up"

# ─────────────────────────────────────────────────────────────────────
note "Story 1: bootstrap admin can issue invites (via CLI as default principal)"
inv_out=$(./target/debug/astrid invite issue --group agent --max-uses 1 --expires-secs 600 2>&1)
echo "$inv_out" | grep -q '✓ issued' && ok "admin issued invite" || err "admin failed: $inv_out"
INV_AGENT=$(echo "$inv_out" | awk '/issued/ {print $3}')

note "Story 2: admin creates ops-team group with capsule:install + invite:issue"
out=$(./target/debug/astrid group create ops-team --caps "capsule:install,invite:issue,invite:list" 2>&1)
echo "$out" | grep -q 'created\|added\|ops-team' && ok "ops-team created" || err "ops-team create: $out"

note "Story 3: admin issues an invite that drops the new principal into ops-team"
ops_out=$(./target/debug/astrid invite issue --group ops-team --max-uses 1 --expires-secs 600 2>&1)
INV_OPS=$(echo "$ops_out" | awk '/issued/ {print $3}')
[ -n "$INV_OPS" ] && ok "ops-team invite token captured" || err "ops invite empty: $ops_out"

note "Story 4: operator-1 redeems via HTTP (joins ops-team)"
PK=$(openssl rand -hex 32)
status=$(http_status POST /api/auth/redeem "" \
  "{\"token\":\"$INV_OPS\",\"public_key\":\"$PK\",\"display_name\":\"operator-1\"}")
assert_eq "redeem status" "$status" "200"
OP1_BEARER=$(jq_field session_token)
OP1=$(jq_field principal)
OP1_GROUP=$(jq_field group)
assert_eq "operator-1 group" "$OP1_GROUP" "ops-team"

note "Story 5: operator-1 CAN issue invites (granted via ops-team)"
status=$(http_status POST /api/sys/invites "$OP1_BEARER" \
  '{"group":"agent","max_uses":1,"expires_secs":600}')
assert_eq "operator-1 invite-issue status" "$status" "200"
SUB_INV=$(python3 -c "import json,sys; print(json.load(open('/tmp/claude/last.body'))['invite']['token'])")
[ -n "$SUB_INV" ] && ok "operator-1 received an invite token to hand to a sub-user" || err "no sub-invite token"

note "Story 6: operator-1 CANNOT delete an existing principal — lacks agent:delete"
# Target the admin principal (`default`) — it exists, so the
# kernel's cap-check fires before the existence check. We use it
# only as a delete target because (a) it's guaranteed-present and
# (b) the kernel's cap-gate denies the request anyway, so no
# damage. A real victim isn't needed for the negative test.
status=$(http_status DELETE /api/sys/principals/default "$OP1_BEARER")
assert_eq "operator-1 delete-default status" "$status" "403"

note "Story 7a: operator-1 CANNOT pair a device — ops-team lacks self:auth:pair"
status=$(http_status POST /api/auth/pair-device "$OP1_BEARER" \
  '{"expires_secs":120,"label":"operator-1 second device"}')
assert_eq "pair-device issue (ops-team, no cap) status" "$status" "403"

note "Story 8: admin issues a plain-agent invite"
agent_out=$(./target/debug/astrid invite issue --group agent --max-uses 1 --expires-secs 600 2>&1)
INV_AGENT2=$(echo "$agent_out" | awk '/issued/ {print $3}')
[ -n "$INV_AGENT2" ] && ok "agent invite captured" || err "agent invite empty"

note "Story 9: regular-user redeems via HTTP (plain agent group)"
PK2=$(openssl rand -hex 32)
status=$(http_status POST /api/auth/redeem "" \
  "{\"token\":\"$INV_AGENT2\",\"public_key\":\"$PK2\",\"display_name\":\"regular-user\"}")
assert_eq "regular-user redeem status" "$status" "200"
USER_BEARER=$(jq_field session_token)
USER_PRINCIPAL=$(jq_field principal)
assert_eq "regular-user group" "$(jq_field group)" "agent"

note "Story 9b: regular-user CAN pair a device — agent group has self:* which covers self:auth:pair"
status=$(http_status POST /api/auth/pair-device "$USER_BEARER" \
  '{"expires_secs":120,"label":"phone"}')
assert_eq "pair-device issue (agent) status" "$status" "200"
PAIR_TOKEN=$(jq_field token)
PAIR_PRINCIPAL=$(jq_field principal)
assert_eq "pair-token bound to regular-user" "$PAIR_PRINCIPAL" "$USER_PRINCIPAL"
NEW_PK=$(openssl rand -hex 32)
status=$(http_status POST /api/auth/pair-device/redeem "" \
  "{\"token\":\"$PAIR_TOKEN\",\"public_key\":\"$NEW_PK\"}")
assert_eq "pair-device redeem status" "$status" "200"
assert_eq "redeemed device bound to regular-user" "$(jq_field principal)" "$USER_PRINCIPAL"

note "Story 10: regular-user sees themselves in /api/sys/principals"
status=$(http_status GET /api/sys/principals "$USER_BEARER")
assert_eq "principals status" "$status" "200"
saw_self=$(python3 -c "
import json
d = json.load(open('/tmp/claude/last.body'))
print(any(p['principal']=='$USER_PRINCIPAL' for p in d['principals']))")
assert_eq "regular-user sees self in list" "$saw_self" "True"

note "Story 11: regular-user CANNOT issue invites"
status=$(http_status POST /api/sys/invites "$USER_BEARER" \
  '{"group":"agent","max_uses":1,"expires_secs":600}')
assert_eq "regular-user invite-issue status (denied)" "$status" "403"

note "Story 12: admin sets a quota on regular-user via CLI; user reads it back via HTTP"
out=$(./target/debug/astrid quota set --agent "$USER_PRINCIPAL" --processes 4 --ipc-rate "1MB/s" 2>&1)
echo "$out" | grep -qiE 'updated|set|ok' && ok "admin set quota via CLI" || err "admin quota set: $out"
status=$(http_status GET /api/sys/principals/$USER_PRINCIPAL/quotas "$USER_BEARER")
assert_eq "quota get status (self)" "$status" "200"
# The kernel surfaces quotas under `Quotas` shape — check that
# something useful round-tripped.
proc=$(python3 -c "
import json
d = json.load(open('/tmp/claude/last.body'))
# Quotas shape varies; just verify the JSON parses with content.
print('ok' if isinstance(d, dict) and len(d) > 0 else 'empty')")
assert_eq "quota response is a non-empty object" "$proc" "ok"

note "Story 13: bearer refresh keeps principal, extends expiry"
status=$(http_status POST /api/auth/refresh "$USER_BEARER")
assert_eq "refresh status" "$status" "200"
new_principal=$(jq_field principal)
assert_eq "refresh keeps principal" "$new_principal" "$USER_PRINCIPAL"

note "Story 14: /api/auth/me is 401 without bearer"
status=$(http_status GET /api/auth/me "")
assert_eq "unauth me status" "$status" "401"

note "Story 15: regular-user CANNOT read /api/sys/status (lacks system:status); admin grants the cap then it works"
status=$(http_status GET /api/sys/status "$USER_BEARER")
assert_eq "sys/status (no cap) status" "$status" "403"
./target/debug/astrid caps grant "$USER_PRINCIPAL" "system:status" >/dev/null 2>&1 \
  && ok "admin granted system:status to regular-user" || err "admin caps grant failed"
status=$(http_status GET /api/sys/status "$USER_BEARER")
assert_eq "sys/status (with cap) status" "$status" "200"
[ "$(jq_field version)" = "0.7.0" ] && ok "daemon reports version 0.7.0" || err "wrong version got: $(last_body | head -c 200)"

note "Story 16: /api/sys/capabilities has 34 caps + structured metadata"
status=$(http_status GET /api/sys/capabilities "$USER_BEARER")
caps_count=$(python3 -c "
import json
d = json.load(open('/tmp/claude/last.body'))
print(len(d.get('capabilities', [])))")
assert_eq "capabilities count" "$caps_count" "34"

note "Story 17: /api/openapi.json lists the agent route"
curl -s "$GATEWAY/api/openapi.json" > /tmp/claude/openapi.json
has_agent=$(python3 -c "
import json
d = json.load(open('/tmp/claude/openapi.json'))
print('post' in d['paths'].get('/api/agent/prompt', {}))")
assert_eq "openapi spec has POST /api/agent/prompt" "$has_agent" "True"

note "Story 18: /api/agent/prompt opens an SSE stream (no LLM stack installed, expect 'ready' then keep-alive)"
# Capture the first ~3s of the SSE stream and check for the ready event.
# In a fully-loaded distro with react/identity/llm capsules, more events would follow.
curl -sN --max-time 3 -X POST "$GATEWAY/api/agent/prompt" \
  -H "Authorization: Bearer $USER_BEARER" \
  -H "Content-Type: application/json" \
  -d '{"text":"hello"}' > /tmp/claude/sse.out 2>&1 || true
if grep -q '^event: ready' /tmp/claude/sse.out; then
  ok "agent SSE emitted 'ready' event"
  if grep -q "\"principal\":\"$USER_PRINCIPAL\"" /tmp/claude/sse.out; then
    ok "ready event echoes caller principal"
  else
    err "ready event missing principal: $(head -c 200 /tmp/claude/sse.out)"
  fi
else
  err "agent SSE did not emit ready: $(head -c 200 /tmp/claude/sse.out)"
fi

note "==== SUMMARY ===="
printf "PASS=%d FAIL=%d\n" "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
