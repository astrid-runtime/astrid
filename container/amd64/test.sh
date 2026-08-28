#!/usr/bin/env bash
set -euo pipefail

IMAGE=${1:?usage: container/amd64/test.sh IMAGE CLI_UPLINK_CAPSULE}
CLI_UPLINK_CAPSULE=${2:?usage: container/amd64/test.sh IMAGE CLI_UPLINK_CAPSULE}
OCI_PLATFORM=${ASTRID_OCI_TEST_PLATFORM:-linux/amd64}
OCI_ARCHITECTURE=${ASTRID_OCI_TEST_ARCHITECTURE:-amd64}
OCI_TEST_LABEL=${ASTRID_OCI_TEST_LABEL:-amd64}
PYTHON=${PYTHON:-python3}
TEST_ROOT=$(mktemp -d)
TEST_BASE_IMAGE="astrid-oci-bound-base:${RANDOM}-${RANDOM}"
TEST_IMAGE="astrid-oci-entrypoint-test:${RANDOM}-${RANDOM}"
TEST_SWAP_IMAGE="astrid-oci-swap-test:${RANDOM}-${RANDOM}"
REAL_CONTAINER=
FIRST_REAL_CONTAINER=

cleanup() {
  if [[ -n "$REAL_CONTAINER" ]]; then
    docker rm --force "$REAL_CONTAINER" >/dev/null 2>&1 || true
  fi
  # The real runtime deliberately creates 0700 state as uid 65532. Restore
  # access only inside this mktemp tree so the unprivileged runner can remove
  # its own test fixture.
  docker run --rm \
    --user 0:0 \
    --entrypoint /bin/sh \
    --mount "type=bind,src=$TEST_ROOT,dst=/cleanup" \
    "$IMAGE" \
    -c 'chmod -R a+rwX /cleanup' >/dev/null 2>&1 || true
  docker image rm --force "$TEST_BASE_IMAGE" >/dev/null 2>&1 || true
  docker image rm --force "$TEST_IMAGE" >/dev/null 2>&1 || true
  docker image rm --force "$TEST_SWAP_IMAGE" >/dev/null 2>&1 || true
  rm -rf "$TEST_ROOT"
}
trap cleanup EXIT

fail() {
  echo "oci $OCI_TEST_LABEL test: $*" >&2
  exit 1
}

parse_proc_status_field() {
  local status_file=$1
  local field=$2
  awk -v field="$field" '$1 == field ":" { print $2; exit }' "$status_file"
}

prepare_runtime_dir() {
  local directory=$1
  local mode=${2:-0700}
  mkdir -p "$directory"
  # Astrid secures ASTRID_HOME itself with chmod(0700), so a bind mount that
  # is merely world-writable is insufficient on Linux: uid 65532 must own the
  # mount root. Use the already-authenticated image as a local ownership
  # helper instead of requiring privileged host commands.
  docker run --rm \
    --user 0:0 \
    --entrypoint /bin/sh \
    --mount "type=bind,src=$directory,dst=/runtime" \
    "$IMAGE" \
    -ec 'chown 65532:65532 /runtime; chmod "$1" /runtime' \
    sh "$mode"
}

runtime_path_is_symlink() {
  local directory=$1
  local relative=$2
  # ASTRID_HOME is deliberately 0700 and owned by uid 65532, so the
  # unprivileged host runner cannot inspect a child directly. Inspect through
  # a short-lived root helper with the bind mounted read-only.
  docker run --rm \
    --platform "$OCI_PLATFORM" \
    --user 0:0 \
    --entrypoint /bin/sh \
    --mount "type=bind,src=$directory,dst=/runtime,readonly" \
    "$IMAGE" \
    -ec 'test -L "/runtime/$1"' \
    sh "$relative"
}

write_runtime_workspace_marker() {
  local directory=$1
  docker run --rm \
    --platform "$OCI_PLATFORM" \
    --user 65532:65532 \
    --entrypoint /bin/sh \
    --mount "type=bind,src=$directory,dst=/workspace" \
    "$IMAGE" \
    -ec 'printf "%s\n" "$1" > "$2"' \
    sh same-mounted-workspace "/workspace/.astrid-oci-mounted-state"
}

start_real_runtime() {
  local state_dir=$1
  local workspace_dir=$2
  REAL_CONTAINER=$(docker run --detach \
    --platform "$OCI_PLATFORM" \
    --read-only \
    --cap-drop=ALL \
    --security-opt=no-new-privileges \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m,uid=65532,gid=65532 \
    --mount "type=bind,src=$TEST_ROOT/fixtures/distro.shuttle,dst=/run/astrid/distro.shuttle,readonly" \
    --mount "type=bind,src=$state_dir,dst=/var/lib/astrid" \
    --mount "type=bind,src=$workspace_dir,dst=/workspace" \
    --env "ASTRID_DISTRO_SHA256=$distro_sha256" \
    "$IMAGE")

}

stop_real_runtime() {
  docker stop --time 10 "$REAL_CONTAINER" >/dev/null
  docker rm "$REAL_CONTAINER" >/dev/null
  REAL_CONTAINER=
}

wait_real_runtime() {
  local label=${1:-real}
  local release_ready=false
  for _ in $(seq 1 120); do
    if [[ "$(docker inspect "$REAL_CONTAINER" --format '{{.State.Running}}')" != true ]]; then
      break
    fi
    if docker exec "$REAL_CONTAINER" test -f /var/lib/astrid/run/system.ready &&
      docker exec "$REAL_CONTAINER" /usr/local/bin/astrid status \
        >"$TEST_ROOT/$label-status.out" 2>"$TEST_ROOT/$label-status.err"; then
      release_ready=true
      break
    fi
    sleep 0.5
  done
  if [[ "$release_ready" != true ]]; then
    docker logs "$REAL_CONTAINER" >&2 || true
    cat "$TEST_ROOT/$label-status.out" >&2 2>/dev/null || true
    cat "$TEST_ROOT/$label-status.err" >&2 2>/dev/null || true
    fail "authenticated release daemon did not become ready ($label)"
  fi
  grep -q "Astrid daemon" "$TEST_ROOT/$label-status.out" ||
    fail "authenticated release daemon did not answer status ($label)"
}

assert_daemon_is_pid_one() {
  local status
  status=$(docker exec "$REAL_CONTAINER" cat /proc/1/status) ||
    fail "daemon status probe failed"
  local comm
  comm=$(docker exec "$REAL_CONTAINER" cat /proc/1/comm) ||
    fail "daemon command-name probe failed"
  local exe
  exe=$(docker exec "$REAL_CONTAINER" readlink /proc/1/exe) ||
    fail "daemon executable probe failed"
  local cwd
  cwd=$(docker exec "$REAL_CONTAINER" readlink /proc/1/cwd) ||
    fail "daemon working-directory probe failed"
  local uid
  uid=$(printf '%s\n' "$status" | parse_proc_status_field /dev/stdin Uid)
  local gid
  gid=$(printf '%s\n' "$status" | parse_proc_status_field /dev/stdin Gid)
  [ "$comm" = astrid-daemon ] ||
    { printf "comm=%s\n" "$comm" >&2; exit 1; }
    [ "$(basename "$exe")" = astrid-daemon ] ||
      { printf "exe=%s\n" "$exe" >&2; exit 1; }
  [ "$uid" = 65532 ] && [ "$gid" = 65532 ] ||
    { printf "uid=%s gid=%s\n" "$uid" "$gid" >&2; exit 1; }
  [ "$cwd" = /workspace ] ||
    { printf "cwd=%s\n" "$cwd" >&2; exit 1; }
  printf 'PID1 astrid-daemon 65532:65532 /workspace\n'
}

run_real_cli() {
  docker exec "$REAL_CONTAINER" /usr/local/bin/astrid "$@"
}

assert_real_self_list() {
  local path=$1
  local principal=$2
  "$PYTHON" - "$path" "$principal" <<'PY'
import json
import sys

path = sys.argv[1]
principal = sys.argv[2]
with open(path, encoding="utf-8") as handle:
    items = json.load(handle)
if not isinstance(items, list):
    raise SystemExit("agent list response is not an array")
names = [item.get("principal") for item in items if isinstance(item, dict)]
if names != [principal]:
    raise SystemExit(
        f"agent list did not return exactly {principal!r}: {names!r}"
    )
PY
}

assert_real_principal_identity_and_groups() {
  local alpha=$1
  local beta=$2
  "$PYTHON" - "$alpha" "$beta" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    alpha = json.load(handle)
with open(sys.argv[2], encoding="utf-8") as handle:
    beta = json.load(handle)
if alpha.get("principal") != "hosted-alpha" or beta.get("principal") != "hosted-beta":
    raise SystemExit("principal identity changed during restart")
if "restricted" not in alpha.get("groups", []):
    raise SystemExit("hosted-alpha lost its restricted capability group")
if "restricted" in beta.get("groups", []):
    raise SystemExit("hosted-beta inherited hosted-alpha's capability group")
PY
}

read_runtime_state_file() {
  local relative=$1
  local runtime_file="/runtime/$relative"
  docker run --rm \
    --platform "$OCI_PLATFORM" \
    --user 0:0 \
    --entrypoint /bin/sh \
    --mount "type=bind,src=$run_dir/real-state,dst=/runtime,readonly" \
    "$IMAGE" \
    -ec 'cat -- "$1"' \
    sh "$runtime_file"
}

assert_runtime_state_file_mode() {
  local relative=$1
  local runtime_file="/runtime/$relative"
  local mode
  mode=$(docker run --rm \
    --platform "$OCI_PLATFORM" \
    --user 0:0 \
    --entrypoint /bin/sh \
    --mount "type=bind,src=$run_dir/real-state,dst=/runtime,readonly" \
    "$IMAGE" \
    -ec 'stat -c "%a %u %g" "$1"' \
    sh "$runtime_file")
  [[ "$mode" == "600 65532 65532" ]] ||
    fail "owner state $relative has unsafe custody metadata: $mode"
}

assert_runtime_state_values() {
  local alpha=$1
  local beta=$2
  "$PYTHON" - "$alpha" "$beta" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    alpha = json.load(handle)
with open(sys.argv[2], encoding="utf-8") as handle:
    beta = json.load(handle)
if alpha.get("OCI_OWNER_STATE") != "alpha-owner-state":
    raise SystemExit("hosted-alpha owner state changed or crossed")
if beta.get("OCI_OWNER_STATE") != "beta-owner-state":
    raise SystemExit("hosted-beta owner state changed or crossed")
PY
}

run_as_principal_cli() {
  local principal=$1
  shift
  docker exec --env "ASTRID_PRINCIPAL=$principal" "$REAL_CONTAINER" \
    /usr/local/bin/astrid "$@"
}

register_v0104_audit_stderr() {
  local destination=$1

  # Registered from v0.10.4 / TEST_SOURCE_COMMIT=b6bf5d1d579915eb5d3c944857d84e62a4fcc878.
  # The stream is exactly 175 bytes, SHA-256 8af9a0342aa14e2f65a9f563a0685f8dc8f806f7eda3d2ae5fa088fe667ae8a4.
  # Any release or byte drift requires a fresh exact-release re-evaluation.
  printf '%s\n' \
    "astrid: audit trail inspection is not available in this release." \
    >"$destination"
  printf '%s\n' \
    "  Tracking issue #675 (Layer 7 audit log routing) — see https://github.com/astrid-runtime/astrid/issues/675" \
    >>"$destination"
}

assert_v0104_audit_is_non_gating() {
  local output=$1
  local error=$2
  local status=0
  local expected=$TEST_ROOT/v0104-audit-expected.stderr

  run_real_cli audit status \
    >"$output" 2>"$error" || status=$?
  if [ "$status" -eq 0 ]; then
    fail "v0.10.4 unexpectedly exposed an audit query"
  fi
  if [ "$status" -ne 2 ]; then
    printf '%s\n' "captured stderr:" >&2
    cat "$error" >&2
    fail "v0.10.4 audit stub exited $status, expected 2; re-evaluate the exact-release proof"
  fi
  register_v0104_audit_stderr "$expected"
  if ! cmp -s "$error" "$expected"; then
    printf '%s\n' "captured stderr:" >&2
    cat "$error" >&2
    fail "v0.10.4 audit stderr drifted; re-evaluate the exact-release proof"
  fi
  printf '%s\n' \
    "BLOCKED AUDIT (non-gating): v0.10.4 baseline blocker; audit is deferred and exposes no supported chain/head or principal-scoped query."
}

ARCH=$(docker image inspect "$IMAGE" --format '{{.Architecture}}')
USER=$(docker image inspect "$IMAGE" --format '{{.Config.User}}')
ENTRYPOINT=$(docker image inspect "$IMAGE" --format '{{json .Config.Entrypoint}}')
EXPOSED=$(docker image inspect "$IMAGE" --format '{{json .Config.ExposedPorts}}')

[[ "$ARCH" == "$OCI_ARCHITECTURE" ]] ||
  fail "image architecture is $ARCH, expected $OCI_ARCHITECTURE"
[[ "$USER" == 65532:65532 ]] || fail "image user is $USER, expected 65532:65532"
[[ "$ENTRYPOINT" == '["/usr/local/bin/astrid-container-entrypoint"]' ]] ||
  fail "unexpected image entrypoint: $ENTRYPOINT"
[[ "$EXPOSED" == null ]] || fail "neutral runtime image must not expose product ports"

# Docker's build frontend resolves an unqualified name@digest as a registry
# source even when that exact digest is already in the local image store.
# Create a test-only local alias from the verified digest for the two derived
# negative-test images; all real runtime probes continue to use "$IMAGE".
docker image tag "$IMAGE" "$TEST_BASE_IMAGE"

mkdir -p "$TEST_ROOT/fixtures"
chmod 0777 "$TEST_ROOT/fixtures"

# Generate a product-neutral signed shuttle containing a real CLI uplink
# capsule built from a pinned source commit. This same fixture is used for the
# release-daemon readiness probe and the deterministic entrypoint tests.
python3 scripts/create_oci_test_shuttle.py \
  --capsule "$CLI_UPLINK_CAPSULE" \
  --output "$TEST_ROOT/fixtures/distro.shuttle"

run_dir="$TEST_ROOT/run"
prepare_runtime_dir "$run_dir/real-state"
prepare_runtime_dir "$run_dir/real-workspace" 0755
write_runtime_workspace_marker "$run_dir/real-workspace"
distro_sha256=$(sha256sum "$TEST_ROOT/fixtures/distro.shuttle")
distro_sha256=${distro_sha256%% *}

# Exercise the authenticated release daemon itself. The readiness sentinel,
# authenticated CLI status round trip, direct PID 1 identity, distinct owner
# state, and same mounted workspace must survive a fresh container on the same
# state/workspace mounts.
start_real_runtime "$run_dir/real-state" "$run_dir/real-workspace"
wait_real_runtime initial
assert_daemon_is_pid_one
FIRST_REAL_CONTAINER=$REAL_CONTAINER

# Create principals and update a capability group through the authenticated
# admin CLI. Then use the release CLI's direct filesystem secret writes to
# persist distinct owner-state artifacts on the shared state mount. This is
# persistence evidence, not authenticated admin IPC or secret-read isolation.
run_real_cli agent create hosted-alpha --group agent --yes \
  >"$TEST_ROOT/alpha-create.out" 2>"$TEST_ROOT/alpha-create.err" || {
  cat "$TEST_ROOT/alpha-create.out" >&2 || true
  cat "$TEST_ROOT/alpha-create.err" >&2 || true
  fail "could not create hosted-alpha through the daemon"
}
run_real_cli agent create hosted-beta --group agent --yes \
  >"$TEST_ROOT/beta-create.out" 2>"$TEST_ROOT/beta-create.err" || {
  cat "$TEST_ROOT/beta-create.out" >&2 || true
  cat "$TEST_ROOT/beta-create.err" >&2 || true
  fail "could not create hosted-beta through the daemon"
}
run_real_cli agent modify hosted-alpha --add-group restricted \
  >"$TEST_ROOT/alpha-modify.out" 2>"$TEST_ROOT/alpha-modify.err" || {
  cat "$TEST_ROOT/alpha-modify.out" >&2 || true
  cat "$TEST_ROOT/alpha-modify.err" >&2 || true
  fail "could not update hosted-alpha capability group"
}
run_real_cli agent create hosted-restricted --group restricted --yes \
  >"$TEST_ROOT/restricted-create.out" 2>"$TEST_ROOT/restricted-create.err" || {
  cat "$TEST_ROOT/restricted-create.out" >&2 || true
  cat "$TEST_ROOT/restricted-create.err" >&2 || true
  fail "could not create the restricted denial principal"
}
run_real_cli agent show hosted-alpha --format json >"$TEST_ROOT/alpha-before.json" \
  || fail "could not inspect hosted-alpha before restart"
run_real_cli agent show hosted-beta --format json >"$TEST_ROOT/beta-before.json" \
  || fail "could not inspect hosted-beta before restart"
assert_real_principal_identity_and_groups "$TEST_ROOT/alpha-before.json" "$TEST_ROOT/beta-before.json"
run_as_principal_cli hosted-alpha agent list --format json \
  >"$TEST_ROOT/alpha-self-before.json" \
  || fail "hosted-alpha could not read its own principal row"
assert_real_self_list "$TEST_ROOT/alpha-self-before.json" hosted-alpha
run_as_principal_cli hosted-beta agent list --format json \
  >"$TEST_ROOT/beta-self-before.json" \
  || fail "hosted-beta could not read its own principal row"
assert_real_self_list "$TEST_ROOT/beta-self-before.json" hosted-beta

run_real_cli secret set OCI_OWNER_STATE alpha-owner-state --agent hosted-alpha \
  >"$TEST_ROOT/alpha-state-write.out" 2>"$TEST_ROOT/alpha-state-write.err" \
  || fail "could not write hosted-alpha owner state"
run_real_cli secret set OCI_OWNER_STATE beta-owner-state --agent hosted-beta \
  >"$TEST_ROOT/beta-state-write.out" 2>"$TEST_ROOT/beta-state-write.err" \
  || fail "could not write hosted-beta owner state"
read_runtime_state_file home/hosted-alpha/.config/env/default.env.json \
  >"$TEST_ROOT/alpha-state-before.json"
read_runtime_state_file home/hosted-beta/.config/env/default.env.json \
  >"$TEST_ROOT/beta-state-before.json"
assert_runtime_state_file_mode home/hosted-alpha/.config/env/default.env.json
assert_runtime_state_file_mode home/hosted-beta/.config/env/default.env.json
assert_runtime_state_file_mode keys/runtime.key
assert_runtime_state_values \
  "$TEST_ROOT/alpha-state-before.json" "$TEST_ROOT/beta-state-before.json"

# Stop and remove the first container before creating the successor. This is
# a fresh process and container namespace opening the same durable mounts, not
# Docker resuming or restarting the original PID 1.
stop_real_runtime
start_real_runtime "$run_dir/real-state" "$run_dir/real-workspace"
[[ -n "$FIRST_REAL_CONTAINER" && "$REAL_CONTAINER" != "$FIRST_REAL_CONTAINER" ]] ||
  fail "fresh-container reopen did not create a new container"
wait_real_runtime reopen
assert_daemon_is_pid_one
[[ "$(cat "$run_dir/real-workspace/.astrid-oci-mounted-state")" == same-mounted-workspace ]] ||
  fail "workspace mount state did not survive fresh-container reopen"
read_runtime_state_file home/hosted-alpha/.config/env/default.env.json \
  >"$TEST_ROOT/alpha-state-after.json"
read_runtime_state_file home/hosted-beta/.config/env/default.env.json \
  >"$TEST_ROOT/beta-state-after.json"
assert_runtime_state_values \
  "$TEST_ROOT/alpha-state-after.json" "$TEST_ROOT/beta-state-after.json"
run_real_cli agent show hosted-alpha --format json >"$TEST_ROOT/alpha-after.json" \
  || fail "could not inspect hosted-alpha after restart"
run_real_cli agent show hosted-beta --format json >"$TEST_ROOT/beta-after.json" \
  || fail "could not inspect hosted-beta after restart"
assert_real_principal_identity_and_groups "$TEST_ROOT/alpha-after.json" "$TEST_ROOT/beta-after.json"
run_as_principal_cli hosted-alpha agent list --format json \
  >"$TEST_ROOT/alpha-self-after.json" \
  || fail "hosted-alpha lost self-scoped list after fresh-container reopen"
assert_real_self_list "$TEST_ROOT/alpha-self-after.json" hosted-alpha
run_as_principal_cli hosted-beta agent list --format json \
  >"$TEST_ROOT/beta-self-after.json" \
  || fail "hosted-beta lost self-scoped list after fresh-container reopen"
assert_real_self_list "$TEST_ROOT/beta-self-after.json" hosted-beta

# A genuine restricted principal has no implicit self:list capability, so it
# must not inherit the agent-group self row. An agent principal also cannot
# modify a peer despite sharing the container UID and state mount.
if run_as_principal_cli hosted-restricted agent list \
  >"$TEST_ROOT/restricted-list.out" 2>"$TEST_ROOT/restricted-list.err"; then
  fail "restricted principal unexpectedly gained agent-list authority"
fi
grep -Eqi "denied|permission|capability" "$TEST_ROOT/restricted-list.err" ||
  fail "restricted principal denial did not identify an authority boundary"
if run_as_principal_cli hosted-alpha agent modify hosted-beta --add-group restricted \
  >"$TEST_ROOT/alpha-cross-modify.out" 2>"$TEST_ROOT/alpha-cross-modify.err"; then
  fail "hosted-alpha unexpectedly modified hosted-beta"
fi
grep -Eqi "denied|permission|capability" "$TEST_ROOT/alpha-cross-modify.err" ||
  fail "cross-principal denial did not identify an authority boundary"

# Reject lifecycle and identity overrides before any distro I/O.
for forbidden in \
  "--ephemeral" \
  "--workspace /attacker" \
  "--session 11111111-1111-1111-1111-111111111111" \
  "--unknown-flag"; do
  read -r -a forbidden_args <<<"$forbidden"
  if docker run --rm --platform "$OCI_PLATFORM" "$IMAGE" "${forbidden_args[@]}" \
    >"$TEST_ROOT/forbidden.out" 2>"$TEST_ROOT/forbidden.err"; then
    fail "forbidden daemon arguments were accepted: $forbidden"
  fi
  grep -Eq "not permitted" "$TEST_ROOT/forbidden.err" ||
    fail "forbidden daemon arguments did not fail at the allowlist: $forbidden"
done
if docker run --rm --platform "$OCI_PLATFORM" "$IMAGE" --host-io-concurrency 0 \
  >"$TEST_ROOT/zero.out" 2>"$TEST_ROOT/zero.err"; then
  fail "zero daemon concurrency was accepted"
fi
grep -q "requires an integer greater than zero" "$TEST_ROOT/zero.err" ||
  fail "zero daemon concurrency did not fail at the allowlist"

# Environment aliases are authority inputs too: a Linux caller cannot move
# the state/workspace roots (or HOME) to a path it controls and thereby mint a
# fresh Astrid identity.  These checks run before any distro is mounted.
for override in \
  "ASTRID_HOME=/attacker" \
  "ASTRID_WORKSPACE=/attacker" \
  "ASTRID_WORKSPACE_STATE_DIR=attacker" \
  "HOME=/attacker"; do
  override_name=${override%%=*}
  if docker run --rm --platform "$OCI_PLATFORM" --env "$override" "$IMAGE" \
    >"$TEST_ROOT/$override_name.out" 2>"$TEST_ROOT/$override_name.err"; then
    fail "hosted profile accepted authority-root override $override"
  fi
  grep -q "fixed to" "$TEST_ROOT/$override_name.err" ||
    fail "authority-root override $override did not fail closed"
done

# Security-sensitive policy overrides are inherited inputs too. The hosted
# profile denies both, even when the caller supplies an otherwise harmless
# value, before any distro or runtime initialization can occur.
for override in \
  "ASTRID_SANDBOX_POLICY=off" \
  "ASTRID_ALLOW_LOCAL_IPS=1"; do
  override_name=${override%%=*}
  if docker run --rm --platform "$OCI_PLATFORM" --env "$override" "$IMAGE" \
    >"$TEST_ROOT/$override_name.out" 2>"$TEST_ROOT/$override_name.err"; then
    fail "hosted profile accepted inherited policy override $override"
  fi
  grep -q "override is not permitted" "$TEST_ROOT/$override_name.err" ||
    fail "inherited policy override $override did not fail closed"
done

cat > "$TEST_ROOT/fake-daemon" <<'EOF'
#!/bin/sh
set -eu
[ "${ASTRID_DAEMON_LOG_TARGET:-}" = stderr ]
[ "$#" -eq 2 ]
[ "$1" = --workspace ]
[ "$2" = /workspace ]
for argument in "$@"; do
  [ "$argument" != --ephemeral ]
done
echo "FAKE_DAEMON_STARTED"
EOF
chmod 0755 "$TEST_ROOT/fake-daemon"

cat > "$TEST_ROOT/Dockerfile" <<EOF
FROM $TEST_BASE_IMAGE
USER 0:0
COPY fake-daemon /opt/astrid/release/astrid-daemon
RUN chmod 0555 /opt/astrid/release/astrid-daemon
USER 65532:65532
EOF
docker build \
  --platform "$OCI_PLATFORM" \
  --tag "$TEST_IMAGE" \
  --file "$TEST_ROOT/Dockerfile" \
  "$TEST_ROOT"

# A predictable-PID probe would truncate this symlink target in a container
# where the entrypoint is PID 1. Exclusive mktemp probes must leave both alone.
mkdir -p "$run_dir/state" "$run_dir/workspace"
printf 'do-not-truncate\n' >"$run_dir/workspace/probe-victim"
ln -s /workspace/probe-victim "$run_dir/state/.astrid-oci-write-probe.1"
prepare_runtime_dir "$run_dir/state"
prepare_runtime_dir "$run_dir/workspace" 0755

if ! docker run --rm \
  --platform "$OCI_PLATFORM" \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m,uid=65532,gid=65532 \
  --mount "type=bind,src=$TEST_ROOT/fixtures/distro.shuttle,dst=/run/astrid/distro.shuttle,readonly" \
  --mount "type=bind,src=$run_dir/state,dst=/var/lib/astrid" \
  --mount "type=bind,src=$run_dir/workspace,dst=/workspace" \
  --env "ASTRID_DISTRO_SHA256=$distro_sha256" \
  "$TEST_IMAGE" >"$TEST_ROOT/start.out" 2>"$TEST_ROOT/start.err"; then
  cat "$TEST_ROOT/start.out" >&2
  cat "$TEST_ROOT/start.err" >&2
  fail "valid signed distro startup failed"
fi
grep -q "FAKE_DAEMON_STARTED" "$TEST_ROOT/start.out" ||
  fail "valid signed distro did not reach the foreground daemon"
[[ "$(cat "$run_dir/workspace/probe-victim")" == do-not-truncate ]] ||
  fail "writable-directory probe followed a pre-created symlink"
runtime_path_is_symlink "$run_dir/state" ".astrid-oci-write-probe.1" ||
  fail "writable-directory probe consumed a pre-created symlink"
if ! grep -Eq "Offline installation complete|Installation complete|Installed [0-9]+ capsule" "$TEST_ROOT/start.err"; then
  cat "$TEST_ROOT/start.err" >&2
  fail "valid signed distro was not installed"
fi

python3 scripts/create_oci_test_shuttle.py \
  --capsule "$CLI_UPLINK_CAPSULE" \
  --output "$TEST_ROOT/fixtures/tampered.shuttle" \
  --tamper-signature
tampered_sha256=$(sha256sum "$TEST_ROOT/fixtures/tampered.shuttle")
tampered_sha256=${tampered_sha256%% *}

prepare_runtime_dir "$TEST_ROOT/tampered-state"
prepare_runtime_dir "$TEST_ROOT/tampered-workspace" 0755
if docker run --rm \
  --platform "$OCI_PLATFORM" \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m,uid=65532,gid=65532 \
  --mount "type=bind,src=$TEST_ROOT/fixtures/tampered.shuttle,dst=/run/astrid/distro.shuttle,readonly" \
  --mount "type=bind,src=$TEST_ROOT/tampered-state,dst=/var/lib/astrid" \
  --mount "type=bind,src=$TEST_ROOT/tampered-workspace,dst=/workspace" \
  --env "ASTRID_DISTRO_SHA256=$tampered_sha256" \
  "$TEST_IMAGE" >"$TEST_ROOT/tampered.out" 2>"$TEST_ROOT/tampered.err"; then
  fail "tampered signed distro was accepted"
fi
if grep -q "FAKE_DAEMON_STARTED" "$TEST_ROOT/tampered.out"; then
  fail "tampered signed distro reached the daemon"
fi
grep -q "distro signature verification failed" "$TEST_ROOT/tampered.err" ||
  fail "tampered signature did not fail at Astrid's internal signature gate"

prepare_runtime_dir "$TEST_ROOT/missing-state"
prepare_runtime_dir "$TEST_ROOT/missing-workspace" 0755
if docker run --rm \
  --platform "$OCI_PLATFORM" \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m,uid=65532,gid=65532 \
  --mount "type=bind,src=$TEST_ROOT/missing-state,dst=/var/lib/astrid" \
  --mount "type=bind,src=$TEST_ROOT/missing-workspace,dst=/workspace" \
  --env "ASTRID_DISTRO_SHA256=$distro_sha256" \
  "$TEST_IMAGE" >"$TEST_ROOT/missing.out" 2>"$TEST_ROOT/missing.err"; then
  fail "absent distro was accepted"
fi
grep -q "signed distro is absent" "$TEST_ROOT/missing.err" ||
  fail "absent distro did not fail at the entrypoint trust gate"

prepare_runtime_dir "$TEST_ROOT/mismatched-state"
prepare_runtime_dir "$TEST_ROOT/mismatched-workspace" 0755
if docker run --rm \
  --platform "$OCI_PLATFORM" \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m,uid=65532,gid=65532 \
  --mount "type=bind,src=$TEST_ROOT/fixtures/distro.shuttle,dst=/run/astrid/distro.shuttle,readonly" \
  --mount "type=bind,src=$TEST_ROOT/mismatched-state,dst=/var/lib/astrid" \
  --mount "type=bind,src=$TEST_ROOT/mismatched-workspace,dst=/workspace" \
  --env "ASTRID_DISTRO_SHA256=0000000000000000000000000000000000000000000000000000000000000000" \
  "$TEST_IMAGE" >"$TEST_ROOT/mismatched.out" 2>"$TEST_ROOT/mismatched.err"; then
  fail "signed distro with a mismatched expected digest was accepted"
fi
if grep -q "FAKE_DAEMON_STARTED" "$TEST_ROOT/mismatched.out"; then
  fail "mismatched signed distro reached the daemon"
fi
grep -q "signed distro SHA-256 does not match" "$TEST_ROOT/mismatched.err" ||
  fail "mismatched signed distro did not fail at the digest trust gate"

# Deterministically swap the operator path after staging but before init reads
# its enforced distro. The fake CLI mutates the source itself, then proves the
# entrypoint passed a distinct, still-authenticated private copy.
cat > "$TEST_ROOT/fake-astrid" <<'EOF'
#!/bin/sh
set -eu
[ "$#" -eq 3 ]
[ "$1" = init ]
[ "$2" = --offline ]
[ "$3" = --yes ]
[ "$ASTRID_ENFORCED_DISTRO" != "$ASTRID_TEST_SOURCE_PATH" ]
printf 'swapped-after-stage\n' >"$ASTRID_TEST_SOURCE_PATH"
actual=$(sha256sum "$ASTRID_ENFORCED_DISTRO")
actual=${actual%% *}
[ "$actual" = "$ASTRID_DISTRO_SHA256" ]
printf 'Offline installation complete\n' >&2
EOF
chmod 0755 "$TEST_ROOT/fake-astrid"

cat > "$TEST_ROOT/swap-daemon" <<'EOF'
#!/bin/sh
set -eu
[ "$(cat "$ASTRID_TEST_SOURCE_PATH")" = swapped-after-stage ]
actual=$(sha256sum "$ASTRID_ENFORCED_DISTRO")
actual=${actual%% *}
[ "$actual" = "$ASTRID_DISTRO_SHA256" ]
echo "STAGED_DISTRO_SURVIVED_SOURCE_SWAP"
EOF
chmod 0755 "$TEST_ROOT/swap-daemon"

cat > "$TEST_ROOT/SwapDockerfile" <<EOF
FROM $TEST_BASE_IMAGE
USER 0:0
COPY fake-astrid /opt/astrid/release/astrid
COPY swap-daemon /opt/astrid/release/astrid-daemon
RUN chmod 0555 /opt/astrid/release/astrid /opt/astrid/release/astrid-daemon
USER 65532:65532
EOF
docker build \
  --platform "$OCI_PLATFORM" \
  --tag "$TEST_SWAP_IMAGE" \
  --file "$TEST_ROOT/SwapDockerfile" \
  "$TEST_ROOT"

mkdir -p "$run_dir/swap-source"
cp "$TEST_ROOT/fixtures/distro.shuttle" "$run_dir/swap-source/distro.shuttle"
chmod 0777 "$run_dir/swap-source"
prepare_runtime_dir "$run_dir/swap-state"
prepare_runtime_dir "$run_dir/swap-workspace" 0755
chmod 0666 "$run_dir/swap-source/distro.shuttle"
if ! docker run --rm \
  --platform "$OCI_PLATFORM" \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m,uid=65532,gid=65532 \
  --mount "type=bind,src=$run_dir/swap-source,dst=/run/astrid/operator" \
  --mount "type=bind,src=$run_dir/swap-state,dst=/var/lib/astrid" \
  --mount "type=bind,src=$run_dir/swap-workspace,dst=/workspace" \
  --env "ASTRID_DISTRO_PATH=/run/astrid/operator/distro.shuttle" \
  --env "ASTRID_TEST_SOURCE_PATH=/run/astrid/operator/distro.shuttle" \
  --env "ASTRID_DISTRO_SHA256=$distro_sha256" \
  "$TEST_SWAP_IMAGE" >"$TEST_ROOT/swap.out" 2>"$TEST_ROOT/swap.err"; then
  cat "$TEST_ROOT/swap.out" >&2
  cat "$TEST_ROOT/swap.err" >&2
  fail "private staged distro did not survive source pathname swap"
fi
grep -q "STAGED_DISTRO_SURVIVED_SOURCE_SWAP" "$TEST_ROOT/swap.out" ||
  fail "source pathname swap test did not reach the daemon"

# The exact v0.10.4 audit command is a registered stub. Record that fact as a
# non-gating blocker instead of pretending that a global count, absent query,
# or green test exit proves audit continuity.
assert_v0104_audit_is_non_gating \
  "$TEST_ROOT/audit-probe.out" "$TEST_ROOT/audit-probe.err"
echo "oci $OCI_TEST_LABEL structure, authentication, principal authority, and fresh-container reopen checks passed"
echo "Audit continuity remains unproven on v0.10.4; this result does not claim hosted-profile qualification."
