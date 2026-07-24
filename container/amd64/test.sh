#!/usr/bin/env bash
set -euo pipefail

IMAGE=${1:?usage: container/amd64/test.sh IMAGE CLI_UPLINK_CAPSULE}
CLI_UPLINK_CAPSULE=${2:?usage: container/amd64/test.sh IMAGE CLI_UPLINK_CAPSULE}
OCI_PLATFORM=${ASTRID_OCI_TEST_PLATFORM:-linux/amd64}
OCI_ARCHITECTURE=${ASTRID_OCI_TEST_ARCHITECTURE:-amd64}
OCI_TEST_LABEL=${ASTRID_OCI_TEST_LABEL:-amd64}
TEST_ROOT=$(mktemp -d)
TEST_BASE_IMAGE="astrid-oci-bound-base:${RANDOM}-${RANDOM}"
TEST_IMAGE="astrid-oci-entrypoint-test:${RANDOM}-${RANDOM}"
TEST_SWAP_IMAGE="astrid-oci-swap-test:${RANDOM}-${RANDOM}"
REAL_CONTAINER=

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
distro_sha256=$(sha256sum "$TEST_ROOT/fixtures/distro.shuttle")
distro_sha256=${distro_sha256%% *}

# Exercise the authenticated release daemon itself. The readiness sentinel and
# an authenticated CLI status round trip must both succeed while the daemon is
# PID 1 under the deployment restrictions claimed by this image.
REAL_CONTAINER=$(docker run --detach \
  --platform "$OCI_PLATFORM" \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m,uid=65532,gid=65532 \
  --mount "type=bind,src=$TEST_ROOT/fixtures/distro.shuttle,dst=/run/astrid/distro.shuttle,readonly" \
  --mount "type=bind,src=$run_dir/real-state,dst=/var/lib/astrid" \
  --mount "type=bind,src=$run_dir/real-workspace,dst=/workspace" \
  --env "ASTRID_DISTRO_SHA256=$distro_sha256" \
  "$IMAGE")

release_ready=false
for _ in $(seq 1 120); do
  if [[ "$(docker inspect "$REAL_CONTAINER" --format '{{.State.Running}}')" != true ]]; then
    break
  fi
  if docker exec "$REAL_CONTAINER" test -f /var/lib/astrid/run/system.ready &&
    docker exec "$REAL_CONTAINER" /usr/local/bin/astrid status \
      >"$TEST_ROOT/real-status.out" 2>"$TEST_ROOT/real-status.err"; then
    release_ready=true
    break
  fi
  sleep 0.5
done
if [[ "$release_ready" != true ]]; then
  docker logs "$REAL_CONTAINER" >&2 || true
  cat "$TEST_ROOT/real-status.out" >&2 2>/dev/null || true
  cat "$TEST_ROOT/real-status.err" >&2 2>/dev/null || true
  fail "authenticated release daemon did not become ready"
fi
grep -q "Astrid daemon" "$TEST_ROOT/real-status.out" ||
  fail "authenticated release daemon did not answer status"
docker stop --time 10 "$REAL_CONTAINER" >/dev/null
docker rm "$REAL_CONTAINER" >/dev/null
REAL_CONTAINER=

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

echo "oci $OCI_TEST_LABEL structure, authentication, and restricted startup tests passed"
