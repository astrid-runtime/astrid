#!/bin/sh
set -eu

fail() {
    printf 'astrid container: %s\n' "$*" >&2
    exit 1
}

# The image owns daemon lifecycle. Callers may tune bounded runtime ceilings
# and verbosity, but may not replace the workspace/session identity, request
# ephemeral shutdown, or pass newly-added daemon flags without an explicit
# review here.
expect_daemon_value=
for daemon_argument do
    if [ -n "$expect_daemon_value" ]; then
        case "$daemon_argument" in
            *[!0-9]*|'0'|'')
                fail "$expect_daemon_value requires an integer greater than zero"
                ;;
        esac
        expect_daemon_value=
        continue
    fi

    case "$daemon_argument" in
        --verbose|-v)
            ;;
        --host-io-concurrency|--host-blocking-concurrency|--instance-pool-size)
            expect_daemon_value=$daemon_argument
            ;;
        --host-io-concurrency=*|--host-blocking-concurrency=*|--instance-pool-size=*)
            daemon_value=${daemon_argument#*=}
            case "$daemon_value" in
                *[!0-9]*|'0'|'')
                    fail "${daemon_argument%%=*} requires an integer greater than zero"
                    ;;
            esac
            ;;
        --ephemeral|--ephemeral=*)
            fail "--ephemeral is not permitted in the persistent runtime image"
            ;;
        *)
            fail "daemon argument is not permitted: $daemon_argument"
            ;;
    esac
done
[ -z "$expect_daemon_value" ] ||
    fail "$expect_daemon_value requires an integer greater than zero"

distro_path=${ASTRID_DISTRO_PATH:-/run/astrid/distro.shuttle}
expected_sha256=${ASTRID_DISTRO_SHA256:-}

[ -n "$expected_sha256" ] ||
    fail "ASTRID_DISTRO_SHA256 is required for the operator-supplied signed distro"
case "$expected_sha256" in
    *[!0-9a-f]*|'')
        fail "ASTRID_DISTRO_SHA256 must be exactly 64 lowercase hexadecimal characters"
        ;;
esac
[ "${#expected_sha256}" -eq 64 ] ||
    fail "ASTRID_DISTRO_SHA256 must be exactly 64 lowercase hexadecimal characters"

[ -f "$distro_path" ] ||
    fail "signed distro is absent: $distro_path"
[ ! -L "$distro_path" ] ||
    fail "signed distro must be a regular file, not a symbolic link: $distro_path"

: "${ASTRID_HOME:=/var/lib/astrid}"
: "${ASTRID_WORKSPACE:=/workspace}"
export ASTRID_HOME ASTRID_WORKSPACE
export HOME="$ASTRID_HOME"
export ASTRID_DAEMON_LOG_TARGET=stderr

for writable_dir in "$ASTRID_HOME" "$ASTRID_WORKSPACE" /tmp; do
    [ -d "$writable_dir" ] ||
        fail "required writable directory is absent: $writable_dir"
    probe=$(umask 077 && mktemp "$writable_dir/.astrid-oci-write-probe.XXXXXX") ||
        fail "required directory is not writable by uid $(id -u): $writable_dir"
    rm -f "$probe"
done

# Never pass the operator-controlled pathname to Astrid after checking it.
# Copy into a private, exclusively-created file and authenticate the staged
# bytes. A rename or symlink swap at the mount cannot change what init reads.
staged_dir=$(umask 077 && mktemp -d /tmp/astrid-distro.XXXXXX) ||
    fail "could not create private signed-distro staging directory"
staged_distro=$staged_dir/distro.shuttle
trap 'rm -f "$staged_distro"; rmdir "$staged_dir"' EXIT HUP INT TERM
cat -- "$distro_path" > "$staged_distro" ||
    fail "could not stage signed distro: $distro_path"
chmod 0400 "$staged_distro" ||
    fail "could not protect staged signed distro"
[ -f "$staged_distro" ] && [ ! -L "$staged_distro" ] ||
    fail "private signed-distro staging path is not a regular file"

actual_sha256=$(sha256sum "$staged_distro") ||
    fail "could not hash staged signed distro"
actual_sha256=${actual_sha256%% *}
[ "$actual_sha256" = "$expected_sha256" ] ||
    fail "signed distro SHA-256 does not match ASTRID_DISTRO_SHA256"
export ASTRID_ENFORCED_DISTRO="$staged_distro"

cd "$ASTRID_WORKSPACE"

# The command deliberately supplies no unsigned-artifact or key-rotation
# override. Offline mode prevents mutable network inputs during installation.
/usr/local/bin/astrid init \
    --offline \
    --yes

# The staged distro must remain available to the daemon after exec. It lives on
# the container's transient /tmp mount and disappears with the container.
trap - EXIT HUP INT TERM
exec /usr/local/bin/astrid-daemon --workspace "$ASTRID_WORKSPACE" "$@"
