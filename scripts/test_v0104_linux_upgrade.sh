#!/usr/bin/env bash
# Exercise a real upgrade from the byte-exact published v0.10.4 Linux release.

set -euo pipefail

readonly RELEASE_VERSION="0.10.4"
readonly RELEASE_ASSET="astrid-${RELEASE_VERSION}-x86_64-unknown-linux-gnu.tar.gz"
readonly RELEASE_SHA256="a7c955ff5901d98059e8e6fba6f6b6e2033224e39c06db93e48a2ebe2a4f4725"
readonly RELEASE_URL="https://github.com/astrid-runtime/astrid/releases/download/v${RELEASE_VERSION}/${RELEASE_ASSET}"

REPOSITORY_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
readonly REPOSITORY_ROOT
readonly CURRENT_BIN_DIR="${ASTRID_CURRENT_BIN_DIR:-${REPOSITORY_ROOT}/target/debug}"
TEST_ROOT="$(mktemp -d "${RUNNER_TEMP:-/tmp}/astrid-v0104-linux-upgrade.XXXXXX")"
readonly TEST_ROOT
readonly RELEASE_ROOT="${TEST_ROOT}/release"
readonly ASTRID_HOME="${TEST_ROOT}/home"
readonly POISON_HOME="${TEST_ROOT}/poison-home"
readonly WORKSPACE="${TEST_ROOT}/workspace"
readonly ARCHIVE="${TEST_ROOT}/${RELEASE_ASSET}"
readonly OLD_BIN_DIR="${RELEASE_ROOT}/astrid-${RELEASE_VERSION}-x86_64-unknown-linux-gnu"

cleanup() {
  set +e
  if [[ -x "${CURRENT_BIN_DIR}/astrid" ]]; then
    (
      cd -- "${WORKSPACE}" 2>/dev/null || exit 0
      timeout 20s env ASTRID_HOME="${ASTRID_HOME}" HOME="${POISON_HOME}" \
        "${CURRENT_BIN_DIR}/astrid" stop >/dev/null 2>&1
    )
  fi
  if [[ -x "${OLD_BIN_DIR}/astrid" ]]; then
    (
      cd -- "${WORKSPACE}" 2>/dev/null || exit 0
      timeout 20s env ASTRID_HOME="${ASTRID_HOME}" HOME="${POISON_HOME}" \
        "${OLD_BIN_DIR}/astrid" stop >/dev/null 2>&1
    )
  fi
  case "${TEST_ROOT}" in
    "${RUNNER_TEMP:-/tmp}"/astrid-v0104-linux-upgrade.*)
      rm -rf -- "${TEST_ROOT}"
      ;;
  esac
}
trap cleanup EXIT

fail() {
  printf 'v0.10.4 Linux upgrade test: %s\n' "$*" >&2
  exit 1
}

run_old() {
  (
    cd -- "${WORKSPACE}"
    env ASTRID_HOME="${ASTRID_HOME}" HOME="${POISON_HOME}" \
      "${OLD_BIN_DIR}/astrid" "$@"
  )
}

run_current() {
  (
    cd -- "${WORKSPACE}"
    env ASTRID_HOME="${ASTRID_HOME}" HOME="${POISON_HOME}" \
      "${CURRENT_BIN_DIR}/astrid" "$@"
  )
}

run_old_bounded() {
  local limit="$1"
  shift
  (
    cd -- "${WORKSPACE}"
    timeout "${limit}" env ASTRID_HOME="${ASTRID_HOME}" HOME="${POISON_HOME}" \
      "${OLD_BIN_DIR}/astrid" "$@"
  )
}

run_current_bounded() {
  local limit="$1"
  shift
  (
    cd -- "${WORKSPACE}"
    timeout "${limit}" env ASTRID_HOME="${ASTRID_HOME}" HOME="${POISON_HOME}" \
      "${CURRENT_BIN_DIR}/astrid" "$@"
  )
}

umask 077
mkdir -p -- "${RELEASE_ROOT}" "${ASTRID_HOME}" "${POISON_HOME}" "${WORKSPACE}"

for binary in astrid astrid-daemon; do
  [[ -x "${CURRENT_BIN_DIR}/${binary}" ]] \
    || fail "current ${binary} binary is missing from ${CURRENT_BIN_DIR}"
done

curl --fail --location --proto '=https' --tlsv1.2 --retry 3 \
  --output "${ARCHIVE}" "${RELEASE_URL}"
printf '%s  %s\n' "${RELEASE_SHA256}" "${ARCHIVE}" | sha256sum --check --strict
tar --extract --gzip --file "${ARCHIVE}" --directory "${RELEASE_ROOT}"

[[ "$(run_old version)" == "astrid ${RELEASE_VERSION}" ]] \
  || fail "published binary did not report astrid ${RELEASE_VERSION}"

# v0.10.4 deliberately refuses to serve without a distro-provided socket
# uplink, but that boot reaches and durably creates the released layout-one
# home. Bound the command so a release regression cannot wedge CI.
set +e
run_old_bounded 45s start >"${TEST_ROOT}/v0104-start.log" 2>&1
old_start_status=$?
set -e
[[ ${old_start_status} -ne 124 ]] || fail "published daemon boot timed out"

[[ "$(<"${ASTRID_HOME}/etc/layout-version")" == "1" ]] \
  || fail "published release did not create layout one"
[[ -d "${ASTRID_HOME}/var/state.db" ]] \
  || fail "published release did not create var/state.db"
compgen -G "${ASTRID_HOME}/var/state.db/manifest/*.manifest" >/dev/null \
  || fail "published release did not create a SurrealKV manifest"
compgen -G "${ASTRID_HOME}/var/state.db/wal/*.wal" >/dev/null \
  || fail "published release did not create a SurrealKV WAL"
run_old_bounded 20s stop >/dev/null 2>&1 || true

run_current_bounded 90s start

# Write through the live upgraded daemon, stop it, then prove the write and the
# imported v0.10.4 identity both survive a second boot from the Astrid volume.
run_current agent list --format json >"${TEST_ROOT}/agents-after-upgrade.json"
grep -Fq 'default' "${TEST_ROOT}/agents-after-upgrade.json" \
  || fail "the released default principal is not visible after upgrade"
run_current agent create upgrade-restart-probe --yes
run_current_bounded 20s stop
run_current_bounded 90s start
run_current agent list --format json >"${TEST_ROOT}/agents-after-restart.json"
grep -Fq 'upgrade-restart-probe' "${TEST_ROOT}/agents-after-restart.json" \
  || fail "post-upgrade write did not survive restart"
run_current_bounded 20s stop

python3 - "${ASTRID_HOME}" <<'PY'
import json
import pathlib
import sys

home = pathlib.Path(sys.argv[1])
if (home / "etc/layout-version").read_bytes() != b"2":
    raise SystemExit("layout-version is not exactly 2")
if not (home / "var/astrid.volume").is_file():
    raise SystemExit("Astrid volume is absent after upgrade")
if (home / "var/astrid.volume").stat().st_size == 0:
    raise SystemExit("Astrid volume is empty after upgrade")
if (home / "var/state.db").exists():
    raise SystemExit("released var/state.db survived verified retirement")
if (home / "var/principal-store").exists():
    raise SystemExit("intermediate directory-backed principal store survived cutover")

intent = json.loads((home / "var/migrations/layout-v1-to-v2.intent").read_text())
receipt = json.loads((home / "var/migrations/layout-v1-to-v2.complete").read_text())
if receipt.get("transaction_id") != intent.get("transaction_id"):
    raise SystemExit("migration receipt does not bind the admitted intent")
if receipt.get("intent") != intent:
    raise SystemExit("migration receipt does not embed the admitted intent")
if receipt.get("destination", {}).get("bytes", 0) <= 0:
    raise SystemExit("migration receipt does not bind a non-empty volume")
PY

printf 'v0.10.4 Linux release upgraded, retired, wrote, and reopened successfully\n'
