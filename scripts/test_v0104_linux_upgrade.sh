#!/usr/bin/env bash
# Exercise a real upgrade from the byte-exact published v0.10.4 Linux release.

set -euo pipefail

readonly RELEASE_VERSION="0.10.4"
readonly RELEASE_ASSET="astrid-${RELEASE_VERSION}-x86_64-unknown-linux-gnu.tar.gz"
readonly RELEASE_SHA256="a7c955ff5901d98059e8e6fba6f6b6e2033224e39c06db93e48a2ebe2a4f4725"
readonly RELEASE_URL="https://github.com/astrid-runtime/astrid/releases/download/v${RELEASE_VERSION}/${RELEASE_ASSET}"
readonly CAPSULE_BUILD_TARGET="wasm32-unknown-unknown"

REPOSITORY_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
readonly REPOSITORY_ROOT
readonly CURRENT_BIN_DIR="${ASTRID_CURRENT_BIN_DIR:-${REPOSITORY_ROOT}/target/debug}"
readonly CAPSULE_SOURCE="${REPOSITORY_ROOT}/e2e/fixtures/astrid-capsule-adversarial"
CAPSULE_RUSTUP_HOME=""
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

dump_daemon_logs() {
  local log
  [[ -d "${ASTRID_HOME}/log" ]] || return 0
  while IFS= read -r -d '' log; do
    printf '\n--- %s ---\n' "${log}" >&2
    tail -n 200 -- "${log}" >&2
  done < <(find "${ASTRID_HOME}/log" -type f -print0)
}

ensure_capsule_build_target() {
  local active_toolchain target_libdir toolchain
  command -v rustup >/dev/null 2>&1 \
    || fail "rustup is required to install ${CAPSULE_BUILD_TARGET}"
  CAPSULE_RUSTUP_HOME="$(rustup show home)" \
    || fail "could not resolve the Rustup home used by the capsule fixture"
  [[ -d "${CAPSULE_RUSTUP_HOME}" ]] \
    || fail "Rustup home is not a directory: ${CAPSULE_RUSTUP_HOME}"

  # The published astrid-build runs Cargo with the capsule source as its
  # current directory. Resolve the toolchain from that exact directory rather
  # than mutating rustup's default toolchain, which can be different in CI.
  active_toolchain="$(cd -- "${CAPSULE_SOURCE}" && rustup show active-toolchain)" \
    || fail "could not resolve the Rust toolchain used by the capsule fixture"
  read -r toolchain _ <<<"${active_toolchain}"
  [[ -n "${toolchain}" ]] \
    || fail "rustup returned no active toolchain for the capsule fixture"

  if ! rustup target list --toolchain "${toolchain}" --installed \
    | grep -Fqx -- "${CAPSULE_BUILD_TARGET}"; then
    rustup target add --toolchain "${toolchain}" "${CAPSULE_BUILD_TARGET}" \
      || fail "could not install Rust target ${CAPSULE_BUILD_TARGET} for ${toolchain}"
  fi
  rustup target list --toolchain "${toolchain}" --installed \
    | grep -Fqx -- "${CAPSULE_BUILD_TARGET}" \
    || fail "Rust target ${CAPSULE_BUILD_TARGET} is unavailable for ${toolchain} after installation"
  target_libdir="$(rustup run "${toolchain}" rustc \
    --print target-libdir --target "${CAPSULE_BUILD_TARGET}")" \
    || fail "could not resolve ${CAPSULE_BUILD_TARGET} libraries for ${toolchain}"
  compgen -G "${target_libdir}/libcore-*.rlib" >/dev/null \
    || fail "Rust core library for ${CAPSULE_BUILD_TARGET} is missing from ${toolchain}"
}

run_old_capsule_build_bounded() {
  local limit="$1"
  shift
  [[ -n "${CAPSULE_RUSTUP_HOME}" ]] \
    || fail "capsule build toolchain was not initialized"
  (
    cd -- "${WORKSPACE}"
    timeout "${limit}" env ASTRID_HOME="${ASTRID_HOME}" HOME="${POISON_HOME}" \
      RUSTUP_HOME="${CAPSULE_RUSTUP_HOME}" "${OLD_BIN_DIR}/astrid" "$@"
  )
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

validate_published_capsule_fixture() {
  python3 - "${ASTRID_HOME}" <<'PY'
import json
import pathlib
import sys

home = pathlib.Path(sys.argv[1])
capsule = home / "home/default/.local/capsules/astrid-capsule-adversarial"
manifest = capsule / "Capsule.toml"
meta_path = capsule / "meta.json"
for required in (manifest, meta_path):
    if not required.is_file():
        raise SystemExit(f"published capsule install did not publish {required}")
if 'name = "astrid-capsule-adversarial"' not in manifest.read_text():
    raise SystemExit("published capsule install wrote the wrong manifest")

meta = json.loads(meta_path.read_text())
wasm_hash = meta.get("wasm_hash")
if not isinstance(wasm_hash, str) or len(wasm_hash) != 64:
    raise SystemExit("published capsule metadata has no canonical WASM hash")
wasm = home / "bin" / f"{wasm_hash}.wasm"
if not wasm.is_file() or wasm.stat().st_size == 0:
    raise SystemExit(f"published capsule install did not publish {wasm}")

wit_files = meta.get("wit_files")
if not isinstance(wit_files, dict) or not wit_files:
    raise SystemExit("published capsule metadata has no WIT content-addresses")
for relative, wit_hash in wit_files.items():
    if not isinstance(relative, str) or not isinstance(wit_hash, str) or len(wit_hash) != 64:
        raise SystemExit("published capsule metadata contains an invalid WIT record")
    blob = home / "wit/store" / f"{wit_hash}.wit"
    if not blob.is_file() or blob.stat().st_size == 0:
        raise SystemExit(f"published capsule install did not publish {blob}")
PY
}

# Seed only released-home shapes that the component-owned importers can parse.
# The helper is called after the v0.10.4 daemon has created the principal
# directory, so the fixture is still a byte-level old-layout source rather
# than a current-layout projection.
seed_legacy_principal_sources() {
  local alias="$1"
  local principal_root="${ASTRID_HOME}/home/${alias}"
  local capsules_root="${principal_root}/.local/capsules"
  local env_root="${principal_root}/.config/env"
  local secret_root="${ASTRID_HOME}/secrets/${alias}"

  mkdir -p -- "${principal_root}/legacy-upgrade" "${principal_root}/.config" \
    "${principal_root}/.local/tmp"
  printf 'legacy ordinary content for %s\n' "${alias}" \
    >"${principal_root}/legacy-upgrade/ordinary.txt"
  chmod 600 -- "${principal_root}/legacy-upgrade/ordinary.txt"
  printf 'legacy invocation scratch for %s\n' "${alias}" \
    >"${principal_root}/.local/tmp/upgrade-scratch.txt"
  chmod 600 -- "${principal_root}/.local/tmp/upgrade-scratch.txt"

  cat >"${principal_root}/.config/distro.lock" <<'EOF'
schema-version = 1
capsule = []

[distro]
id = "legacy-upgrade"
version = "0.10.4"
resolved-at = "2026-08-17T00:00:00Z"
EOF
  printf 'legacy disposable init lock for %s\n' "${alias}" \
    >"${principal_root}/.config/distro.init.lock"
  chmod 600 -- "${principal_root}/.config/distro.lock" \
    "${principal_root}/.config/distro.init.lock"

  # Keep the released profile as the canonical destination and add a stale
  # pre-#672 copy in the old principal home. The migration must retain the
  # destination profile and retire only this legacy copy.  A missing profile
  # means the released CLI did not create the source shape this fixture is
  # meant to exercise; silently skipping it would make the upgrade evidence
  # weaker than the production path.
  if [[ ! -f "${ASTRID_HOME}/etc/profiles/${alias}.toml" ]]; then
    fail "published release did not create profile.toml for admitted principal ${alias}"
  fi
  cp --preserve=mode "${ASTRID_HOME}/etc/profiles/${alias}.toml" \
    "${principal_root}/.config/profile.toml"
  chmod 600 -- "${principal_root}/.config/profile.toml"
  printf '%s\n' "${alias}" >>"${TEST_ROOT}/legacy-profiles"

  # The fixture setup installs a real capsule through the published CLI
  # before this helper runs.  Copy the paired env/secret scopes for every
  # installed package so the migration exercises package authority/WIT and
  # both environment scopes instead of merely checking an empty directory.
  if [[ -d "${capsules_root}" ]]; then
    local capsule_dir capsule
    shopt -s nullglob
    for capsule_dir in "${capsules_root}"/*; do
      [[ -d "${capsule_dir}" ]] || continue
      capsule="${capsule_dir##*/}"
      [[ -f "${capsule_dir}/Capsule.toml" && -f "${capsule_dir}/meta.json" ]] || continue
      mkdir -p -- "${env_root}" "${secret_root}/${capsule}"
      printf '{"LEGACY_UPGRADE_PROBE":"%s/%s"}\n' "${alias}" "${capsule}" \
        >"${env_root}/${capsule}.env.json"
      printf 'legacy-secret-%s-%s\n' "${alias}" "${capsule}" \
        >"${secret_root}/${capsule}/probe"
      chmod 600 -- "${env_root}/${capsule}.env.json" "${secret_root}/${capsule}/probe"
    done
    shopt -u nullglob
  fi
  printf '%s\n' "${alias}" >>"${TEST_ROOT}/legacy-aliases"
}

umask 077
mkdir -p -- "${RELEASE_ROOT}" "${ASTRID_HOME}" "${POISON_HOME}" "${WORKSPACE}"
: >"${TEST_ROOT}/legacy-aliases"
: >"${TEST_ROOT}/legacy-capsules"
: >"${TEST_ROOT}/legacy-profiles"

for binary in astrid astrid-daemon; do
  [[ -x "${CURRENT_BIN_DIR}/${binary}" ]] \
    || fail "current ${binary} binary is missing from ${CURRENT_BIN_DIR}"
done

curl --fail --location --proto '=https' --tlsv1.2 --retry 3 \
  --output "${ARCHIVE}" "${RELEASE_URL}"
printf '%s  %s\n' "${RELEASE_SHA256}" "${ARCHIVE}" | sha256sum --check --strict
tar --extract --gzip --file "${ARCHIVE}" --directory "${RELEASE_ROOT}"

published_version="$(run_old version --format json)"
python3 - "${published_version}" "${RELEASE_VERSION}" <<'PY'
import json
import sys

reported = json.loads(sys.argv[1]).get("version")
expected = sys.argv[2]
if reported != expected:
    raise SystemExit(
        f"published binary reported version {reported!r}, expected {expected!r}"
    )
PY

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

# The checked-in adversarial capsule is a real Rust capsule source, so the
# released CLI can build and install it into the legacy native tree. Do not
# silently skip package/authority/WIT coverage when the published CLI loses
# this capability: that is a release-fixture failure, not an optional branch.
ensure_capsule_build_target
if ! run_old_capsule_build_bounded 180s capsule install --yes \
  --var adversarial_lifecycle_probe=runtime-lifecycle-ok \
  "${CAPSULE_SOURCE}" \
  >"${TEST_ROOT}/v0104-capsule-install.log" 2>&1; then
  cat "${TEST_ROOT}/v0104-capsule-install.log" >&2
  fail "published v0.10.4 CLI could not create the capsule migration fixture"
fi
validate_published_capsule_fixture
printf 'astrid-capsule-adversarial\n' >"${TEST_ROOT}/legacy-capsules"

# Exercise the system-file importers with valid released schemas. Empty
# version-one stores still produce durable migration receipts and are useful
# coverage: malformed or permissive parsers must not be able to skip them.
cat >"${ASTRID_HOME}/etc/invites.toml" <<'EOF'
schema_version = 1
EOF
cat >"${ASTRID_HOME}/etc/pair-tokens.toml" <<'EOF'
schema_version = 1
EOF
printf '{}\n' >"${ASTRID_HOME}/etc/gateway-revocations.json"
chmod 600 -- \
  "${ASTRID_HOME}/etc/invites.toml" \
  "${ASTRID_HOME}/etc/pair-tokens.toml" \
  "${ASTRID_HOME}/etc/gateway-revocations.json"

# The default principal is always admitted by the released CLI. A second
# principal is attempted through that same CLI when the published daemon can
# serve management IPC; releases intentionally built without a distro uplink
# may not support the operation, so the fixture records exactly which aliases
# were admitted instead of fabricating an unbound UID.
seed_legacy_principal_sources default
set +e
run_old_bounded 30s agent create legacy-second-alias --yes \
  >"${TEST_ROOT}/v0104-second-alias-create.log" 2>&1
old_second_alias_status=$?
set -e
if [[ ${old_second_alias_status} -eq 0 ]]; then
  seed_legacy_principal_sources legacy-second-alias
else
  printf 'published release did not expose agent:create; continuing with admitted aliases\n' \
    >>"${TEST_ROOT}/v0104-second-alias-create.log"
fi

# A released home may carry a disposable workspace-CoW tree from an earlier
# development build. Seed one so the upgrade exercises its retirement rather
# than merely asserting the path was never present.
mkdir -p -- "${ASTRID_HOME}/cow/legacy-workspace/merged"
printf '%s\n' 'disposable legacy CoW bytes' \
  >"${ASTRID_HOME}/cow/legacy-workspace/merged/file"
run_old_bounded 20s stop >/dev/null 2>&1 || true

if ! run_current_bounded 90s start; then
  dump_daemon_logs
  fail "current daemon could not start after migrating the published v0.10.4 home"
fi

# Write through the live upgraded daemon, stop it, then prove the write and the
# imported v0.10.4 identity both survive a second boot from the Astrid volume.
run_current agent list --format json >"${TEST_ROOT}/agents-after-upgrade.json"
grep -Fq 'default' "${TEST_ROOT}/agents-after-upgrade.json" \
  || fail "the released default principal is not visible after upgrade"
run_current agent create upgrade-restart-probe --yes
run_current agent create upgrade-second-alias --yes
run_current_bounded 20s stop
run_current_bounded 90s start
run_current agent list --format json >"${TEST_ROOT}/agents-after-restart.json"
grep -Fq 'upgrade-restart-probe' "${TEST_ROOT}/agents-after-restart.json" \
  || fail "post-upgrade write did not survive restart"
grep -Fq 'upgrade-second-alias' "${TEST_ROOT}/agents-after-restart.json" \
  || fail "second post-upgrade principal did not survive restart"
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
if (home / "cow").exists():
    raise SystemExit("legacy workspace CoW tree survived layout-v2 migration/restart")

ledger = json.loads((home / "var/migrations/layout-v2-components.complete").read_text())
if ledger.get("schema") != 1 or ledger.get("complete") is not True:
    raise SystemExit("component migration ledger is not a complete schema-1 record")
components = ledger.get("components")
if not isinstance(components, list) or not components:
    raise SystemExit("component migration ledger has no component records")
names = [component.get("name") for component in components]
if names != sorted(set(names)):
    raise SystemExit("component migration ledger names are not unique and sorted")
required = {
    "system:state-db",
    "system:cow",
    "system:invites",
    "system:pair-tokens",
    "system:gateway-revocations",
    "system:capsule-authority",
    "system:host-secrets",
}
if not required.issubset(names):
    raise SystemExit(f"component migration ledger is missing required records: {required - set(names)}")
for component in components:
    source = component.get("source") or {}
    proof = component.get("destination_proof")
    if source.get("present") and source.get("digest") == "absent":
        raise SystemExit(f"present source has absent digest: {component.get('name')}")
    if not source.get("present") and source.get("digest") != "absent":
        raise SystemExit(f"absent source has digest: {component.get('name')}")
    if source.get("present") and proof == "absent" and component.get("name") != "system:cow":
        raise SystemExit(f"present source has no destination proof: {component.get('name')}")
    if component.get("name") == "system:cow":
        if not str(proof).startswith("verified-discard-v1:"):
            raise SystemExit("CoW disposition is not explicitly verified-discard-v1")
        if "layout-receipt=layout-v1-to-v2.complete" not in proof:
            raise SystemExit("CoW disposition is not bound to the layout receipt")

aliases = [
    line.strip()
    for line in (home.parent / "legacy-aliases").read_text().splitlines()
    if line.strip()
]
for alias in aliases:
    principal = home / "home" / alias
    for relative in (
        ".local/capsules",
        ".config/env",
        ".local/audit",
        ".local/log",
        ".local/tmp",
        ".config/distro.lock",
        ".config/distro.init.lock",
        ".config/profile.toml",
    ):
        path = principal / relative
        if path.exists():
            if path.is_dir() and not any(path.iterdir()):
                continue
            raise SystemExit(f"legacy principal source survived for {alias}: {path}")
    if principal.exists() and any(principal.iterdir()):
        raise SystemExit(f"legacy ordinary principal source survived for {alias}: {principal}")
    secret_root = home / "secrets" / alias
    if secret_root.exists() and any(secret_root.iterdir()):
        raise SystemExit(f"legacy secret source survived for {alias}: {secret_root}")

    receipt_candidates = sorted((home / "var/migrations").glob("principal-home-*.json"))
    matching = []
    for receipt_path in receipt_candidates:
        receipt = json.loads(receipt_path.read_text())
        if receipt.get("alias") == alias:
            matching.append((receipt_path, receipt))
    if len(matching) != 1:
        raise SystemExit(f"expected exactly one ordinary-home receipt for {alias}")
    receipt_path, receipt = matching[0]
    if receipt.get("schema") != 2 or receipt.get("entry_count", 0) <= 0:
        raise SystemExit(f"ordinary-home receipt is incomplete for {alias}: {receipt_path}")
    uid = receipt.get("uid")
    pages = sorted((home / "var/migrations").glob(f"principal-home-{uid}.page-*.json"))
    if not pages:
        raise SystemExit(f"ordinary-home receipt has no pages for {alias}")
    ordinary = []
    for page in pages:
        payload = json.loads(page.read_text())
        ordinary.extend(payload.get("entries", []))
    if not any(
        entry.get("source") == "legacy-upgrade/ordinary.txt"
        and entry.get("destination") == "home/legacy-upgrade/ordinary.txt"
        and entry.get("kind") == "file"
        and entry.get("bytes", 0) > 0
        and isinstance(entry.get("digest"), str)
        and len(entry["digest"]) == 64
        for entry in ordinary
    ):
        raise SystemExit(f"ordinary destination readback proof is missing for {alias}")

    tmp_component = next(
        (component for component in components if component.get("name") == f"principal:{uid}:tmp"),
        None,
    )
    if not tmp_component or not str(tmp_component.get("destination_proof", "")).startswith(
        "verified-discard-v1:"
    ):
        raise SystemExit(f"tmp source is not source-bound discarded for {alias}")
    if "disposable=tmp" not in tmp_component["destination_proof"]:
        raise SystemExit(f"tmp disposition is missing its purpose for {alias}")
    audit_component = next(
        (component for component in components if component.get("name") == f"principal:{uid}:audit"),
        None,
    )
    if not audit_component:
        raise SystemExit(f"audit source/receipt component is missing for {alias}")
    if audit_component.get("source", {}).get("present") and audit_component.get(
        "destination_proof"
    ) == "absent":
        raise SystemExit(f"audit source has no durable destination receipt for {alias}")
    for component_name in (f"principal:{uid}:distro-lock", f"principal:{uid}:distro-init"):
        if not any(component.get("name") == component_name for component in components):
            raise SystemExit(f"missing distro migration component {component_name}")

    profiled_aliases = {
        line.strip()
        for line in (home.parent / "legacy-profiles").read_text().splitlines()
        if line.strip()
    }
    if alias in profiled_aliases:
        profile_component = next(
            (
                component
                for component in components
                if component.get("name") == f"principal:{uid}:profile"
            ),
            None,
        )
        if not profile_component or not profile_component.get("source", {}).get("present"):
            raise SystemExit(f"profile source was not represented in the migration ledger for {alias}")
        destination = home / "etc/profiles" / f"{alias}.toml"
        if not destination.is_file():
            raise SystemExit(f"migrated profile destination is missing for {alias}: {destination}")
        profile_proof = profile_component.get("destination_proof", "")
        if not (
            isinstance(profile_proof, str)
            and profile_proof.startswith("blake3:")
            and len(profile_proof.removeprefix("blake3:")) == 64
        ):
            raise SystemExit(f"profile destination proof is not a content digest for {alias}")

capsule_ids = [line.strip() for line in (home.parent / "legacy-capsules").read_text().splitlines() if line.strip()]
for capsule_id in capsule_ids:
    capsule_components = [
        component
        for component in components
        if component.get("name", "").endswith(":capsules")
        and component.get("source", {}).get("present")
    ]
    if not capsule_components:
        raise SystemExit(f"capsule source was not represented in the migration ledger: {capsule_id}")
    uid = next(
        component["name"].split(":")[1]
        for component in capsule_components
        if component["name"].startswith("principal:")
    )
    if not any(
        component.get("name") == f"principal:{uid}:env:{capsule_id}"
        and component.get("source", {}).get("present")
        for component in components
    ):
        raise SystemExit(f"capsule environment source was not represented: {capsule_id}")
    if not any(
        component.get("name") == f"principal:{uid}:secret:{capsule_id}"
        and component.get("source", {}).get("present")
        for component in components
    ):
        raise SystemExit(f"capsule secret source was not represented: {capsule_id}")

for source in (
    home / "etc/invites.toml",
    home / "etc/pair-tokens.toml",
    home / "etc/gateway-revocations.json",
):
    if source.exists():
        raise SystemExit(f"legacy system source survived verified retirement: {source}")
host_secret_root = home / "secrets" / "__host__"
if host_secret_root.exists():
    if any(host_secret_root.iterdir()):
        raise SystemExit(f"legacy host secret source survived verified retirement: {host_secret_root}")
    raise SystemExit(f"empty legacy host secret root survived verified retirement: {host_secret_root}")

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
