#!/usr/bin/env bash
# Local Distro staging and signed offline smoke helpers for runtime E2E.

stage_local_distro() {
  local root=$1
  local archive=$2
  mkdir -p "$root/capsules"
  cp "$archive" "$root/capsules/astrid-capsule-registry.capsule"
  cat > "$root/Distro.toml" <<'EOF'
schema-version = 1

[distro]
id = "runtime-e2e"
name = "Runtime E2E"
version = "0.0.0"

[[capsule]]
name = "astrid-capsule-registry"
source = "capsules/astrid-capsule-registry.capsule"
version = "0.0.0"
role = "uplink"
EOF
}

run_cli_distro_seal_smoke() {
  local archive=$1
  local output=$2
  local distro_root="$ARTIFACTS/seal-distro"
  rm -rf "$distro_root"
  stage_local_distro "$distro_root" "$archive"

  local signing_home="$ARTIFACTS/seal-signing-home"
  rm -rf "$signing_home"
  mkdir -p "$signing_home"
  ASTRID_HOME="$signing_home" "$CORE_DIR/target/debug/astrid" keypair generate \
    --name distro-seal --raw > "$ARTIFACTS/distro-signer.pub.hex"
  local public_hex
  public_hex="$(cat "$ARTIFACTS/distro-signer.pub.hex")"
  python3 - "$public_hex" "$distro_root/Distro.toml" <<'PY'
import base64, binascii, sys
public = bytes.fromhex(sys.argv[1])
assert len(public) == 32
pubkey = "ed25519:" + base64.b64encode(public).decode("ascii")
path = sys.argv[2]
text = open(path, encoding="utf-8").read()
text += f'\n[distro.signing]\npubkey = "{pubkey}"\n'
open(path, "w", encoding="utf-8").write(text)
PY

  ASTRID_HOME="$signing_home" "$CORE_DIR/target/debug/astrid" distro seal "$distro_root/Distro.toml" \
    --output "$output" \
    --key "$signing_home/keys/local/distro-seal.ed25519"
  [[ -f "$output" ]] || fail "sealed distro was not produced"
}

run_cli_offline_init_smoke() {
  local archive=$1
  local shuttle="$ARTIFACTS/offline-init-distro.shuttle"
  rm -f "$shuttle"
  run_cli_distro_seal_smoke "$archive" "$shuttle"
  run_cli init --distro "$shuttle" --offline --yes
}
