#!/usr/bin/env bash

install_adversarial_capsule_with_lifecycle_config() {
  local stdout="$ARTIFACTS/adversarial-install.out"
  local stderr="$ARTIFACTS/adversarial-install.err"

  note "checking typed lifecycle configuration during adversarial capsule install"
  printf '$ astrid capsule install e2e/fixtures/astrid-capsule-adversarial\n' \
    >> "$ARTIFACTS/cli-transcript.log"
  if ! printf 'runtime-lifecycle-ok\n' \
    | "$CORE_DIR/target/debug/astrid" capsule install \
      "$CORE_DIR/e2e/fixtures/astrid-capsule-adversarial" \
      > "$stdout" 2> "$stderr"; then
    cat "$stdout" >&2 || true
    cat "$stderr" >&2 || true
    fail "adversarial capsule lifecycle install failed"
  fi
  grep -q 'runtime E2E lifecycle probe' "$stdout" "$stderr" \
    || fail "adversarial install did not surface declared lifecycle configuration prompt"

  # This regression proves a newly admitted nondefault principal receives a
  # UID-bound storage home during lifecycle execution. No alias-keyed native
  # PrincipalHome may be created as a side effect.
  if [[ "$ASTRID_HOME_GENERATED" -ne 1 ]]; then
    note "skipping fresh principal-home lifecycle probe for supplied ASTRID_E2E_HOME"
    return
  fi

  local principal="e2e-lifecycle-home"
  local principal_home="$ASTRID_HOME/home/$principal"

  note "checking fresh nondefault lifecycle home mount"
  run_cli agent create "$principal" --group agent -y
  [[ ! -e "$principal_home" ]] \
    || fail "agent admission unexpectedly created a native principal home"
  if ! printf 'runtime-lifecycle-ok\n' \
    | ASTRID_PRINCIPAL="$principal" "$CORE_DIR/target/debug/astrid" \
      --principal "$principal" capsule install \
      "$CORE_DIR/e2e/fixtures/astrid-capsule-adversarial" \
      > "$ARTIFACTS/adversarial-principal-install.out" \
      2> "$ARTIFACTS/adversarial-principal-install.err"; then
    cat "$ARTIFACTS/adversarial-principal-install.out" >&2 || true
    cat "$ARTIFACTS/adversarial-principal-install.err" >&2 || true
    fail "fresh nondefault lifecycle install failed"
  fi
  [[ ! -e "$principal_home" ]] \
    || fail "lifecycle install escaped into a native alias-keyed principal home"
  run_cli agent modify "$principal" --add-capsule astrid-capsule-adversarial
  bounded_principal_cli "$principal" 12 \
    "$ARTIFACTS/adversarial-principal-home-read.out" \
    capsule run astrid-capsule-adversarial adversarial-home-ready \
    || fail "principal could not read its lifecycle marker through home://"
  grep -q 'lifecycle home mounted' \
    "$ARTIFACTS/adversarial-principal-home-read.out" \
    || fail "principal runtime did not observe the storage-backed lifecycle home marker"
  ASTRID_PRINCIPAL="$principal" "$CORE_DIR/target/debug/astrid" \
    --principal "$principal" capsule remove astrid-capsule-adversarial --force \
    > "$ARTIFACTS/adversarial-principal-remove.out" \
    2> "$ARTIFACTS/adversarial-principal-remove.err"
}
