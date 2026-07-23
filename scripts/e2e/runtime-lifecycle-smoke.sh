#!/usr/bin/env bash

install_adversarial_capsule_with_lifecycle_elicit() {
  local stdout="$ARTIFACTS/adversarial-install.out"
  local stderr="$ARTIFACTS/adversarial-install.err"

  note "checking lifecycle elicit during adversarial capsule install"
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
  grep -q 'runtime E2E lifecycle probe' "$stdout" \
    || fail "adversarial install did not surface lifecycle elicit prompt"

  # This regression deliberately removes one principal home to prove the
  # lifecycle install path provisions it again before mounting `home://`.
  # Never do that against an operator-supplied ASTRID_E2E_HOME.
  if [[ "$ASTRID_HOME_GENERATED" -ne 1 ]]; then
    note "skipping fresh principal-home lifecycle probe for supplied ASTRID_E2E_HOME"
    return
  fi

  local principal="e2e-lifecycle-home"
  local principal_home="$ASTRID_HOME/home/$principal"
  local workspace
  workspace="$(mktemp -d "${TMPDIR:-/tmp}/astrid-lifecycle-workspace.XXXXXX")"

  note "checking fresh nondefault workspace lifecycle home mount"
  run_cli agent create "$principal" -y
  [[ "$principal_home" == "$ASTRID_HOME/home/e2e-lifecycle-home" ]] \
    || fail "refusing to remove lifecycle home outside the generated ASTRID_HOME"
  rm -rf "$principal_home"
  if ! (
    cd "$workspace"
    printf 'runtime-lifecycle-ok\n' \
      | ASTRID_PRINCIPAL="$principal" "$CORE_DIR/target/debug/astrid" \
        --principal "$principal" capsule install \
        "$CORE_DIR/e2e/fixtures/astrid-capsule-adversarial" --workspace
  ) > "$ARTIFACTS/adversarial-workspace-install.out" \
    2> "$ARTIFACTS/adversarial-workspace-install.err"; then
    cat "$ARTIFACTS/adversarial-workspace-install.out" >&2 || true
    cat "$ARTIFACTS/adversarial-workspace-install.err" >&2 || true
    fail "fresh nondefault workspace lifecycle install failed"
  fi
  [[ -f "$principal_home/adversarial-lifecycle-home-mounted" ]] \
    || fail "workspace lifecycle guest did not mount the fresh target principal home"
  [[ "$(cat "$principal_home/adversarial-lifecycle-home-mounted")" == "mounted" ]] \
    || fail "workspace lifecycle guest wrote an unexpected home marker"
  [[ "$workspace" == "${TMPDIR:-/tmp}"/astrid-lifecycle-workspace.* ]] \
    || fail "refusing to remove lifecycle workspace outside the temporary root"
  rm -rf "$workspace"
}
