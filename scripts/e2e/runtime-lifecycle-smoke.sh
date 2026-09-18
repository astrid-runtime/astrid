#!/usr/bin/env bash

runtime_start_count() {
  local capsule=$1
  local pattern="Starting background WASM run loop capsule=$capsule"
  find "$ASTRID_HOME/log" -type f -name '*.log' -exec \
    grep -h -o -F "$pattern" {} + 2>/dev/null \
    | awk 'END { print NR + 0 }' || true
}

install_adversarial_capsule_with_lifecycle_config() {
  local stdout="$ARTIFACTS/adversarial-install.out"
  local stderr="$ARTIFACTS/adversarial-install.err"
  local unrelated_capsule=""
  local capsule
  for capsule in $CORE_CAPSULES; do
    if [[ "$capsule" != "astrid-capsule-adversarial" ]]; then
      unrelated_capsule="$capsule"
      break
    fi
  done
  local adversarial_starts_before
  local unrelated_starts_before
  adversarial_starts_before="$(runtime_start_count astrid-capsule-adversarial)"
  unrelated_starts_before=0
  if [[ -n "$unrelated_capsule" ]]; then
    local status_before="$ARTIFACTS/lifecycle-status-before.txt"
    if "$CORE_DIR/target/debug/astrid" status > "$status_before" 2>/dev/null \
      && grep -q "^[[:space:]]*-[[:space:]]$unrelated_capsule$" "$status_before"; then
      unrelated_starts_before="$(runtime_start_count "$unrelated_capsule")"
    else
      note "skipping unrelated restart assertion: '$unrelated_capsule' is not loaded"
      unrelated_capsule=""
    fi
  fi

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

  # A daemon-owned install activates the newly admitted capsule before its
  # authenticated response returns. The CLI must not immediately reload that
  # same id, which would run its #[astrid::run] loop twice. Keep one already
  # loaded capsule in the count as a guard against broad reload churn too.
  local adversarial_starts_after
  local unrelated_starts_after
  local adversarial_delta
  adversarial_starts_after="$(runtime_start_count astrid-capsule-adversarial)"
  adversarial_delta=$((adversarial_starts_after - adversarial_starts_before))
  (( adversarial_delta == 1 )) \
    || fail "adversarial install activated $adversarial_delta new times; expected one run-loop start"
  if [[ -n "$unrelated_capsule" ]]; then
    unrelated_starts_after="$(runtime_start_count "$unrelated_capsule")"
    (( unrelated_starts_after == unrelated_starts_before )) \
      || fail "$unrelated_capsule restarted during adversarial install"
  fi

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
