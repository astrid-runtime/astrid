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
}
