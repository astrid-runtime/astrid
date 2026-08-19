#!/usr/bin/env bash

set -euo pipefail

set +e
cargo test --workspace --locked -- --test-threads=1
status=$?
set -e

if [[ $status -ne 0 ]]; then
  echo "::group::macOS failure diagnostics"
  echo "exit_status=$status"
  uname -a || true
  sw_vers || true
  sysctl -n hw.optional.arm64 hw.memsize hw.ncpu || true
  ulimit -a || true

  echo "::group::Recent relevant processes"
  # shellcheck disable=SC2009 # Preserve the full process-table diagnostic.
  ps -axo pid,ppid,pgid,stat,comm,args \
    | grep -E 'astrid_capsule|cargo|rustc|sleep| sh ' \
    | grep -v grep || true
  echo "::endgroup::"

  echo "::group::Recent macOS abort/crash log entries"
  log show --last 10m --style compact --info --debug \
    --predicate 'eventMessage CONTAINS[c] "SIGABRT" OR eventMessage CONTAINS[c] "abort" OR eventMessage CONTAINS[c] "crash" OR eventMessage CONTAINS[c] "killed" OR eventMessage CONTAINS[c] "terminated" OR process CONTAINS[c] "astrid_capsule" OR process CONTAINS[c] "sleep"' \
    || true
  echo "::endgroup::"

  echo "::group::Diagnostic reports"
  for dir in "$HOME/Library/Logs/DiagnosticReports" "/Library/Logs/DiagnosticReports"; do
    [[ -d "$dir" ]] || continue
    echo "Reports in $dir"
    find "$dir" -maxdepth 1 -type f \( -name '*astrid*' -o -name '*cargo*' -o -name '*rustc*' -o -name '*sleep*' \) -print \
      | while read -r report; do
          echo "--- $report"
          sed -n '1,220p' "$report" || true
        done
  done
  echo "::endgroup::"
  echo "::endgroup::"
fi

exit "$status"
