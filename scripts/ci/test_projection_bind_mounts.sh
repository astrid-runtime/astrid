#!/usr/bin/env bash
# Run mount-boundary regressions with real Linux bind mounts, isolated from the host.
set -euo pipefail

python3 scripts/test_cargo_test_executable.py
for package in astrid-core astrid-storage; do
  test_target="${package//-/_}"
  test_binary=$(cargo test --locked -p "$package" --lib --no-run --message-format=json | python3 scripts/ci/cargo_test_executable.py "$test_target")
  sudo unshare --mount --propagation private -- "$test_binary" \
    bind_mount_ --ignored --nocapture --test-threads=1
done
