#!/usr/bin/env bash
# Run mount-boundary regressions with real Linux bind mounts, isolated from the host.
set -euo pipefail

python3 scripts/test_cargo_test_executable.py
test_binary=$(cargo test --locked -p astrid-core --lib --no-run --message-format=json | python3 scripts/ci/cargo_test_executable.py astrid_core)
sudo unshare --mount --propagation private -- "$test_binary" \
  bind_mount_ --ignored --nocapture --test-threads=1
