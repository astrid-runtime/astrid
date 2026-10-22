#!/usr/bin/env bash
set -euo pipefail

if [[ $# -gt 1 || (${1:-} != "" && ${1:-} != "--b3sum-only") ]]; then
  echo "usage: $0 [--b3sum-only]" >&2
  exit 2
fi

if [[ ${1:-} != "--b3sum-only" ]]; then
  sudo apt-get update
  sudo apt-get install -y --no-install-recommends fuse3
  if [[ ! -c /dev/fuse ]]; then
    sudo modprobe fuse
  fi
  [[ -c /dev/fuse ]] || { echo "::error::hosted runner has no Linux FUSE device" >&2; exit 1; }
  command -v fusermount3 >/dev/null || { echo "::error::hosted runner has no fusermount3" >&2; exit 1; }
  sudo chmod 0666 /dev/fuse
fi

B3SUM_REQUIRED_VERSION="1.8.5"
b3sum_bin_dir="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/astrid-certification-b3sum-${B3SUM_REQUIRED_VERSION}/bin"
mkdir -p "$b3sum_bin_dir"
b3sum_bin="$b3sum_bin_dir/b3sum"

if [[ ! -x "$b3sum_bin" ]] || [[ "$("$b3sum_bin" --version)" != "b3sum ${B3SUM_REQUIRED_VERSION}" ]]; then
  cargo install b3sum --version 1.8.5 --locked --root "${b3sum_bin_dir%/bin}"
fi

[[ "$("$b3sum_bin" --version)" == "b3sum ${B3SUM_REQUIRED_VERSION}" ]]
[[ "$(printf '' | "$b3sum_bin" --no-names)" == "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262" ]]

if [[ -n "${GITHUB_PATH:-}" ]]; then
  printf '%s\n' "$b3sum_bin_dir" >> "$GITHUB_PATH"
else
  printf '%s\n' "$b3sum_bin_dir"
fi
