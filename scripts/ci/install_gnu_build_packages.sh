#!/usr/bin/env bash
set -euo pipefail

# Bullseye supplies the glibc 2.31 build baseline, but LTS ended 2026-08-31.
# Freeze its final package sources rather than raising the binary ABI floor.
# Only these immutable snapshots waive freshness; APT still verifies Debian
# signatures and package hashes. Do not apply this policy to live repositories.
sources=$(mktemp)
trap 'rm -f "$sources"' EXIT
printf '%s\n' \
  'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/20260901T000000Z/ bullseye main' \
  'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian-security/20260901T000000Z/ bullseye-security main' \
  > "$sources"
options=(-o "Dir::Etc::sourcelist=$sources" -o Dir::Etc::sourceparts=-)
apt-get "${options[@]}" update
apt-get "${options[@]}" install -y --no-install-recommends "$@"
