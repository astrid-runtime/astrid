#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
workflow="$repo_root/.github/workflows/promote-channel.yml"
release_workflow="$repo_root/.github/workflows/release.yml"

grep -Fq "if: github.ref == 'refs/heads/main'" "$workflow"
grep -Fq "repos/\$GITHUB_REPOSITORY/git/ref/tags/\$RELEASE_TAG" "$workflow"
grep -Fq "repos/\$GITHUB_REPOSITORY/git/tags/\$TAG_COMMIT" "$workflow"
grep -Fq "[[ \"\$TAG_TYPE\" == commit ]]" "$workflow"
grep -Fq "HISTORY_FLOOR=\$(printf" "$workflow"
grep -Fq -- "--generation \"\$HISTORY_FLOOR\"" "$workflow"
grep -Fq -- "--release-manifest \"\$RELEASE_METADATA\"" "$workflow"
grep -Fq 'BLAKE3SUMS.txt.sigstore.json' "$workflow"
grep -Fq 'validate-checksums' "$workflow"
grep -Fq 'release assets are write-once' "$release_workflow"
grep -Fq 'overwrite_files: false' "$release_workflow"
grep -Fq 'draft: true' "$release_workflow"
grep -Fq 'current pointer is malformed; continuity will use authenticated history' "$workflow"
grep -Fq "elif authenticate_current_history \"\$CURRENT\" recovered-current; then" "$workflow"
grep -Fq 'current pointer is unauthenticated; continuity will use authenticated history' "$workflow"
grep -Fq "CURRENT_PRESENT=\$CURRENT_PRESENT" "$workflow"
grep -Fq "[[ \"\$GENERATION\" -ge \"\${HISTORY_FLOOR:-0}\" ]]" "$workflow"

if grep -Fq "repos/\$GITHUB_REPOSITORY/commits/\$RELEASE_TAG" "$workflow"; then
  echo "channel promotion resolves an ambiguous branch-or-tag revision" >&2
  exit 1
fi
