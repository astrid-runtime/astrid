#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
workflow="$repo_root/.github/workflows/promote-channel.yml"
release_workflow="$repo_root/.github/workflows/release.yml"
bootstrap_workflow="$repo_root/.github/workflows/bootstrap-channels.yml"

grep -Fq "if: github.ref == 'refs/heads/main'" "$workflow"
grep -Fq "repos/\$GITHUB_REPOSITORY/git/ref/tags/\$RELEASE_TAG" "$workflow"
grep -Fq "repos/\$GITHUB_REPOSITORY/git/tags/\$TAG_COMMIT" "$workflow"
grep -Fq "[[ \"\$TAG_TYPE\" == commit ]]" "$workflow"
grep -Fq "HISTORY_FLOOR=\$(jq -er '.\"history-floor\"' \"\$ASSET_PLAN\")" "$workflow"
grep -Fq -- "--generation \"\$HISTORY_FLOOR\"" "$workflow"
grep -Fq -- "--release-manifest \"\$RELEASE_METADATA\"" "$workflow"
grep -Fq 'BLAKE3SUMS.txt.sigstore.json' "$workflow"
grep -Fq 'validate-checksums' "$workflow"
grep -Fq 'select(.draft == false and .immutable == true)' "$workflow"
grep -Fq 'actions/workflows/release.yml/runs?event=push&status=completed' "$workflow"
grep -Fq ".head_branch == \$tag and .head_sha == \$commit and .conclusion == \"success\"" "$workflow"
grep -Fq 'release assets are write-once; never clobber, delete, or retag a published version' "$release_workflow"
grep -Fq 'overwrite_files: false' "$release_workflow"
grep -Fq 'draft: true' "$release_workflow"
grep -Fq 'EXISTING_RELEASE=1' "$release_workflow"
grep -Fq "SELECTED_RELEASE_ID=\$RELEASE_ID" "$release_workflow"
grep -Fq "[[ \"\$RELEASE_ID\" == \"\$SELECTED_RELEASE_ID\" ]]" "$release_workflow"
grep -Fq 'scripts/release_publication.py' "$release_workflow"
grep -Fq 'select(.draft == false and .immutable == true and .published_at != null)' "$release_workflow"
grep -Fq 'secrets.ASTRID_RELEASE_ADMIN_TOKEN' "$release_workflow"
grep -Fq 'secrets.CARGO_REGISTRY_TOKEN' "$release_workflow"
grep -Fq 'python3 scripts/crate_publication.py' "$release_workflow"
grep -Fq "cargo publish --locked -p \"\$crate\"" "$release_workflow"
grep -Fq ".version.checksum == \$expected and .version.yanked == false" "$release_workflow"
grep -Fq "[[ \"\$published\" == 1 ]]" "$release_workflow"
grep -Fq 'current pointer is malformed; continuity will use authenticated history' "$workflow"
grep -Fq "elif authenticate_current_history \"\$CURRENT\" recovered-current 0; then" "$workflow"
grep -Fq 'authenticated current pointer diverges from its immutable history' "$workflow"
grep -Fq 'current pointer is unauthenticated; continuity will use authenticated history' "$workflow"
grep -Fq "CURRENT_PRESENT=\$CURRENT_PRESENT" "$workflow"
grep -Fq "CURRENT_BUNDLE_PRESENT=\$CURRENT_BUNDLE_PRESENT" "$workflow"
grep -Fq "[[ \"\$GENERATION\" -ge \"\${HISTORY_FLOOR:-0}\" ]]" "$workflow"
grep -Fq 'scripts/channel_publication.py' "$workflow"
grep -Fq 'run the protected channel bootstrap before promotion' "$workflow"
grep -Fq "cmp -s \"\$HISTORY_ARCHIVE\" \"published-history/\$HISTORY_ARCHIVE\"" "$workflow"
grep -Fq "[[ \"\$(jq -er '.\"history-floor\"' \"\$ASSET_PLAN\")\" == \"\$HISTORY_FLOOR\" ]]" "$workflow"

grep -Fq "if: github.ref == 'refs/heads/main'" "$bootstrap_workflow"
grep -Fq 'secrets.ASTRID_RELEASE_ADMIN_TOKEN' "$bootstrap_workflow"
grep -Fq "gh release create \"\$tag\"" "$bootstrap_workflow"
grep -Fq '.draft == false and .prerelease == true and .immutable == false' "$bootstrap_workflow"
grep -Fq "repos/\$GITHUB_REPOSITORY/immutable-releases" "$bootstrap_workflow"

if grep -Fq "repos/\$GITHUB_REPOSITORY/commits/\$RELEASE_TAG" "$workflow"; then
  echo "channel promotion resolves an ambiguous branch-or-tag revision" >&2
  exit 1
fi
