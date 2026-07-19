#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
workflow="$repo_root/.github/workflows/promote-channel.yml"
release_workflow="$repo_root/.github/workflows/release.yml"
bootstrap_workflow="$repo_root/.github/workflows/bootstrap-channels.yml"
nightly_workflow="$repo_root/.github/workflows/nightly.yml"
nightly_promotion_workflow="$repo_root/.github/workflows/promote-nightly.yml"
stable_crates_workflow="$repo_root/.github/workflows/publish-stable-crates.yml"
stable_crates_script="$repo_root/scripts/publish_crates_io.sh"

grep -Fq "if: github.ref == 'refs/heads/main'" "$workflow"
if grep -Fq 'TAP_DISPATCH_TOKEN' "$workflow" || \
  grep -Fq 'homebrew-tap/dispatches' "$workflow"; then
  echo "channel promotion must not push caller-selected versions to Homebrew" >&2
  exit 1
fi
grep -Fq "repos/\$GITHUB_REPOSITORY/git/ref/tags/\$RELEASE_TAG" "$workflow"
grep -Fq "repos/\$GITHUB_REPOSITORY/git/tags/\$TAG_COMMIT" "$workflow"
grep -Fq "[[ \"\$TAG_TYPE\" == commit ]]" "$workflow"
grep -Fq "HISTORY_FLOOR=\$(jq -er '.\"history-floor\"' \"\$ASSET_PLAN\")" "$workflow"
grep -Fq -- "--generation \"\$HISTORY_FLOOR\"" "$workflow"
grep -Fq -- "--release-manifest \"\$RELEASE_METADATA\"" "$workflow"
grep -Fq 'BLAKE3SUMS.txt.sigstore.json' "$workflow"
grep -Fq 'validate-checksums' "$workflow"
grep -Fq '.immutable == true and .prerelease == $prerelease' "$workflow"
grep -Fq 'actions/workflows/release.yml/runs?status=completed' "$workflow"
grep -Fq '.event == $event and .head_branch == $tag and .head_sha == $commit and .conclusion == "success"' "$workflow"
grep -Fq 'release assets are write-once; never clobber, delete, or retag a published version' "$release_workflow"
grep -Fq 'overwrite_files: false' "$release_workflow"
grep -Fq 'draft: true' "$release_workflow"
grep -Fq 'EXISTING_RELEASE=1' "$release_workflow"
grep -Fq "SELECTED_RELEASE_ID=\$RELEASE_ID" "$release_workflow"
grep -Fq "[[ \"\$RELEASE_ID\" == \"\$SELECTED_RELEASE_ID\" ]]" "$release_workflow"
grep -Fq 'scripts/release_publication.py' "$release_workflow"
grep -Fq '.immutable == true and .prerelease == $prerelease and .published_at != null' "$release_workflow"
grep -Fq 'actions/runs/$GITHUB_RUN_ID' "$release_workflow"
grep -Fq -- "- '!v[0-9]+.*-nightly.*'" "$release_workflow"
grep -Fq 'git/matching-refs/tags/v$BASE_VERSION' "$release_workflow"
grep -Fq 'repos/$GITHUB_REPOSITORY/git/ref/tags/$GITHUB_REF_NAME' "$release_workflow"
grep -Fq -- '-f make_latest="$EXPECTED_LATEST"' "$release_workflow"
grep -Fq 'secrets.ASTRID_RELEASE_ADMIN_TOKEN' "$release_workflow"
if grep -Fq 'CARGO_REGISTRY_TOKEN' "$release_workflow" || \
  grep -Fq 'cargo publish' "$release_workflow"; then
  echo "immutable candidate creation must not publish crates.io packages" >&2
  exit 1
fi
grep -Fq "if: github.ref == 'refs/heads/main' && inputs.channel == 'stable'" "$workflow"
grep -Fq 'uses: ./.github/workflows/publish-stable-crates.yml' "$workflow"
if grep -Fq 'secrets: inherit' "$workflow"; then
  echo "stable crates publication must not inherit unrelated caller secrets" >&2
  exit 1
fi
grep -Fq "inputs.channel != 'stable' || needs.publish-stable-crates.result == 'success'" "$workflow"
grep -Fq 'workflow_call:' "$stable_crates_workflow"
if grep -Fq 'workflow_dispatch:' "$stable_crates_workflow"; then
  echo "crates.io publication must only be reachable through stable promotion" >&2
  exit 1
fi
grep -Fq 'environment: release' "$stable_crates_workflow"
grep -Fq "if: github.ref == 'refs/heads/main'" "$stable_crates_workflow"
grep -Fq -- '--expected-channel dev' "$stable_crates_workflow"
grep -Fq 'secrets.CARGO_REGISTRY_TOKEN' "$stable_crates_workflow"
grep -Fq 'scripts/publish_crates_io.sh' "$stable_crates_workflow"
grep -Fq 'python3 "$script_root/crate_publication.py"' "$stable_crates_script"
grep -Fq 'crates.io publication requires a canonical X.Y.Z version' "$stable_crates_script"
grep -Fq 'expected 26 publishable workspace crates' "$stable_crates_script"
grep -Fq "cargo publish --locked -p \"\$crate\"" "$stable_crates_script"
grep -Fq ".version.checksum == \$expected and .version.yanked == false" "$stable_crates_script"
grep -Fq "[[ \"\$published\" == 1 ]]" "$stable_crates_script"
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
grep -Fq "jq -e '.enabled == true'" "$bootstrap_workflow"
grep -Fq "jq -e '.enabled == false'" "$bootstrap_workflow"

grep -Fq 'vars.ASTRID_NIGHTLY_RELEASES_ENABLED' "$nightly_workflow"
grep -Fq 'actions/runs/$GITHUB_RUN_ID' "$nightly_workflow"
grep -Fq 'git/matching-refs/tags/v$BASE_VERSION' "$nightly_workflow"
grep -Fq 'gh workflow run release.yml --ref "$TAG"' "$nightly_workflow"
grep -Fq 'recover-promotion=true' "$nightly_workflow"
grep -Fq 'gh workflow run promote-channel.yml' "$nightly_workflow"
grep -Fq '.run_number] | unique | if length == 1' "$nightly_workflow"
grep -Fq 'git merge-base --is-ancestor "$SOURCE_COMMIT" origin/main' "$nightly_workflow"
grep -Fq 'git merge-base --is-ancestor "$SOURCE_COMMIT" origin/main' "$release_workflow"
grep -Fq 'workflow_run:' "$nightly_promotion_workflow"
grep -Fq "github.event.workflow_run.conclusion == 'success'" "$nightly_promotion_workflow"
grep -Fq 'gh workflow run promote-channel.yml' "$nightly_promotion_workflow"

if grep -Fq "repos/\$GITHUB_REPOSITORY/commits/\$RELEASE_TAG" "$workflow"; then
  echo "channel promotion resolves an ambiguous branch-or-tag revision" >&2
  exit 1
fi
