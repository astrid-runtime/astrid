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
grep -Fq 'preserve_order: true' "$release_workflow"
grep -Fq 'draft: true' "$release_workflow"
grep -Fq 'EXISTING_RELEASE=1' "$release_workflow"
grep -Fq 'scripts/release_draft_recovery.py' "$release_workflow"
grep -Fq 'gh release upload "$GITHUB_REF_NAME" "$CANDIDATE/$asset"' "$release_workflow"
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
grep -A8 -F 'publish-stable-crates:' "$workflow" | grep -Fq 'actions: read'
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
grep -Fq 'CARGO_REGISTRY_TOKEN:' "$stable_crates_workflow"
grep -Fq 'secrets.CARGO_REGISTRY_TOKEN' "$stable_crates_workflow"
grep -Fq 'cargo install b3sum --version 1.8.5 --locked' "$stable_crates_workflow"
stable_toolchain_line=$(grep -n 'uses: dtolnay/rust-toolchain@' "$stable_crates_workflow" | cut -d: -f1)
stable_b3sum_line=$(grep -n 'cargo install b3sum --version 1.8.5 --locked' "$stable_crates_workflow" | cut -d: -f1)
[[ "$stable_toolchain_line" -lt "$stable_b3sum_line" ]]
grep -Fq 'CARGO_REGISTRY_TOKEN: ${{ secrets.CARGO_REGISTRY_TOKEN }}' "$workflow"
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

python3 - "$release_workflow" "$repo_root/.github/workflows/nightly.yml" <<'PY'
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path


release_path = Path(sys.argv[1])
nightly_path = Path(sys.argv[2])
repo_root = release_path.parent.parent.parent
text = release_path.read_text(encoding="utf-8")
nightly_text = nightly_path.read_text(encoding="utf-8")


def fail(message: str) -> None:
    print(f"release prepare-only workflow contract: {message}", file=sys.stderr)
    raise SystemExit(1)


def require(pattern: str, body: str = text, description: str | None = None) -> None:
    if not re.search(pattern, body, flags=re.MULTILINE):
        fail(f"missing {description or pattern}")


def job_block(name: str) -> str:
    marker = f"  {name}:\n"
    start = text.find(marker)
    if start < 0:
        fail(f"missing job: {name}")
    body_start = start + len(marker)
    next_job = re.search(r"^  [A-Za-z0-9_-]+:\n", text[body_start:], flags=re.MULTILINE)
    end = body_start + next_job.start() if next_job else len(text)
    return text[body_start:end]


def step_block(job: str, name: str) -> str:
    body = job_block(job)
    marker = f"      - name: {name}\n"
    start = body.find(marker)
    if start < 0:
        fail(f"missing step in {job}: {name}")
    body_start = start + len(marker)
    next_step = re.search(r"^      - (?:name|uses): ", body[body_start:], flags=re.MULTILINE)
    end = body_start + next_step.start() if next_step else len(body)
    return body[body_start:end]


# The prepare-only lane is dispatch-only, opt-in, and cannot affect the
# existing tag/nightly caller because both new inputs default to absent.
workflow_inputs_start = text.find("  workflow_dispatch:\n    inputs:\n")
prepare_input_start = text.find("      prepare_only:\n", workflow_inputs_start)
source_input_start = text.find("      source_commit:\n", workflow_inputs_start)
if workflow_inputs_start < 0 or prepare_input_start < 0 or source_input_start < 0:
    fail("missing optional prepare-only workflow inputs")
prepare_input = text[prepare_input_start:source_input_start]
source_input = text[source_input_start:text.find("\n\npermissions:", source_input_start)]
for value in ("required: false", "default: false", "type: boolean"):
    if value not in prepare_input:
        fail(f"prepare_only input is missing {value}")
for value in ("required: false", "type: string"):
    if value not in source_input:
        fail(f"source_commit input is missing {value}")

prepare_start = text.find('if [[ "$EVENT_NAME" == workflow_dispatch && "$PREPARE_ONLY" == true ]]; then')
prepare_end = text.find('elif [[ "$GITHUB_REF" == refs/tags/v* ]]; then', prepare_start)
if prepare_start < 0 or prepare_end < 0:
    fail("missing the prepare-only and legacy tag classification branches")
prepare = text[prepare_start:prepare_end]

# Prepare-only is confined to protected main and binds a lower-case 40-hex
# revision before the build reads any source from it.
require(r'^\s*\[\[ "\$GITHUB_REF" == refs/heads/main \]\]', prepare, "protected-main prepare gate")
require(
    r'^\s*\[\[ "\$REQUESTED_SOURCE" =~ \^\[0-9a-f\]\{40\}\$ \]\]',
    prepare,
    "exact 40-hex source gate",
)
require(
    r'^\s*git merge-base --is-ancestor "\$REQUESTED_SOURCE" origin/main',
    prepare,
    "requested source ancestry proof",
)
require(
    r'^\s*git checkout --detach --force "\$REQUESTED_SOURCE"$',
    prepare,
    "requested source checkout",
)
source_identity = """[[ "$(git rev-parse 'HEAD^{commit}')" == "$REQUESTED_SOURCE" ]]"""
if source_identity not in prepare:
    fail("missing requested source identity check")
version_command = '''VERSION=$(python3 -c 'import tomllib; print(tomllib.load(open("Cargo.toml", "rb"))["workspace"]["package"]["version"])')'''
if version_command not in prepare:
    fail("missing workspace Cargo.toml version derivation")
require(r'^            NIGHTLY=false$', prepare, "prepare-only nightly=false classification")
if prepare.find('NIGHTLY=true') >= 0:
    fail("prepare-only must not classify as nightly")

build = job_block("build")
classifier_relpath = "scripts/classify_release_build_matrix.py"
classifier = repo_root / classifier_relpath
matrix_invocation = f'BUILD_MATRIX=$(python3 {classifier_relpath})'
checkout_line = text.find("- uses: actions/checkout@")
matrix_invocation_index = text.find(matrix_invocation)
if checkout_line < 0 or matrix_invocation_index < 0 or checkout_line > matrix_invocation_index:
    fail("classified build matrix must be generated by the named script after checkout")
matrix_program = classifier.read_text(encoding="utf-8")
if "import os" not in matrix_program or "PREPARE_ONLY = os.environ.get(" not in matrix_program:
    fail("build matrix must read PREPARE_ONLY through the process environment")
for target in ("x86_64-apple-darwin", "aarch64-apple-darwin"):
    if f'"target": "{target}"' not in matrix_program:
        fail(f"classified build matrix is missing required Darwin target {target}")
conditional_start = matrix_program.find('if PREPARE_ONLY != "true":')
if conditional_start < 0:
    fail("missing prepare-only build matrix filter")
non_darwin = matrix_program[conditional_start:]
for target in (
    "x86_64-pc-windows-msvc",
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "x86_64-unknown-linux-musl",
    "aarch64-unknown-linux-musl",
):
    if f'"target": "{target}"' not in non_darwin:
        fail(f"classified build matrix does not preserve non-Darwin target {target} outside prepare-only")

expected_prepare_only = [
    {"target": "x86_64-apple-darwin", "os": "macos-latest", "archive": "tar.gz", "libc": "native"},
    {"target": "aarch64-apple-darwin", "os": "macos-latest", "archive": "tar.gz", "libc": "native"},
]
expected_full = expected_prepare_only + [
    {"target": "x86_64-pc-windows-msvc", "os": "windows-latest", "archive": "tar.gz", "libc": "native"},
    {"target": "x86_64-unknown-linux-gnu", "os": "ubuntu-latest", "archive": "tar.gz", "libc": "gnu"},
    {"target": "aarch64-unknown-linux-gnu", "os": "ubuntu-latest", "archive": "tar.gz", "libc": "gnu"},
    {
        "target": "x86_64-unknown-linux-musl",
        "os": "ubuntu-latest",
        "archive": "tar.gz",
        "libc": "musl",
        "platform": "linux/amd64",
        "image": "docker.io/library/rust@sha256:e98196986adced5602f6e21c54babdbf2a8700400c7a78868324a3630e0c5d15",
    },
    {
        "target": "aarch64-unknown-linux-musl",
        "os": "ubuntu-24.04-arm",
        "archive": "tar.gz",
        "libc": "musl",
        "platform": "linux/arm64",
        "image": "docker.io/library/rust@sha256:594694ee6b07747b63b5c265be2616b62e814180b66227e2c18c6ee85e4136be",
    },
]
for case, prepare_only in (
    ("true", "true"),
    ("false", "false"),
    ("empty", ""),
    ("absent", None),
):
    case_env = os.environ.copy()
    if prepare_only is None:
        case_env.pop("PREPARE_ONLY", None)
    else:
        case_env["PREPARE_ONLY"] = prepare_only
    result = subprocess.run(
        [sys.executable, str(classifier)],
        env=case_env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        fail(f"matrix classification failed for PREPARE_ONLY {case}: {result.stderr.strip()}")
    try:
        matrix = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        fail(f"matrix classification emitted invalid JSON for PREPARE_ONLY {case}: {error}")
    expected = expected_prepare_only if case == "true" else expected_full
    if matrix != {"include": expected}:
        fail(f"matrix classification has the wrong members for PREPARE_ONLY {case}")
    if case == "true" and any(entry["os"] != "macos-latest" for entry in matrix["include"]):
        fail("prepare-only matrix includes a non-Darwin runner")
    print(f"prepare-only matrix {case}: {','.join(entry['target'] for entry in matrix['include'])}")
if 'matrix: ${{ fromJSON(needs.classify.outputs.build-matrix) }}' not in build:
    fail("build job does not consume the classified build matrix")
require(
    r"^\s*ref: \$\{\{ needs\.classify\.outputs\.source-commit \}\}\s*$",
    build,
    "build checkout bound to the classified source commit",
)
if re.search(r"^\s*environment:\s*release\s*$", build, flags=re.MULTILINE):
    fail("Darwin build must stay outside the release environment")

package = step_block("build", "Package binaries")
require(
    r"^\s*VERSION: \$\{\{ needs\.classify\.outputs\.version \}\}\s*$",
    package,
    "packaging bound to the classified version",
)
if "GITHUB_REF_NAME" in package:
    fail("prepare-only packaging must not derive its archive name from GITHUB_REF_NAME")
require(
    r"^\s*name: binary-\$\{\{ matrix\.target \}\}\s*$",
    build,
    "triple-named binary upload",
)

fskit = job_block("fskit-certification")
release = job_block("github-release")
for name, block in (("fskit-certification", fskit), ("github-release", release)):
    if not re.search(r"^\s*if: \$\{\{ !inputs\.prepare_only \}\}\s*$", block, flags=re.MULTILINE):
        fail(f"{name} is not skipped by prepare_only")

nightly_dispatch = 'gh workflow run release.yml --ref "$TAG"'
if nightly_dispatch not in nightly_text:
    fail("missing unchanged nightly Release dispatch")
if "prepare_only=" in nightly_text:
    fail("nightly must continue to call Release without prepare-only inputs")

print("release prepare-only workflow contract: PASS")
PY
