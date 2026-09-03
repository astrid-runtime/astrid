#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
workflow="$repo_root/.github/workflows/native-storage-certification.yml"

python3 - "$workflow" <<'PY'
from __future__ import annotations

import re
import sys
from pathlib import Path


workflow_path = Path(sys.argv[1])
text = workflow_path.read_text(encoding="utf-8")


def fail(message: str) -> None:
    print(f"native storage certification workflow contract: {message}", file=sys.stderr)
    raise SystemExit(1)


def step_block(name: str) -> str:
    marker = f"      - name: {name}\n"
    start = text.find(marker)
    if start < 0:
        fail(f"missing step: {name}")
    body_start = start + len(marker)
    next_step = re.search(r"^      - name: ", text[body_start:], flags=re.MULTILINE)
    end = body_start + next_step.start() if next_step else len(text)
    return text[body_start:end]


resolver = step_block("Resolve the exact release build artifact")
source_binding = step_block("Bind certification to protected-main source")
same_run = step_block("Download the same-run build artifact")
release_run = step_block("Download the released build artifact for the certified source")


def require(pattern: str, body: str, description: str) -> None:
    if not re.search(pattern, body, flags=re.MULTILINE):
        fail(f"missing {description}")


def require_persisted_echo(variable: str, value: str, description: str) -> None:
    lines = resolver.splitlines()
    echo = f'echo "{variable}={value}"'
    for index, line in enumerate(lines):
        if echo not in line:
            continue
        if re.search(r'>>\s*"\$GITHUB_ENV"', line):
            return
        # Accept the shell's grouped form: { echo ...; } >> "$GITHUB_ENV".
        opening = next(
            (candidate for candidate in range(index - 1, -1, -1) if lines[candidate].strip() == "{"),
            None,
        )
        if opening is None:
            continue
        if any(
            re.search(r'^\s*\}\s*>>\s*"\$GITHUB_ENV"\s*$', lines[candidate])
            for candidate in range(index + 1, len(lines))
        ):
            return
    fail(f"missing {description}")


# The standalone path must resolve a successful Release run and carry both
# identifiers into the action step; an artifact id alone searches this run.
require_persisted_echo("CERT_ARTIFACT_SOURCE", "release-run", "release-run source persistence")
require_persisted_echo("CERT_RELEASE_RUN_ID", "$RUN_ID", "CERT_RELEASE_RUN_ID persistence")
require_persisted_echo("CERT_ARTIFACT_ID", "$ARTIFACT_ID", "CERT_ARTIFACT_ID persistence")

if re.search(r"^\s*artifact-id\s*:", text, flags=re.MULTILINE):
    fail("singular artifact-id is unsupported; use artifact-ids")
require(r"^\s*if: env\.CERT_ARTIFACT_SOURCE == 'release-run'\s*$", release_run, "release-run condition")
require(
    r"^\s*uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c\s+# v8\.0\.1\s*$",
    release_run,
    "pinned release-run artifact action",
)
require(r"^\s*artifact-ids: \$\{\{ env\.CERT_ARTIFACT_ID \}\}\s*$", release_run, "release-run artifact-ids")
require(r"^\s*run-id: \$\{\{ env\.CERT_RELEASE_RUN_ID \}\}\s*$", release_run, "release-run run-id")
require(r"^\s*github-token: \$\{\{ github\.token \}\}\s*$", release_run, "release-run github-token")
require(
    r"^\s*path: \$\{\{ runner\.temp \}\}/fskit-cert-artifact\s*$",
    release_run,
    "release-run artifact path",
)

# Same-run artifacts are looked up by name in the calling Release run. Keep
# this branch distinct from the cross-run id-based download contract.
require(r"^\s*if: env\.CERT_ARTIFACT_SOURCE == 'same-run'\s*$", same_run, "same-run condition")
require(
    r"^\s*uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c\s+# v8\.0\.1\s*$",
    same_run,
    "pinned same-run artifact action",
)
require(r"^\s*name: binary-\$\{\{ env\.CERT_TRIPLE \}\}\s*$", same_run, "same-run artifact name")
require(
    r"^\s*path: \$\{\{ runner\.temp \}\}/fskit-cert-artifact\s*$",
    same_run,
    "same-run artifact path",
)
if re.search(r"^\s*(?:artifact-ids|run-id|github-token)\s*:", same_run, flags=re.MULTILINE):
    fail("same-run download must remain name-based without cross-run selectors")

# Protected-main dispatch and exact source binding are independent gates.
require(r'^\s*\[\[ "\$GITHUB_REF" == refs/heads/main \]\]', resolver, "protected-main standalone gate")
require(
    r'^\s*\[\[ "\$REQUESTED_SOURCE" =~ \^\[0-9a-f\]\{40\}\$ \]\]',
    source_binding,
    "exact source SHA shape gate",
)
require(
    r'git merge-base --is-ancestor "\$REQUESTED_SOURCE" origin/main',
    source_binding,
    "protected-main ancestor proof",
)
require(
    r'git checkout --detach --force "\$REQUESTED_SOURCE"',
    source_binding,
    "detached source checkout",
)
require(
    r"\[\[ \"\$\(git rev-parse 'HEAD\^\{commit\}'\)\" == \"\$REQUESTED_SOURCE\" \]\]",
    source_binding,
    "exact detached source binding",
)
require(
    r'echo "SOURCE_COMMIT=\$REQUESTED_SOURCE"\s*>> "\$GITHUB_ENV"',
    source_binding,
    "SOURCE_COMMIT environment binding",
)

# A reusable workflow is selected through its inputs, never by comparing the
# caller event name with the literal workflow_call trigger.
if re.search(
    r"(?:github\.event_name\s*(?:==|!=|===|!==)\s*['\"]workflow_call['\"]|['\"]workflow_call['\"]\s*(?:==|!=|===|!==)\s*github\.event_name)",
    text,
):
    fail("must not compare github.event_name to workflow_call")

print("native storage certification workflow contract: PASS")
PY
