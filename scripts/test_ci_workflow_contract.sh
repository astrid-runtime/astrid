#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
workflow="$repo_root/.github/workflows/ci.yml"

python3 - "$workflow" <<'PY'
from __future__ import annotations

import sys
from pathlib import Path


workflow_path = Path(sys.argv[1])
text = workflow_path.read_text(encoding="utf-8")


def fail(message: str) -> None:
    print(f"CI workflow contract: {message}", file=sys.stderr)
    raise SystemExit(1)


concurrency_marker = "concurrency:\n"
if text.count(concurrency_marker) != 1:
    fail("expected exactly one top-level concurrency block")

concurrency_start = text.index(concurrency_marker)
jobs_start = text.find("\njobs:\n", concurrency_start)
if jobs_start < 0:
    fail("missing jobs section after concurrency block")
concurrency = text[concurrency_start:jobs_start]

expected_group = (
    "  group: ${{ github.workflow }}-${{ github.event_name == 'pull_request' "
    "&& format('pr-{0}', github.event.pull_request.number) || "
    "format('run-{0}', github.run_id) }}"
)
expected_cancel = "  cancel-in-progress: ${{ github.event_name == 'pull_request' }}"

if expected_group not in concurrency:
    fail("group must key pull requests by workflow and PR, with unique non-PR run fallback")
if expected_cancel not in concurrency:
    fail("cancel-in-progress must be enabled only for pull_request events")
if "  cancel-in-progress: true" in concurrency or "  cancel-in-progress: false" in concurrency:
    fail("cancel-in-progress must remain event-scoped, not unconditional")

# Keep this contract wired to both CI trigger classes. Otherwise changing the
# test itself could silently stop exercising the workflow on one event class.
if text.count("      - 'scripts/test_ci_workflow_contract.sh'") != 2:
    fail("contract test must remain in both push and pull_request path filters")


def group(workflow_name: str, event_name: str, pr_number: int | None, run_id: int) -> str:
    if event_name == "pull_request":
        assert pr_number is not None
        return f"{workflow_name}-pr-{pr_number}"
    return f"{workflow_name}-run-{run_id}"


def cancel(event_name: str) -> bool:
    return event_name == "pull_request"


same_pr_old = group("CI", "pull_request", 1837, 101)
same_pr_new = group("CI", "pull_request", 1837, 102)
if same_pr_old != same_pr_new:
    fail("successive commits for one pull request must share a concurrency group")
if same_pr_new == group("CI", "pull_request", 1838, 103):
    fail("different pull requests must not share a concurrency group")

for event_name, run_id in (("push", 201), ("workflow_dispatch", 202)):
    if cancel(event_name):
        fail(f"{event_name} runs must not enable cancellation")
    if group("CI", event_name, None, run_id) == group("CI", event_name, None, run_id + 1):
        fail(f"successive {event_name} runs must not share a cancellation group")

if cancel("push") or cancel("workflow_dispatch"):
    fail("non-PR event cancellation guard regressed")
if group("CI", "push", None, 301) == group("CI", "push", None, 302):
    fail("main/tag pushes must use independent run groups")

print("CI workflow contract: PASS")
PY
