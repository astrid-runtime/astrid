#!/usr/bin/env python3
"""Check the campaign branch and path coverage in GitHub Actions workflows.

This intentionally parses only the small YAML subset used by workflow trigger
blocks.  Keeping the check dependency-free makes it runnable before CI can run.
"""

from __future__ import annotations

import re
import sys
from collections.abc import Mapping
from pathlib import Path


CAMPAIGN_BRANCH = "os/universal"
MAIN_BRANCH = "main"
CODEX_BRANCH_PREFIX = "codex/"

OWNED_WORKFLOWS = frozenset(
    {
        "ci.yml",
        "pr-checks.yml",
        "changelog.yml",
        "codeql.yml",
        "dependency-review.yml",
        "runtime-e2e.yml",
        "macos-v0104-upgrade.yml",
        "windows-local-transport.yml",
    }
)
PUSH_CAMPAIGN_WORKFLOWS = frozenset(
    {
        "ci.yml",
        "codeql.yml",
        "macos-v0104-upgrade.yml",
        "runtime-e2e.yml",
        "windows-local-transport.yml",
    }
)
PROTECTED_WORKFLOWS = frozenset({"release.yml", "scorecard.yml", "native-kernel.yml"})


def _event_block(text: str, event: str) -> list[str] | None:
    """Return the lines nested under a top-level ``on.<event>`` entry."""

    lines = text.splitlines()
    event_pattern = re.compile(rf"^  {re.escape(event)}:\s*(?:#.*)?$")
    top_level_pattern = re.compile(r"^[^\s#].*:")

    for index, line in enumerate(lines):
        if not event_pattern.match(line):
            continue
        end = len(lines)
        for candidate, candidate_line in enumerate(lines[index + 1 :], index + 1):
            if top_level_pattern.match(candidate_line):
                end = candidate
                break
        return lines[index + 1 : end]
    return None


def _clean_scalar(value: str) -> str:
    value = value.split(" #", 1)[0].strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        return value[1:-1]
    return value


def _inline_values(value: str) -> list[str]:
    value = value.strip()
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    if not value:
        return []
    return [_clean_scalar(item) for item in value.split(",") if _clean_scalar(item)]


def _field_values(block: list[str], field: str) -> list[str] | None:
    """Read a four-space workflow field in inline or block-list form."""

    field_pattern = re.compile(rf"^    {re.escape(field)}:\s*(.*?)\s*$")
    list_item_pattern = re.compile(r"^      -\s*(.*?)\s*$")

    for index, line in enumerate(block):
        match = field_pattern.match(line)
        if not match:
            continue
        inline = match.group(1)
        if inline:
            return _inline_values(inline)

        values: list[str] = []
        for candidate in block[index + 1 :]:
            if re.match(r"^    \S", candidate):
                break
            item = list_item_pattern.match(candidate)
            if item:
                value = _clean_scalar(item.group(1))
                if value:
                    values.append(value)
        return values
    return None


def _event_field_values(text: str, event: str, field: str) -> list[str] | None:
    block = _event_block(text, event)
    return None if block is None else _field_values(block, field)


def _has_codex_filter(branches: list[str]) -> bool:
    return any(branch.startswith(CODEX_BRANCH_PREFIX) for branch in branches)


def validate_workflows(workflows: Mapping[str, str]) -> list[str]:
    """Return human-readable trigger-policy violations for loaded workflows."""

    errors: list[str] = []

    for name, text in sorted(workflows.items()):
        pull_request_branches = _event_field_values(text, "pull_request", "branches")
        if pull_request_branches is not None:
            if name in PROTECTED_WORKFLOWS:
                if CAMPAIGN_BRANCH in pull_request_branches or _has_codex_filter(pull_request_branches):
                    errors.append(f"{name}: protected workflow has a campaign pull_request branch")
            else:
                missing = {MAIN_BRANCH, CAMPAIGN_BRANCH}.difference(pull_request_branches)
                if missing:
                    errors.append(
                        f"{name}: pull_request.branches is missing {', '.join(sorted(missing))}"
                    )
                if _has_codex_filter(pull_request_branches):
                    errors.append(f"{name}: pull_request.branches must not include codex branch filters")

        push_branches = _event_field_values(text, "push", "branches")
        if push_branches is not None:
            if MAIN_BRANCH not in push_branches:
                errors.append(f"{name}: push.branches must preserve main")
            if CAMPAIGN_BRANCH in push_branches and name not in PUSH_CAMPAIGN_WORKFLOWS:
                errors.append(f"{name}: os/universal push coverage is not authorized")
            if _has_codex_filter(push_branches):
                errors.append(f"{name}: push.branches must not include codex branch filters")

        if name in PROTECTED_WORKFLOWS:
            for event in ("pull_request", "push"):
                branches = _event_field_values(text, event, "branches")
                if branches and (CAMPAIGN_BRANCH in branches or _has_codex_filter(branches)):
                    errors.append(f"{name}: protected workflow gained campaign branch expansion")

    for name in PUSH_CAMPAIGN_WORKFLOWS:
        text = workflows.get(name)
        if text is None:
            errors.append(f"{name}: authorized post-integration push workflow is missing")
            continue
        branches = _event_field_values(text, "push", "branches")
        if branches is None or CAMPAIGN_BRANCH not in branches:
            errors.append(f"{name}: push.branches must include os/universal")

    for name in OWNED_WORKFLOWS:
        text = workflows.get(name)
        if text is None:
            errors.append(f"{name}: owned workflow is missing")
            continue
        for event in ("pull_request", "push"):
            branches = _event_field_values(text, event, "branches")
            if branches and _has_codex_filter(branches):
                errors.append(f"{name}: {event}.branches must not include codex branch filters")

    changelog = workflows.get("changelog.yml")
    if changelog is None:
        errors.append("changelog.yml: workflow is missing")
    else:
        paths = _event_field_values(changelog, "pull_request", "paths")
        if paths is None:
            errors.append("changelog.yml: pull_request.paths is missing")
        else:
            for required_path in ("docs/**", "changes/**"):
                if required_path not in paths:
                    errors.append(f"changelog.yml: pull_request.paths is missing {required_path}")

    return errors


def load_workflows(repo_root: Path) -> dict[str, str]:
    workflows_dir = repo_root / ".github" / "workflows"
    paths = sorted({*workflows_dir.glob("*.yml"), *workflows_dir.glob("*.yaml")})
    return {path.name: path.read_text(encoding="utf-8") for path in paths}


def check_repository(repo_root: Path) -> list[str]:
    return validate_workflows(load_workflows(repo_root))


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    errors = check_repository(repo_root)
    if errors:
        print("Campaign CI trigger policy failed:", file=sys.stderr)
        for error in errors:
            print(f"::error::{error}", file=sys.stderr)
        return 1
    print("Campaign CI trigger policy passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
