#!/usr/bin/env python3
"""Lint the copyable repository template without third-party dependencies."""

from __future__ import annotations

import re
from pathlib import Path
import sys


SHA_RE = re.compile(r"^[0-9a-f]{40}$")
USES_RE = re.compile(r"^\s*uses:\s*([^\s#]+)@([^\s#]+)")


def fail(message: str) -> None:
    raise SystemExit(f"template lint: {message}")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    workflows = sorted((root / ".github" / "workflows").glob("*.yml"))
    if not workflows:
        fail("no workflow templates found")
    blocked_rotation = root / ".github" / "workflows" / "rotate-timestamp.yml"
    if blocked_rotation.exists():
        fail("rotate-timestamp.yml is blocked until a reviewed timestamp-only API exists")
    for workflow in workflows:
        text = workflow.read_text(encoding="utf-8")
        if "permissions:" not in text:
            fail(f"{workflow.name} must declare explicit permissions")
        if "gh api" in text or "api.github.com" in text or "github.rest" in text:
            fail(f"{workflow.name} must not use GitHub API for anonymous client data")
        if "INDEX_TOOL_SHA" not in text:
            fail(f"{workflow.name} must pin the external index tool by commit SHA")
        for stale in ("bin/index-tool", "validate-pr", "tuf verify", "tuf rotate-timestamp"):
            if stale in text:
                fail(f"{workflow.name} invokes unavailable command or path: {stale}")
        for line in text.splitlines():
            match = USES_RE.match(line)
            if not match:
                continue
            ref = match.group(2)
            if not SHA_RE.fullmatch(ref):
                fail(f"{workflow.name} has an unpinned action: {match.group(1)}@{ref}")
    pages = (root / ".github" / "workflows" / "publish-pages.yml").read_text(encoding="utf-8")
    if "needs: sign-pages" not in pages or "environment:" not in pages:
        fail("publish-pages.yml must deploy only after sign-pages verification with an Environment")
    if "upload-pages-artifact" not in pages or "deploy-pages" not in pages:
        fail("publish-pages.yml must use the Pages artifact/deploy actions")
    if "cargo build --locked --release" not in pages or "target/release/astrid-index-tool" not in pages:
        fail("publish-pages.yml must build and invoke the pinned astrid-index-tool binary")
    for command in ("generate", "sign-pages"):
        if command not in pages:
            fail(f"publish-pages.yml must invoke astrid-index-tool {command}")
    for argument in (
        "--input",
        "--output",
        "--event-authorization curator-review",
        "--targets-key",
        "--snapshot-key",
        "--timestamp-key",
        "--targets-version",
        "--snapshot-version",
        "--timestamp-version",
        "--targets-expires",
        "--snapshot-expires",
        "--timestamp-expires",
    ):
        if argument not in pages:
            fail(f"publish-pages.yml is missing sign-pages argument {argument}")
    pr = (root / ".github" / "workflows" / "validate-index-pr.yml").read_text(encoding="utf-8")
    if "cargo build --locked --release" not in pr or "target/release/astrid-index-tool" not in pr:
        fail("validate-index-pr.yml must build and invoke the pinned astrid-index-tool binary")
    if (
        " validate \\\n" not in pr
        or "--base" not in pr
        or "--candidate" not in pr
        or "--event-authorization curator-review" not in pr
    ):
        fail("validate-index-pr.yml must invoke validate --base PATH --candidate PATH with curator-review authorization")
    validator = root / "scripts" / "index_repository_validate.py"
    if not validator.is_file():
        fail("index_repository_validate.py is missing")
    print(f"ok: {len(workflows)} workflow templates, validator present")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
