#!/usr/bin/env python3
"""Bound the OS integration exception to authenticated protected-main history.

This helper must be loaded from the trusted PR base, never the proposed tree.
It neither certifies historical commits nor relaxes checks on new commits.
"""
from __future__ import annotations

import json
import re
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

REPOSITORY = "astrid-runtime/astrid"
OS_BRANCH = "os/universal"
COMMIT_SHA = re.compile(r"[0-9a-f]{40}\Z")


@dataclass(frozen=True)
class ImportScope:
    main_sha: str | None
    imported: frozenset[str]


def _sha(value: object) -> str:
    if not isinstance(value, str) or COMMIT_SHA.fullmatch(value) is None:
        raise ValueError("expected an exact lowercase 40-character commit SHA")
    return value


def _run(args: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=60, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError("unable to obtain trusted import ancestry") from error


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return _run(["git", "--no-replace-objects", "-C", str(repo), *args])


def _ancestor(repo: Path, ancestor: str, descendant: str) -> bool:
    result = _git(repo, "merge-base", "--is-ancestor", ancestor, descendant)
    if result.returncode not in (0, 1):
        raise ValueError("unable to prove commit ancestry")
    return result.returncode == 0


def protected_main_imports(
    commits: Sequence[Mapping[str, object]], event: object, repo: Path
) -> ImportScope:
    if not isinstance(event, dict):
        raise ValueError("invalid GitHub event")
    pr = event.get("pull_request")
    if not isinstance(pr, dict):
        raise ValueError("missing pull request event")
    base, head = pr.get("base"), pr.get("head")
    if not isinstance(base, dict) or not isinstance(head, dict):
        raise ValueError("missing pull request refs")
    base_repo, head_repo = base.get("repo"), head.get("repo")
    if not isinstance(base_repo, dict) or not isinstance(head_repo, dict):
        raise ValueError("missing pull request repository identity")
    if (
        base.get("ref") != OS_BRANCH
        or base_repo.get("full_name") != REPOSITORY
        or head_repo.get("full_name") != REPOSITORY
    ):
        return ImportScope(None, frozenset())

    base_sha, head_sha = _sha(base.get("sha")), _sha(head.get("sha"))
    checkout = _git(repo, "rev-parse", "HEAD")
    if checkout.returncode != 0 or checkout.stdout.strip() != base_sha:
        raise ValueError("import checker is not running from the trusted base checkout")
    branch_result = _run(["gh", "api", f"repos/{REPOSITORY}/branches/main"])
    if branch_result.returncode != 0:
        raise ValueError("unable to authenticate protected main")
    try:
        branch = json.loads(branch_result.stdout)
        if branch.get("name") != "main" or branch.get("protected") is not True:
            raise ValueError("main must be protected before history can be imported")
        main_sha = _sha(branch["commit"]["sha"])
    except (KeyError, TypeError, AttributeError, json.JSONDecodeError) as error:
        raise ValueError("invalid protected-main response") from error

    fetched = _git(
        repo, "fetch", "--no-tags", "--no-recurse-submodules",
        f"https://github.com/{REPOSITORY}.git", main_sha, head_sha,
    )
    if fetched.returncode != 0:
        raise ValueError("unable to fetch pinned main and PR ancestry")
    imported = set()
    seen = set()
    for commit in commits:
        sha = _sha(commit.get("sha"))
        if sha in seen:
            raise ValueError("duplicate commit metadata")
        seen.add(sha)
        if not _ancestor(repo, sha, head_sha):
            raise ValueError("commit metadata is not reachable from the exact PR head")
        if _ancestor(repo, sha, main_sha):
            imported.add(sha)
    # GitHub's PR commit listing has a service-side ceiling. Never let a
    # truncated listing omit a new contribution from DCO validation.
    listed = _git(repo, "rev-list", head_sha, "^" + base_sha)
    if listed.returncode != 0:
        raise ValueError("unable to enumerate the exact PR commit range")
    expected = {_sha(value) for value in listed.stdout.splitlines()}
    if seen != expected:
        raise ValueError("commit metadata does not cover the exact PR range")
    return ImportScope(main_sha, frozenset(imported))
