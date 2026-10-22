#!/usr/bin/env python3
"""Validate DCO sign-offs in the commits belonging to a pull request."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Iterable, Mapping
from pathlib import Path


SIGNED_OFF_BY = re.compile(
    r"(?im)^Signed-off-by:\s*(?P<name>[^<\n]+?)\s*<(?P<email>[^>\n]+)>\s*$"
)


def _flatten_commits(payload: object) -> Iterable[Mapping[str, object]]:
    if not isinstance(payload, list):
        raise ValueError("expected the GitHub commits response to be a JSON array")

    for item in payload:
        if isinstance(item, list):
            yield from _flatten_commits(item)
        elif isinstance(item, dict):
            yield item
        else:
            raise ValueError("expected every GitHub commit entry to be an object")


def _is_bot(commit: Mapping[str, object]) -> bool:
    # `author.login` is GitHub's API identity field, not commit-message text.
    author = commit.get("author")
    return isinstance(author, dict) and str(author.get("login", "")).endswith("[bot]")


def check_commits(payload: object, *, require_all_contributions: bool = False) -> list[str]:
    errors: list[str] = []

    for commit in _flatten_commits(payload):
        sha = str(commit.get("sha", "unknown"))[:12]
        parents = commit.get("parents")
        if not require_all_contributions and isinstance(parents, list) and len(parents) > 1:
            # Merge commits are transport history, not authored patch commits.
            continue
        if not require_all_contributions and _is_bot(commit):
            continue

        commit_metadata = commit.get("commit")
        if not isinstance(commit_metadata, dict):
            errors.append(f"{sha}: missing commit metadata")
            continue

        author_metadata = commit_metadata.get("author")
        author_email = ""
        if isinstance(author_metadata, dict):
            author_email = str(author_metadata.get("email", "")).strip()
        message = str(commit_metadata.get("message", ""))
        signoff_emails = [match.group("email").strip() for match in SIGNED_OFF_BY.finditer(message)]

        if not signoff_emails:
            errors.append(f"{sha}: missing Signed-off-by trailer")
            continue
        if not author_email:
            errors.append(f"{sha}: commit author has no email to validate against the sign-off")
            continue
        if author_email.casefold() not in {email.casefold() for email in signoff_emails}:
            errors.append(
                f"{sha}: Signed-off-by email must match the commit author email ({author_email})"
            )

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("commits_json", type=Path)
    parser.add_argument("--event-json", type=Path)
    parser.add_argument("--git-repo", type=Path)
    args = parser.parse_args()

    try:
        payload = json.loads(args.commits_json.read_text(encoding="utf-8"))
        if (args.event_json is None) != (args.git_repo is None):
            raise ValueError("event and trusted Git checkout must be supplied together")
        if args.event_json is not None:
            from check_dco_import_scope import protected_main_imports

            commits = tuple(_flatten_commits(payload))
            event = json.loads(args.event_json.read_text(encoding="utf-8"))
            scope = protected_main_imports(commits, event, args.git_repo)
            if scope.main_sha is not None:
                print(f"Protected main import pin: {scope.main_sha}")
                for sha in sorted(scope.imported):
                    print(f"Already admitted on protected main: {sha}")
            payload = [item for item in commits if item.get("sha") not in scope.imported]
        errors = check_commits(payload, require_all_contributions=(
            args.event_json is not None and scope.main_sha is not None
        ))
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"::error::Unable to validate DCO commits: {error}")
        return 1

    if errors:
        print("::error::Every checked contribution must carry a matching DCO sign-off:")
        for error in errors:
            print(f"::error::  {error}")
        return 1

    print("DCO sign-off check passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
