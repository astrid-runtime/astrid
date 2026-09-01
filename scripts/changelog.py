#!/usr/bin/env python3
"""Changelog fragments for pull requests and Keep a Changelog release rolls."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from collections import OrderedDict
from collections.abc import Iterable, Sequence
from pathlib import Path


KINDS = ("added", "changed", "deprecated", "removed", "fixed", "security")
KIND_HEADING = {kind: kind.title() for kind in KINDS}
FRAGMENT_NAME = re.compile(rf"^(\d+)\.({'|'.join(KINDS)})\.md$")
VERSION_HEADER_PREFIX = "## ["
UNRELEASED_HEADER = "## [Unreleased]"
CODE_FILENAMES = {"Cargo.toml", "Cargo.lock"}
SKIP_LABEL = "skip-changelog"
ALLOWED_CHANGES_FILES = {".gitkeep"}


def is_code_path(path: str) -> bool:
    name = Path(path).name
    return path.endswith(".rs") or name in CODE_FILENAMES


def parse_labels(raw: str) -> list[str]:
    # GitHub's join expression renders a quoted '\n' as two literal characters.
    normalized = raw.replace(r"\n", "\n")
    return [part.strip() for part in re.split(r"[\s,]+", normalized) if part.strip()]


def has_skip_changelog(labels: Iterable[str]) -> bool:
    return any(label.casefold() == SKIP_LABEL for label in labels)


def pending_fragment_paths(changes_dir: Path) -> list[Path]:
    if not changes_dir.is_dir():
        return []
    return [
        path
        for path in sorted(changes_dir.iterdir())
        if path.is_file() and path.name not in ALLOWED_CHANGES_FILES
    ]


def entry_from_fragment(body: str) -> str:
    text = body.strip("\n")
    if not text.strip():
        raise ValueError("fragment body is empty")
    lines = text.splitlines()
    if not lines[0].lstrip().startswith("- "):
        lines[0] = f"- {lines[0]}"
        lines = [
            lines[0],
            *[line if not line or line.startswith(" ") else f"  {line}" for line in lines[1:]],
        ]
    elif not lines[0].startswith("- "):
        lines[0] = lines[0].lstrip()
    return "\n".join(lines).rstrip() + "\n"


def git_diff_names(*, base: str, head: str, diff_filter: str | None = None) -> list[str]:
    command = ["git", "diff", "--name-only"]
    if diff_filter:
        command.append(f"--diff-filter={diff_filter}")
    command.append(f"{base}...{head}")
    result = subprocess.run(command, check=False, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "git diff failed")
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def check_pr(
    *,
    labels: Iterable[str],
    changed_paths: Sequence[str],
    added_paths: Sequence[str],
    changes_dir: str = "changes",
) -> list[str]:
    errors: list[str] = []
    added_fragments: list[str] = []
    prefix = changes_dir.rstrip("/") + "/"

    for path in added_paths:
        if not path.startswith(prefix):
            continue
        relative = path[len(prefix) :]
        if "/" in relative or relative in ALLOWED_CHANGES_FILES:
            continue
        if FRAGMENT_NAME.fullmatch(relative):
            added_fragments.append(path)
        else:
            errors.append(
                f"{path}: name must be {{issue}}.{{kind}}.md with kind "
                f"{'|'.join(KINDS)}"
            )

    if errors:
        return errors
    if has_skip_changelog(labels):
        return []
    code_changed = any(is_code_path(path) for path in changed_paths)
    changelog_changed = any(Path(path).name == "CHANGELOG.md" for path in changed_paths)
    if code_changed and changelog_changed:
        errors.append(
            "Ordinary code PRs must not edit CHANGELOG.md; add "
            f"{changes_dir}/{{issue}}.{{kind}}.md instead. Release PRs that "
            f"roll CHANGELOG.md should use the {SKIP_LABEL} label."
        )
        return errors
    if not code_changed:
        return []
    if added_fragments:
        return []

    errors.append(
        "Every code PR must add a changelog fragment under "
        f"{changes_dir}/{{issue}}.{{kind}}.md (or the {SKIP_LABEL} label). "
        "Do not edit CHANGELOG.md on ordinary PRs."
    )
    return errors


def _section_heading(line: str) -> str | None:
    if not line.startswith("### "):
        return None
    return line[4:].strip()


def parse_unreleased_sections(body: str) -> OrderedDict[str, str]:
    sections: OrderedDict[str, str] = OrderedDict()
    current: str | None = None
    chunks: list[str] = []

    def flush() -> None:
        nonlocal current, chunks
        if current is None:
            if "".join(chunks).strip():
                raise ValueError(
                    "unreleased text before the first ### heading is not a Keep a Changelog section"
                )
            chunks = []
            return
        sections[current] = "".join(chunks)
        chunks = []

    for line in body.splitlines(keepends=True):
        heading = _section_heading(line.rstrip("\n"))
        if heading is not None:
            flush()
            current = heading
            continue
        chunks.append(line)
    flush()
    return sections


def render_sections(sections: OrderedDict[str, str]) -> str:
    parts: list[str] = []
    for heading, body in sections.items():
        if not body.strip():
            continue
        parts.append(f"### {heading}\n")
        text = body if body.startswith("\n") else "\n" + body
        if not text.endswith("\n"):
            text += "\n"
        parts.append(text)
        if not text.endswith("\n\n"):
            parts.append("\n")
    return "".join(parts)


def split_changelog(text: str) -> tuple[str, str, str]:
    lines = text.splitlines(keepends=True)
    unreleased_at = next(
        (i for i, line in enumerate(lines) if line.rstrip("\n") == UNRELEASED_HEADER),
        None,
    )
    if unreleased_at is None:
        raise ValueError("CHANGELOG.md is missing ## [Unreleased]")
    rest_at = next(
        (
            i
            for i, line in enumerate(lines[unreleased_at + 1 :], start=unreleased_at + 1)
            if line.startswith(VERSION_HEADER_PREFIX)
        ),
        len(lines),
    )
    preamble = "".join(lines[:unreleased_at])
    unreleased = "".join(lines[unreleased_at + 1 : rest_at])
    rest = "".join(lines[rest_at:])
    return preamble, unreleased, rest


def load_fragments(changes_dir: Path) -> list[tuple[Path, str, str]]:
    loaded: list[tuple[Path, str, str]] = []
    for path in pending_fragment_paths(changes_dir):
        match = FRAGMENT_NAME.fullmatch(path.name)
        if match is None:
            raise ValueError(f"{path}: name must be {{issue}}.{{kind}}.md")
        loaded.append((path, match.group(2), path.read_text(encoding="utf-8")))
    return loaded


def merge_fragments(
    unreleased_body: str, fragments: Sequence[tuple[Path, str, str]]
) -> OrderedDict[str, str]:
    sections = parse_unreleased_sections(unreleased_body)
    kind_rank = {kind: index for index, kind in enumerate(KINDS)}
    for _path, kind, body in sorted(
        fragments, key=lambda item: (kind_rank[item[1]], item[0].name)
    ):
        heading = KIND_HEADING[kind]
        entry = entry_from_fragment(body)
        current = sections.get(heading, "")
        if current.strip():
            current = current.rstrip() + "\n\n" + entry
        else:
            current = "\n" + entry
        sections[heading] = current if current.endswith("\n") else current + "\n"
    return sections


def roll_changelog(
    text: str,
    *,
    version: str,
    date: str,
    fragments: Sequence[tuple[Path, str, str]],
) -> str:
    preamble, unreleased, rest = split_changelog(text)
    rendered = render_sections(merge_fragments(unreleased, fragments))
    rolled = preamble
    if rolled and not rolled.endswith("\n"):
        rolled += "\n"
    rolled += f"{UNRELEASED_HEADER}\n\n"
    rolled += f"## [{version}] - {date}\n"
    if rendered:
        rolled += "\n" + rendered
        if not rolled.endswith("\n"):
            rolled += "\n"
        if not rolled.endswith("\n\n"):
            rolled += "\n"
    else:
        rolled += "\n"
    rolled += rest
    return rolled


def extract_notes(text: str, version: str) -> str:
    needle = f"{VERSION_HEADER_PREFIX}{version}]"
    lines = text.splitlines(keepends=True)
    found = False
    collected: list[str] = []
    for line in lines:
        if not found:
            if line.startswith(needle):
                found = True
            continue
        if line.startswith(VERSION_HEADER_PREFIX):
            break
        collected.append(line)
    return "".join(collected).strip("\n") + ("\n" if collected else "")


def fragment_body_errors(added_paths: Sequence[str], *, changes_dir: str = "changes") -> list[str]:
    errors: list[str] = []
    prefix = changes_dir.rstrip("/") + "/"
    for path in added_paths:
        if not path.startswith(prefix) or not FRAGMENT_NAME.fullmatch(Path(path).name):
            continue
        try:
            entry_from_fragment(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            errors.append(f"{path}: {error}")
    return errors


def cmd_check(args: argparse.Namespace) -> int:
    labels = parse_labels(args.labels or os.environ.get("PR_LABELS", ""))
    try:
        changed = git_diff_names(base=args.base, head=args.head)
        added = git_diff_names(base=args.base, head=args.head, diff_filter="A")
        errors = check_pr(
            labels=labels,
            changed_paths=changed,
            added_paths=added,
            changes_dir=args.changes_dir,
        )
        errors.extend(fragment_body_errors(added, changes_dir=args.changes_dir))
    except (OSError, RuntimeError, ValueError) as error:
        print(f"::error::Unable to validate changelog fragments: {error}")
        return 1

    if errors:
        print("::error::Changelog fragment check failed:")
        for error in errors:
            print(f"::error::  {error}")
        return 1

    print("Changelog fragment check passed.")
    return 0


def cmd_roll(args: argparse.Namespace) -> int:
    changelog = Path(args.changelog)
    changes_dir = Path(args.changes_dir)
    try:
        fragments = load_fragments(changes_dir)
        rolled = roll_changelog(
            changelog.read_text(encoding="utf-8"),
            version=args.version,
            date=args.date,
            fragments=fragments,
        )
        if args.dry_run:
            sys.stdout.write(rolled)
            return 0
        changelog.write_text(rolled, encoding="utf-8")
        for path, _, _ in fragments:
            path.unlink()
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(
        f"Rolled {len(fragments)} fragment(s) into {changelog} as [{args.version}] - {args.date}."
    )
    return 0


def cmd_notes(args: argparse.Namespace) -> int:
    try:
        pending = pending_fragment_paths(Path(args.changes_dir))
        if args.require_rolled and pending:
            names = ", ".join(path.name for path in pending)
            raise ValueError(
                "unrolled changelog fragments remain in "
                f"{args.changes_dir}/ ({names}); run scripts/changelog.py roll "
                "before tagging a release"
            )
        notes = extract_notes(
            Path(args.changelog).read_text(encoding="utf-8"), args.version
        )
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    sys.stdout.write(notes)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="require a new fragment on code PRs")
    check.add_argument(
        "--base",
        required=True,
        help="base SHA (usually github.event.pull_request.base.sha)",
    )
    check.add_argument("--head", default="HEAD")
    check.add_argument("--labels", default="")
    check.add_argument("--changes-dir", default="changes")
    check.set_defaults(func=cmd_check)

    roll = sub.add_parser(
        "roll", help="fold fragments into a Keep a Changelog version section"
    )
    roll.add_argument("--version", required=True)
    roll.add_argument("--date", required=True, help="YYYY-MM-DD")
    roll.add_argument("--changelog", default="CHANGELOG.md")
    roll.add_argument("--changes-dir", default="changes")
    roll.add_argument("--dry-run", action="store_true")
    roll.set_defaults(func=cmd_roll)

    notes = sub.add_parser(
        "notes", help="print the Keep a Changelog section for a version"
    )
    notes.add_argument("--version", required=True)
    notes.add_argument("--changelog", default="CHANGELOG.md")
    notes.add_argument("--changes-dir", default="changes")
    notes.add_argument("--require-rolled", action="store_true")
    notes.set_defaults(func=cmd_notes)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
