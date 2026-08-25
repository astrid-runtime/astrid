#!/usr/bin/env python3
"""Recognize a deliberate linked-issue line in a pull request body.

Accepted lines, after optional blockquote, ATX heading, or list markers, start
with Tracking, Refs, or a GitHub closing keyword, then an issue number. Closing
keywords remain valid. Campaign children may use Tracking or Refs without
closing the issue.

Incidental or negated substrings such as "This is not Closes #1564" do not
count. GitHub sidebar links and workflow exception paths stay in the caller.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Iterable
from pathlib import Path


RECOGNIZED_ISSUE_LINE = re.compile(
    r"""
    ^
    [ \t]*
    (?:>[ \t]*)*
    (?:\#{1,6}[ \t]+)?
    (?:(?:[-*+]|\d+[.)])[ \t]+)?
    (?:Tracking|Refs|Close[sd]?|Fix(?:es|ed)?|Resolve[sd]?)
    (?:[ \t]*:)?
    [ \t]+
    \#\d+
    \b
    """,
    re.IGNORECASE | re.VERBOSE,
)


def _body_lines(body: str) -> Iterable[str]:
    for line in body.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        yield line


def recognized_issue_lines(body: str) -> list[str]:
    return [line for line in _body_lines(body) if RECOGNIZED_ISSUE_LINE.search(line)]


def has_recognized_issue_line(body: str) -> bool:
    return bool(recognized_issue_lines(body))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("body_file", type=Path)
    args = parser.parse_args()

    try:
        body = args.body_file.read_text(encoding="utf-8")
    except OSError as error:
        print(f"::error::Unable to read pull request body: {error}")
        return 2

    matches = recognized_issue_lines(body)
    if not matches:
        return 1

    print("Linked issue reference found.")
    for line in matches:
        print(line.strip())
    return 0


if __name__ == "__main__":
    sys.exit(main())
