#!/usr/bin/env python3
"""Recognize a deliberate linked-issue line in a pull request body.

Accepted lines, after optional blockquote, ATX heading, or list markers, start
with Tracking, Refs, or a GitHub closing keyword, then an issue number. Closing
keywords remain valid. Campaign children may use Tracking or Refs without
closing the issue.

Hidden or non-rendered Markdown is not a link: fenced code, indented code, and
HTML comments are removed before recognition. Incidental or negated substrings
such as "This is not Closes #1564" do not count. GitHub sidebar links and
workflow exception paths stay in the caller.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Iterable
from pathlib import Path


FENCE_OPEN = re.compile(r"^( {0,3})(`{3,}|~{3,})(.*)$")
HTML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
INDENTED_CODE_LINE = re.compile(r"^(?: {4}|\t)")

RECOGNIZED_ISSUE_LINE = re.compile(
    r"""
    ^
    [ ]{0,3}
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


def _normalize_newlines(body: str) -> str:
    return body.replace("\r\n", "\n").replace("\r", "\n")


def _strip_html_comments(text: str) -> str:
    return HTML_COMMENT.sub("", text)


def _strip_fenced_code(text: str) -> str:
    lines = text.split("\n")
    visible: list[str] = []
    index = 0
    while index < len(lines):
        match = FENCE_OPEN.match(lines[index])
        if match is None:
            visible.append(lines[index])
            index += 1
            continue
        fence = match.group(2)
        marker = fence[0]
        minimum = len(fence)
        index += 1
        close = re.compile(rf"^( {{0,3}}){re.escape(marker)}{{{minimum},}}[ \t]*$")
        while index < len(lines) and close.match(lines[index]) is None:
            index += 1
        if index < len(lines):
            index += 1
    return "\n".join(visible)


def _strip_indented_code(text: str) -> str:
    lines = text.split("\n")
    visible: list[str] = []
    in_block = False
    for index, line in enumerate(lines):
        previous_blank = index == 0 or lines[index - 1].strip() == ""
        if INDENTED_CODE_LINE.match(line) and (in_block or previous_blank):
            in_block = True
            continue
        if line.strip() == "":
            in_block = False
            visible.append(line)
            continue
        in_block = False
        visible.append(line)
    return "\n".join(visible)


def visible_markdown_text(body: str) -> str:
    text = _normalize_newlines(body)
    text = _strip_html_comments(text)
    text = _strip_fenced_code(text)
    return _strip_indented_code(text)


def _body_lines(body: str) -> Iterable[str]:
    yield from visible_markdown_text(body).split("\n")


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
