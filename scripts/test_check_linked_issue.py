#!/usr/bin/env python3
"""Positive and hostile regressions for linked-issue recognition."""

from __future__ import annotations

import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from check_linked_issue import has_recognized_issue_line, main, recognized_issue_lines


ROOT = Path(__file__).resolve().parents[1]
OLD_UNANCHORED = re.compile(
    r"(close[sd]?|fix(e[sd])?|resolve[sd]?)\s+#[0-9]+",
    re.IGNORECASE,
)
WORKFLOW = ROOT / ".github" / "workflows" / "pr-checks.yml"


class CheckLinkedIssueTests(unittest.TestCase):
    def test_tracking_campaign_line_passes(self):
        body = (
            "## Linked Issue\n\n"
            "Tracking #1564 (campaign CI bootstrap only). Do not close the epic.\n"
        )
        self.assertTrue(has_recognized_issue_line(body))
        self.assertEqual(
            recognized_issue_lines(body),
            ["Tracking #1564 (campaign CI bootstrap only). Do not close the epic."],
        )

    def test_refs_line_passes(self):
        self.assertTrue(has_recognized_issue_line("Refs #1564\n"))

    def test_github_closing_keywords_pass(self):
        for line in (
            "Closes #1564",
            "Close #12",
            "Closed #3",
            "Fixes #10",
            "Fix #11",
            "Fixed #12",
            "Resolves #2",
            "Resolve #8",
            "Resolved #9",
            "closes: #1564",
        ):
            with self.subTest(line=line):
                self.assertTrue(has_recognized_issue_line(line))

    def test_blockquote_list_and_heading_prefixes_pass(self):
        for line in (
            "> Tracking #1564",
            "- Refs #7",
            "* Closes #8",
            "+ Fixes #9",
            "1. Tracking #1564",
            "2) Refs #22",
            "## Tracking #1564",
        ):
            with self.subTest(line=line):
                self.assertTrue(has_recognized_issue_line(line))

    def test_negated_closes_substring_fails(self):
        body = "This is not Closes #1564"
        self.assertTrue(OLD_UNANCHORED.search(body))
        self.assertFalse(has_recognized_issue_line(body))

    def test_incidental_and_negated_lines_fail(self):
        for line in (
            "Please don't close #1564",
            "not Tracking #1564",
            "See Closes #1564 in the docs",
            "This PR is not Closes #1564",
            "Tracking issue #1564",
            "Retracking #1564",
            "#1564",
            "See #1564",
            "Closes #<!-- issue number -->",
            "",
        ):
            with self.subTest(line=repr(line)):
                self.assertFalse(has_recognized_issue_line(line))

    def test_unfilled_template_does_not_count(self):
        body = (ROOT / ".github" / "pull_request_template.md").read_text(encoding="utf-8")
        self.assertFalse(has_recognized_issue_line(body))

    def test_cli_accepts_tracking_and_rejects_negated(self):
        with tempfile.TemporaryDirectory() as tmp:
            tracking = Path(tmp) / "tracking.md"
            tracking.write_text(
                "Tracking #1564 (campaign CI bootstrap only). Do not close the epic.\n",
                encoding="utf-8",
            )
            negated = Path(tmp) / "negated.md"
            negated.write_text("This is not Closes #1564\n", encoding="utf-8")
            with patch("sys.argv", ["check_linked_issue.py", str(tracking)]):
                self.assertEqual(main(), 0)
            with patch("sys.argv", ["check_linked_issue.py", str(negated)]):
                self.assertEqual(main(), 1)

    def test_workflow_no_longer_uses_unanchored_closing_grep(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertNotIn(r"(close[sd]?|fix(e[sd])?|resolve[sd]?)\s+#[0-9]+", text)
        self.assertIn("scripts/check_linked_issue.py", text)
        self.assertIn("Tracking #N", text)
        self.assertIn("Refs #N", text)
        self.assertIn("This is not Closes #1564", text)


if __name__ == "__main__":
    unittest.main()
