#!/usr/bin/env python3
"""Regression tests for the campaign CI trigger policy."""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from check_campaign_ci_triggers import check_repository


ROOT = Path(__file__).resolve().parents[1]


class CampaignCiTriggerTests(unittest.TestCase):
    def _copy_workflows(self) -> Path:
        temp_root = Path(tempfile.mkdtemp(prefix="campaign-ci-triggers-"))
        shutil.copytree(ROOT / ".github" / "workflows", temp_root / ".github" / "workflows")
        self.addCleanup(shutil.rmtree, temp_root)
        return temp_root

    def test_current_workflows_pass(self):
        self.assertEqual(check_repository(ROOT), [])

    def test_pull_request_requires_campaign_branch(self):
        temp_root = self._copy_workflows()
        workflow = temp_root / ".github" / "workflows" / "ci.yml"
        workflow.write_text(workflow.read_text(encoding="utf-8").replace(
            "branches: [main, os/universal]", "branches: [main]", 1
        ), encoding="utf-8")
        errors = check_repository(temp_root)
        self.assertTrue(any("ci.yml: pull_request.branches is missing os/universal" in error for error in errors))

    def test_codex_filter_is_rejected(self):
        temp_root = self._copy_workflows()
        workflow = temp_root / ".github" / "workflows" / "pr-checks.yml"
        forbidden_branch = "codex/" + "**"
        workflow.write_text(workflow.read_text(encoding="utf-8").replace(
            "branches: [main, os/universal]",
            f"branches: [main, os/universal, {forbidden_branch}]",
            1,
        ), encoding="utf-8")
        errors = check_repository(temp_root)
        self.assertTrue(any("pr-checks.yml: pull_request.branches must not include codex branch filters" in error for error in errors))

    def test_changelog_docs_and_changes_are_required(self):
        temp_root = self._copy_workflows()
        workflow = temp_root / ".github" / "workflows" / "changelog.yml"
        text = workflow.read_text(encoding="utf-8").replace('      - "docs/**"\n', "")
        workflow.write_text(text, encoding="utf-8")
        errors = check_repository(temp_root)
        self.assertTrue(any("changelog.yml: pull_request.paths is missing docs/**" in error for error in errors))

    def test_push_campaign_branch_is_allowlisted(self):
        temp_root = self._copy_workflows()
        workflow = temp_root / ".github" / "workflows" / "scorecard.yml"
        text = workflow.read_text(encoding="utf-8").replace(
            "branches: [main]", "branches: [main, os/universal]", 1
        )
        workflow.write_text(text, encoding="utf-8")
        errors = check_repository(temp_root)
        self.assertTrue(any("scorecard.yml: os/universal push coverage is not authorized" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
