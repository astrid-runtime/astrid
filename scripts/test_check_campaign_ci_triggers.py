#!/usr/bin/env python3
"""Regression tests for the campaign CI trigger policy."""

from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from check_campaign_ci_triggers import (
    OWNED_WORKFLOWS,
    check_repository,
    load_workflows,
    validate_workflows,
)


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
        workflow.write_text(
            workflow.read_text(encoding="utf-8").replace(
                "branches: [main, os/universal]", "branches: [main]", 1
            ),
            encoding="utf-8",
        )
        errors = check_repository(temp_root)
        self.assertTrue(
            any(
                "ci.yml: pull_request.branches is missing os/universal" in error
                for error in errors
            )
        )

    def test_pull_request_requires_main_branch(self):
        temp_root = self._copy_workflows()
        workflow = temp_root / ".github" / "workflows" / "pr-checks.yml"
        workflow.write_text(
            workflow.read_text(encoding="utf-8").replace(
                "branches: [main, os/universal]", "branches: [os/universal]", 1
            ),
            encoding="utf-8",
        )
        errors = check_repository(temp_root)
        self.assertTrue(
            any(
                "pr-checks.yml: pull_request.branches is missing main" in error
                for error in errors
            )
        )

    def test_codex_filter_is_rejected(self):
        temp_root = self._copy_workflows()
        workflow = temp_root / ".github" / "workflows" / "pr-checks.yml"
        workflow.write_text(
            workflow.read_text(encoding="utf-8").replace(
                "branches: [main, os/universal]",
                "branches: [main, os/universal, codex/**]",
                1,
            ),
            encoding="utf-8",
        )
        errors = check_repository(temp_root)
        self.assertTrue(
            any(
                "pr-checks.yml: pull_request.branches must not include codex branch filters"
                in error
                for error in errors
            )
        )

    def test_branchless_pull_request_is_rejected(self):
        temp_root = self._copy_workflows()
        workflow = temp_root / ".github" / "workflows" / "pr-checks.yml"
        workflow.write_text(
            workflow.read_text(encoding="utf-8").replace(
                "    branches: [main, os/universal]\n", "", 1
            ),
            encoding="utf-8",
        )
        errors = check_repository(temp_root)
        self.assertTrue(
            any("pr-checks.yml: pull_request.branches is required" in error for error in errors)
        )

    def test_all_owned_branchless_pull_request_is_rejected(self):
        drop_pr_branches = re.compile(
            r"(  pull_request:\n(?:    [^\n]+\n)*?)    branches: \[main, os/universal\]\n"
        )
        workflows = load_workflows(ROOT)
        mutated = {
            name: (
                drop_pr_branches.sub(r"\1", text, count=1)
                if name in OWNED_WORKFLOWS
                else text
            )
            for name, text in workflows.items()
        }
        errors = validate_workflows(mutated)
        required = {
            f"{name}: pull_request.branches is required" for name in OWNED_WORKFLOWS
        }
        self.assertTrue(required.issubset(set(errors)), errors)

    def test_branches_ignore_on_ci_is_rejected(self):
        temp_root = self._copy_workflows()
        workflow = temp_root / ".github" / "workflows" / "ci.yml"
        workflow.write_text(
            workflow.read_text(encoding="utf-8").replace(
                "    branches: [main, os/universal]",
                "    branches-ignore: [main]",
                1,
            ),
            encoding="utf-8",
        )
        errors = check_repository(temp_root)
        self.assertTrue(
            any(
                "ci.yml: pull_request.branches-ignore is not allowed" in error
                for error in errors
            )
        )

    def test_branches_ignore_on_scorecard_is_rejected(self):
        temp_root = self._copy_workflows()
        workflow = temp_root / ".github" / "workflows" / "scorecard.yml"
        workflow.write_text(
            workflow.read_text(encoding="utf-8").replace(
                "    branches: [main]", "    branches-ignore: [main]", 1
            ),
            encoding="utf-8",
        )
        errors = check_repository(temp_root)
        self.assertTrue(
            any(
                "scorecard.yml: push.branches-ignore is not allowed" in error
                for error in errors
            )
        )

    def test_oci_branch_narrowing_is_rejected(self):
        temp_root = self._copy_workflows()
        workflow = temp_root / ".github" / "workflows" / "oci-amd64.yml"
        text = workflow.read_text(encoding="utf-8")
        workflow.write_text(
            text.replace(
                "  pull_request:\n    paths:",
                "  pull_request:\n    branches: [main, os/universal]\n    paths:",
                1,
            ),
            encoding="utf-8",
        )
        errors = check_repository(temp_root)
        self.assertTrue(
            any(
                "oci-amd64.yml: pull_request.branches must remain unfiltered" in error
                for error in errors
            )
        )

    def test_ci_docs_path_is_rejected(self):
        temp_root = self._copy_workflows()
        workflow = temp_root / ".github" / "workflows" / "ci.yml"
        text = workflow.read_text(encoding="utf-8")
        workflow.write_text(
            text.replace(
                "      - '**.rs'\n",
                "      - '**.rs'\n      - 'docs/**'\n",
            ),
            encoding="utf-8",
        )
        errors = check_repository(temp_root)
        self.assertTrue(
            any(
                "ci.yml: pull_request.paths must not include docs coverage" in error
                or "ci.yml: push.paths must not include docs coverage" in error
                for error in errors
            )
        )

    def test_changelog_docs_and_changes_are_required(self):
        for required_path in ("docs/**", "changes/**"):
            with self.subTest(required_path=required_path):
                temp_root = self._copy_workflows()
                workflow = temp_root / ".github" / "workflows" / "changelog.yml"
                text = workflow.read_text(encoding="utf-8").replace(
                    f'      - "{required_path}"\n', ""
                )
                workflow.write_text(text, encoding="utf-8")
                errors = check_repository(temp_root)
                self.assertTrue(
                    any(
                        f"changelog.yml: pull_request.paths is missing {required_path}"
                        in error
                        for error in errors
                    ),
                    errors,
                )

    def test_protected_workflows_reject_branchless_or_wildcard_push(self):
        temp_root = self._copy_workflows()
        scorecard = temp_root / ".github" / "workflows" / "scorecard.yml"
        scorecard.write_text(
            scorecard.read_text(encoding="utf-8").replace(
                "    branches: [main]\n", "", 1
            ),
            encoding="utf-8",
        )
        errors = check_repository(temp_root)
        self.assertTrue(
            any("scorecard.yml: push.branches is required" in error for error in errors),
            errors,
        )

        temp_root = self._copy_workflows()
        release = temp_root / ".github" / "workflows" / "release.yml"
        release.write_text(
            release.read_text(encoding="utf-8").replace(
                "  push:\n    tags:\n      - 'v[0-9]+.*'\n      - '!v[0-9]+.*-nightly.*'\n",
                "  push:\n",
                1,
            ),
            encoding="utf-8",
        )
        errors = check_repository(temp_root)
        self.assertTrue(
            any("release.yml: push.tags is required" in error for error in errors),
            errors,
        )

        temp_root = self._copy_workflows()
        scorecard = temp_root / ".github" / "workflows" / "scorecard.yml"
        scorecard.write_text(
            scorecard.read_text(encoding="utf-8").replace(
                "branches: [main]", "branches: ['**']", 1
            ),
            encoding="utf-8",
        )
        errors = check_repository(temp_root)
        self.assertTrue(
            any(
                "scorecard.yml: push.branches must be exactly [main]" in error
                for error in errors
            ),
            errors,
        )

    def test_scorecard_rejects_branchless_pull_request_event(self):
        workflows = load_workflows(ROOT)
        scorecard = workflows["scorecard.yml"]
        mutated = dict(workflows)
        mutated["scorecard.yml"] = scorecard.replace("on:\n", "on:\n  pull_request:\n", 1)
        errors = validate_workflows(mutated)
        self.assertTrue(
            any(
                "scorecard.yml: pull_request event is not allowed" in error
                for error in errors
            ),
            errors,
        )

        mutated["scorecard.yml"] = scorecard.replace(
            "on:\n",
            "on:\n  pull_request:\n    types: [opened]\n",
            1,
        )
        errors = validate_workflows(mutated)
        self.assertTrue(
            any(
                "scorecard.yml: pull_request event is not allowed" in error
                for error in errors
            ),
            errors,
        )

    def test_push_campaign_branch_is_allowlisted(self):
        temp_root = self._copy_workflows()
        workflow = temp_root / ".github" / "workflows" / "scorecard.yml"
        text = workflow.read_text(encoding="utf-8").replace(
            "branches: [main]", "branches: [main, os/universal]", 1
        )
        workflow.write_text(text, encoding="utf-8")
        errors = check_repository(temp_root)
        self.assertTrue(
            any(
                "scorecard.yml: push.branches must be exactly [main]" in error
                for error in errors
            ),
            errors,
        )


if __name__ == "__main__":
    unittest.main()
