#!/usr/bin/env python3
"""Executable regressions for dev release-candidate staging."""

import os
import subprocess
import tempfile
import unittest

import release_candidate
from test_nightly_version import NightlyVersionTests


class ReleaseCandidateTests(NightlyVersionTests):
    def test_shipped_macos_manager_accepts_bundle_base_but_binds_exact_runtime(self) -> None:
        root = release_candidate.nightly_version.ROOT
        manager = (root / "scripts/manage-macos-fskit.sh").read_text()
        companion = manager.split("validate_companion() {", 1)[1].split("\napp_process_matches()", 1)[0]
        process = manager.split("app_process_matches() {", 1)[1].split("\ncheck_app_processes()", 1)[0]
        # Execute the shipped functions, replacing only host inspection tools;
        # no app installation, signatures or real process identity are claimed.
        companion = companion.replace("/usr/bin/codesign", "codesign")
        process = process.replace("/bin/ps", "ps").replace("/usr/sbin/lsof", "lsof").replace("/usr/bin/codesign", "codesign")
        with tempfile.TemporaryDirectory() as temporary:
            provider = os.path.join(temporary, "provider")
            with open(provider, "w") as output:
                output.write('#!/bin/sh\nprintf \'{"name":"astrid-storage-provider-fskit","version":"%s"}\\n\' "$TEST_PROVIDER_VERSION"\n')
            os.chmod(provider, 0o700)
            body = '''
codesign() { printf 'Identifier=provider\\nTeamIdentifier=team\\nIdentifier=app\\n'; }
plutil() { printf '%s\\n' "$TEST_BUNDLE_VERSION"; }
ps() { printf '%s\\n' "$APP_EXECUTABLE"; }
lsof() { printf 'n%s\\n' "$APP_EXECUTABLE"; }
COMPANION_IDENTIFIER=provider CODE_SIGN_TEAM=team APP_IDENTIFIER=app
SOURCE_APP=/fixture/source DESTINATION_APP=/fixture/destination APP_EXECUTABLE=/fixture/app
'''
            body += "validate_companion() {" + companion
            body += "app_process_matches() {" + process
            body += '\nvalidate_companion "$1" && app_process_matches 123\n'
            for provider_version, bundle, expected, success in (
                ("2026.10.0-rc.1", "2026.10.0", "2026.10.0-rc.1", True),
                ("2026.10.0", "2026.10.0", "2026.10.0", True),
                ("2026.10.0-rc.2", "2026.10.0", "2026.10.0-rc.1", False),
                ("2026.9.4-rc.1", "2026.10.0", "2026.10.0-rc.1", False),
            ):
                with self.subTest(provider=provider_version, expected=expected):
                    env = dict(os.environ, TEST_PROVIDER_VERSION=provider_version, TEST_BUNDLE_VERSION=bundle, ASTRID_FSKIT_EXPECTED_VERSION=expected)
                    run = subprocess.run(["bash", "-euo", "pipefail", "-c", body, "manager-test", provider], env=env, capture_output=True, text=True)
                    self.assertEqual(run.returncode == 0, success, run.stderr)

    def test_tag_push_executes_the_actual_workflow_classifier(self) -> None:
        root = release_candidate.nightly_version.ROOT
        workflow = (root / ".github/workflows/release.yml").read_text()
        block = workflow.split("      - name: Bind event, tag, and source commit\n", 1)[1].split("\n  # ── Build", 1)[0]
        body = block.split("        run: |\n", 1)[1]
        body = "\n".join(line[10:] for line in body.splitlines())
        base = release_candidate.nightly_version.source_version(root)
        for version, success, prerelease in (
            (base, True, "false"), (f"{base}-rc.1", True, "true"),
            (f"{base}-rc.0", False, None), (f"{base}-beta.1", False, None),
            (f"{base}-rc.1+build", False, None), ("0.0.0-rc.1", False, None),
        ):
            with self.subTest(version=version), tempfile.NamedTemporaryFile() as output:
                env = dict(os.environ, EVENT_NAME="push", PREPARE_ONLY="false", PREPARE_SET="", GITHUB_REF=f"refs/tags/v{version}", GITHUB_REF_NAME=f"v{version}", GITHUB_OUTPUT=output.name)
                run = subprocess.run(["bash", "-euo", "pipefail", "-c", body], cwd=root, env=env, capture_output=True, text=True)
                self.assertEqual(run.returncode == 0, success, run.stderr)
                if success:
                    receipt = output.read().decode()
                    self.assertIn(f"version={version}\n", receipt)
                    self.assertIn(f"prerelease={prerelease}\n", receipt)
                    self.assertIn("nightly=false\n", receipt)

    def test_stage_candidate_without_consuming_final_identity(self) -> None:
        version = "0.9.4-rc.1"
        release_candidate.stage(self.root, version)
        self.assertEqual((self.root / "Cargo.toml").read_text().count(version), 3)
        lock = (self.root / "Cargo.lock").read_text()
        self.assertEqual(lock.count(version), 3)
        self.assertIn('name = "external"\nversion = "0.9.4"', lock)

    def test_invalid_candidates_do_not_change_source(self) -> None:
        cargo = (self.root / "Cargo.toml").read_bytes()
        lock = (self.root / "Cargo.lock").read_bytes()
        for version in ("0.10.0-rc.1", "0.9.4-rc.0", "0.9.4-rc.01", "0.9.4-rc.1+build", "0.9.4-beta.1"):
            with self.subTest(version=version), self.assertRaises(ValueError):
                release_candidate.stage(self.root, version)
            self.assertEqual((self.root / "Cargo.toml").read_bytes(), cargo)
            self.assertEqual((self.root / "Cargo.lock").read_bytes(), lock)


if __name__ == "__main__":
    unittest.main()
