"""Preparation authority and status failures; every subprocess is mocked."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "hosted_setup", Path(__file__).with_name("hosted_macos_setup.py"))
SETUP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SETUP)


class SetupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.workspace = Path(self.temp.name).resolve()
        self.root = self.workspace / "astrid-benchmark.noindex"
        self.source = self.root / "protocol/scripts/benchmarks/hosted_macos_setup.py"
        self.source.parent.mkdir(parents=True)
        self.root.chmod(0o700)
        self.source.write_text("# mock checkout source\n")
        self.receipt = self.root / "host-indexing-setup.json"
        self.environment = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
                            "RUNNER_OS": "macOS", "GITHUB_REPOSITORY": "astrid-runtime/astrid",
                            "GITHUB_JOB": "matched-packing", "GITHUB_WORKSPACE": str(self.workspace)}
        for context in (patch.dict(os.environ, self.environment, clear=True),
                        patch.object(SETUP, "__file__", str(self.source)),
                        patch.object(SETUP.platform, "system", return_value="Darwin")):
            context.start()
            self.addCleanup(context.stop)
        self.run_patch = patch.object(SETUP.subprocess, "run", side_effect=[
            subprocess.CompletedProcess(SETUP.DISABLE, 0, "/:\nIndexing disabled.\n", ""),
            subprocess.CompletedProcess(SETUP.STATUS, 0, "/:\n\tIndexing disabled.\n", "")])
        self.run = self.run_patch.start()
        self.addCleanup(self.run_patch.stop)

    def assert_rejected(self):
        with self.assertRaises((RuntimeError, OSError)):
            SETUP.prepare()
        self.run.assert_not_called()
        self.assertFalse(self.receipt.exists())

    def test_reject_local_self_hosted_wrong_os_repository_and_job_before_commands(self):
        for key, value in (("GITHUB_ACTIONS", "false"), ("RUNNER_ENVIRONMENT", "self-hosted"),
                           ("RUNNER_OS", "Linux"), ("GITHUB_REPOSITORY", "other/astrid"),
                           ("GITHUB_JOB", "benchmark"), ("GITHUB_WORKSPACE", "relative")):
            with self.subTest(key=key), patch.dict(os.environ, {key: value}):
                self.assert_rejected()
        with patch.object(SETUP.platform, "system", return_value="Linux"):
            self.assert_rejected()

    def test_reject_aliased_namespace(self):
        actual = self.workspace / "outside.noindex"
        self.root.rename(actual)
        self.root.symlink_to(actual, target_is_directory=True)
        self.assert_rejected()

    def test_reject_aliased_workspace(self):
        alias = self.workspace / "workspace-alias"
        alias.symlink_to(self.workspace, target_is_directory=True)
        with patch.dict(os.environ, {"GITHUB_WORKSPACE": str(alias)}), patch.object(
                SETUP, "__file__", str(alias / self.source.relative_to(self.workspace))):
            self.assert_rejected()

    def test_reject_redirected_protocol_or_wrong_source(self):
        with patch.object(SETUP, "__file__", str(self.workspace / "hosted_macos_setup.py")):
            self.assert_rejected()
        actual = self.root / "other-protocol"
        protocol = self.root / "protocol"
        protocol.rename(actual)
        protocol.symlink_to(actual, target_is_directory=True)
        self.assert_rejected()

    def test_reject_nonprivate_or_unowned_namespace(self):
        self.root.chmod(0o755)
        self.assert_rejected()
        self.root.chmod(0o700)
        with patch.object(SETUP.os, "getuid", return_value=os.getuid() + 1):
            self.assert_rejected()

    def test_existing_receipt_cannot_be_overwritten_or_redirected(self):
        sentinel = self.workspace / "sentinel"
        sentinel.write_text("preserved")
        self.receipt.symlink_to(sentinel)
        with self.assertRaises(FileExistsError):
            SETUP.prepare()
        self.run.assert_not_called()
        self.assertEqual(sentinel.read_text(), "preserved")

    def test_disabled_status_records_actual_commands_and_results(self):
        SETUP.prepare()
        receipt = json.loads(self.receipt.read_text())
        self.assertTrue(receipt["complete"])
        self.assertFalse(receipt["proves_quiet"])
        self.assertEqual([entry["argv"] for entry in receipt["commands"]], [SETUP.DISABLE, SETUP.STATUS])
        self.assertEqual([entry["returncode"] for entry in receipt["commands"]], [0, 0])
        self.assertEqual(receipt["context"], self.environment)
        self.assertIn("finished_at", receipt)
        for call in self.run.call_args_list:
            self.assertEqual(call.kwargs, {"capture_output": True, "text": True, "timeout": 30, "check": False})

    def test_native250_is_also_authorized(self):
        with patch.dict(os.environ, {"GITHUB_JOB": "matched-native250"}):
            SETUP.prepare()
        self.assertTrue(json.loads(self.receipt.read_text())["complete"])

    def test_command_failure_records_failure_and_never_attempts_status(self):
        self.run.side_effect = [subprocess.CompletedProcess(SETUP.DISABLE, 1, "", "permission denied")]
        with self.assertRaises(RuntimeError):
            SETUP.prepare()
        receipt = json.loads(self.receipt.read_text())
        self.assertFalse(receipt["complete"])
        self.assertEqual(self.run.call_count, 1)
        self.assertEqual(receipt["commands"][0]["stderr"], "permission denied")

    def test_status_command_failure_is_not_success(self):
        self.run.side_effect = [subprocess.CompletedProcess(SETUP.DISABLE, 0, "", ""),
                                subprocess.CompletedProcess(SETUP.STATUS, 1, "Indexing disabled.", "failed")]
        with self.assertRaises(RuntimeError):
            SETUP.prepare()
        self.assertFalse(json.loads(self.receipt.read_text())["complete"])

    def test_enabled_unknown_or_mixed_status_is_not_success(self):
        for status in ("/:\nIndexing enabled.", "unknown", "", "/:\nIndexing disabled.\nIndexing enabled."):
            with self.subTest(status=status):
                self.run.side_effect = [subprocess.CompletedProcess(SETUP.DISABLE, 0, "", ""),
                                        subprocess.CompletedProcess(SETUP.STATUS, 0, status, "")]
                with self.assertRaises(RuntimeError):
                    SETUP.prepare()
                self.assertFalse(json.loads(self.receipt.read_text())["complete"])
                self.receipt.unlink()

    def test_timeout_is_recorded_and_raised(self):
        self.run.side_effect = subprocess.TimeoutExpired(SETUP.DISABLE, 30)
        with self.assertRaises(subprocess.TimeoutExpired):
            SETUP.prepare()
        receipt = json.loads(self.receipt.read_text())
        self.assertFalse(receipt["complete"])
        self.assertIn("TimeoutExpired", receipt["error"])
        self.assertEqual(self.run.call_count, 1)
