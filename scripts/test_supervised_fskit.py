#!/usr/bin/env python3
"""Executable regressions for supervised release approval binding."""

import copy
import json
from pathlib import Path
import tempfile
import io
import tarfile
import unittest
from unittest.mock import patch
import os
import subprocess
import sys

import supervised_fskit as cert
import certify_fskit_local as local


class ApprovalTests(unittest.TestCase):
    def test_private_directories_do_not_depend_on_umask(self):
        with tempfile.TemporaryDirectory() as directory:
            previous = os.umask(0o022)
            try:
                home, mount = local.prepare_directories(Path(directory))
            finally:
                os.umask(previous)
            for path in (home, mount):
                self.assertEqual(path.stat().st_mode & 0o777, 0o700)

    @unittest.skipUnless(hasattr(os, "fork"), "POSIX inherited-descriptor regression")
    def test_detached_stdout_does_not_hold_command_open(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            code = """import os, time
pid = os.fork()
if pid == 0:
    time.sleep(1)
    os._exit(0)
print('parent completed', flush=True)
"""
            output = local.run_logged(
                [sys.executable, "-c", code], os.environ.copy(), root / "log", timeout=0.5)
            self.assertIn("parent completed", output)
            self.assertIn("exit=0", (root / "log").read_text())

    def test_failure_and_timeout_keep_diagnostics(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "log"
            with self.assertRaises(RuntimeError):
                local.run_logged([sys.executable, "-c", "print('failed'); exit(7)"],
                                 os.environ.copy(), log)
            self.assertIn("exit=7\nfailed", log.read_text())
            with self.assertRaises(subprocess.TimeoutExpired):
                local.run_logged([sys.executable, "-c",
                                  "import time; print('waiting', flush=True); time.sleep(10)"],
                                 os.environ.copy(), log, timeout=0.2)
            self.assertIn("timeout=0.2\nwaiting", log.read_text())

    def test_runner_source_rejects_edits_and_wrong_checkout(self):
        with tempfile.TemporaryDirectory() as directory:
            scripts = Path(directory) / "scripts"
            scripts.mkdir()
            script = scripts / "certify_fskit_local.py"
            helper = scripts / "supervised_fskit.py"
            script.write_bytes(b"runner")
            helper.write_bytes(b"helper")
            source = "a" * 40
            with patch.object(local.subprocess, "check_output",
                              side_effect=[source, b"runner", b"helper"]):
                local.verify_runner_source(source, script)
            for changed in (script, helper):
                original = changed.read_bytes()
                changed.write_bytes(b"edited")
                with patch.object(local.subprocess, "check_output",
                                  side_effect=[source, b"runner", b"helper"]):
                    with self.assertRaisesRegex(ValueError, "differs from release source"):
                        local.verify_runner_source(source, script)
                changed.write_bytes(original)
            with patch.object(local.subprocess, "check_output", return_value="b" * 40):
                with self.assertRaisesRegex(ValueError, "checkout differs"):
                    local.verify_runner_source(source, script)
            with self.assertRaisesRegex(ValueError, "must use"):
                local.verify_runner_source(source, scripts / "copy.py")

    def test_local_mount_type_is_bound_to_exact_mount(self):
        with tempfile.TemporaryDirectory() as directory:
            mount = Path(directory) / "mount with spaces"
            mount.mkdir()
            name = str(mount.resolve())
            self.assertTrue(local.is_astridfs(mount, f"AOS on {name} (astridfs, local)"))
            for table in (
                f"AOS on {name}-other (astridfs, local)",
                f"disk on {name} (apfs, local)",
                f"AOS on {name} (astridfs-other, local)",
                "/",
                "",
            ):
                with self.subTest(table=table):
                    self.assertFalse(local.is_astridfs(mount, table))

    def setUp(self):
        self.expected = {"schema": 1, "source_commit": "a" * 40, "run_id": "123",
                         "run_attempt": "2", "target": cert.TARGET,
                         "archive": "astrid-2026.9.0-aarch64-apple-darwin.tar.gz",
                         "archive_sha256": "b" * 64}
        self.receipt = dict(self.expected, result="PASS", checks=dict.fromkeys(cert.CHECKS, True))
        self.review = {"state": "approved", "user": {"login": "joshuajbouw"},
                       "environments": [{"name": "release"}],
                       "comment": json.dumps(self.receipt)}

    def test_exact_approval(self):
        self.assertEqual(cert.approved_receipt(self.expected, [self.review]), self.receipt)

    def test_stale_or_different_identity(self):
        for field in ("source_commit", "archive_sha256", "run_id", "run_attempt", "target", "archive"):
            with self.subTest(field=field):
                receipt = dict(self.receipt, **{field: "different"})
                with self.assertRaises(ValueError):
                    cert.approved_receipt(self.expected, [dict(self.review, comment=json.dumps(receipt))])

    def test_no_generic_approval_or_incomplete_claims(self):
        for comment in ("Ship it!", "{}", "null", "[]", "true", "", json.dumps(self.expected)):
            with self.subTest(comment=comment), self.assertRaises(ValueError):
                cert.approved_receipt(self.expected, [dict(self.review, comment=comment)])
        for value in (False, "true", 1, None):
            receipt = copy.deepcopy(self.receipt)
            receipt["checks"]["mount"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                cert.approved_receipt(self.expected, [dict(self.review, comment=json.dumps(receipt))])

    def test_untrusted_review(self):
        for change in ({"state": "rejected"}, {"user": {"login": "someone"}},
                       {"environments": [{"name": "unprotected"}]}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                cert.approved_receipt(self.expected, [dict(self.review, **change)])

    def test_manifest_hashes_actual_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / self.expected["archive"]
            path.write_bytes(b"first")
            first = cert.manifest(directory, "a" * 40, "123", "2")
            path.write_bytes(b"second")
            second = cert.manifest(directory, "a" * 40, "123", "2")
            self.assertNotEqual(first["archive_sha256"], second["archive_sha256"])
            (Path(directory) / "extra").write_text("unexpected")
            with self.assertRaises(ValueError):
                cert.manifest(directory, "a" * 40, "123", "2")

    def test_workflow_keeps_protected_gate_and_same_run_bytes(self):
        root = Path(__file__).resolve().parents[1]
        text = (root / ".github/workflows/supervised-storage-certification.yml").read_text()
        self.assertIn("environment: release", text)
        self.assertEqual(text.count("name: binary-aarch64-apple-darwin"), 2)
        self.assertIn('test "$SOURCE_COMMIT" = "$GITHUB_SHA"', text)
        self.assertIn("/actions/runs/$GITHUB_RUN_ID/approvals", text)
        self.assertIn("supervised_fskit.py verify", text)
        self.assertNotIn("secrets.", text)
        release = (root / ".github/workflows/release.yml").read_text()
        self.assertIn("needs: [classify, build, fskit-certification]", release)
        self.assertIn("uses: ./.github/workflows/supervised-storage-certification.yml", release)

    def test_local_app_inventory_detects_changed_bytes_and_links(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            member = root / "file"
            member.write_text("first")
            before = local.inventory(root)
            member.write_text("second")
            self.assertNotEqual(before, local.inventory(root))
            (root / "link").symlink_to(member)
            with self.assertRaises(ValueError):
                local.inventory(root)

    def test_local_extraction_refuses_escape_and_links(self):
        for name, kind in (("../outside", tarfile.REGTYPE), ("root/link", tarfile.SYMTYPE)):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                archive = root / "root.tar.gz"
                with tarfile.open(archive, "w:gz") as stream:
                    member = tarfile.TarInfo(name)
                    member.type = kind
                    member.linkname = "/tmp/outside"
                    stream.addfile(member, io.BytesIO())
                with self.assertRaises(ValueError):
                    local.unpack(archive, root / "out")


if __name__ == "__main__":
    unittest.main()
