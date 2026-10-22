#!/usr/bin/env python3
"""Exercise bounded CLI capture with a real inert subprocess and split streams."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parent / "e2e/runtime-crash-smoke.sh"


class RuntimeCliCaptureTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        binary = self.root / "target/debug/astrid"
        binary.parent.mkdir(parents=True)
        binary.write_text(
            f"#!{sys.executable}\n"
            "import sys, time\n"
            "print('! Update available: fixture', file=sys.stderr, flush=True)\n"
            "print('[{\"principal\":\"fixture\",\"owner_uid\":\"fixture-uid\"}]', flush=True)\n"
            "if sys.argv[-1] == 'timeout': time.sleep(10)\n"
            "if sys.argv[-1] == 'failure': raise SystemExit(17)\n"
        )
        binary.chmod(0o700)
        self.output = self.root / "roster.json"

    def capture(self, mode, argument="success", timeout="3"):
        environment = os.environ.copy()
        environment.update(CORE_DIR=str(self.root), PYTHON=sys.executable)
        return subprocess.run(
            [
                "bash", "-c",
                'source "$1"; "$2" fixture "$3" "$4" "$5"',
                "capture-test", str(SCRIPT), mode, timeout, str(self.output), argument,
            ],
            env=environment, capture_output=True, text=True, timeout=8, check=False,
        )

    def test_json_stdout_excludes_update_banner_and_keeps_diagnostic(self):
        result = self.capture("bounded_principal_cli_json")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(self.output.read_text())[0]["owner_uid"], "fixture-uid")
        self.assertIn("Update available", Path(str(self.output) + ".stderr").read_text())

    def test_failure_preserves_exact_status_and_both_streams(self):
        result = self.capture("bounded_principal_cli_json", "failure")
        self.assertEqual(result.returncode, 17, result.stderr)
        self.assertEqual(json.loads(self.output.read_text())[0]["principal"], "fixture")
        self.assertIn("Update available", Path(str(self.output) + ".stderr").read_text())

    def test_timeout_preserves_partial_stdout_and_stderr(self):
        result = self.capture("bounded_principal_cli_json", "timeout", "2")
        self.assertEqual(result.returncode, 124, result.stderr)
        self.assertEqual(json.loads(self.output.read_text())[0]["principal"], "fixture")
        self.assertIn("Update available", Path(str(self.output) + ".stderr").read_text())

    def test_text_consumers_keep_combined_diagnostics(self):
        result = self.capture("bounded_principal_cli")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Update available", self.output.read_text())
        self.assertIn("fixture-uid", self.output.read_text())
        self.assertFalse(Path(str(self.output) + ".stderr").exists())


if __name__ == "__main__":
    unittest.main()
