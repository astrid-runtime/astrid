#!/usr/bin/env python3
"""Exercise the Cargo JSON selector through its real stdin/stdout entry point."""

import json
from pathlib import Path
import subprocess
import sys
import unittest

SCRIPT = Path(__file__).parent / "ci/cargo_test_executable.py"


class CargoTestExecutableTests(unittest.TestCase):
    def select(self, messages, target="astrid_core"):
        return subprocess.run(
            [sys.executable, str(SCRIPT), target],
            input="".join(json.dumps(message) + "\n" for message in messages),
            capture_output=True, text=True, check=False,
        )

    @staticmethod
    def artifact(target="astrid_core", test=True, executable="/owned/test-binary"):
        return {"reason": "compiler-artifact", "executable": executable,
                "target": {"name": target}, "profile": {"test": test}}

    def test_exact_target_and_test_profile_only(self):
        for target in ("astrid_core", "astrid_storage", "astrid"):
            with self.subTest(target=target):
                result = self.select([
                    self.artifact("other"), self.artifact(target, test=False),
                    self.artifact(target, executable=None), self.artifact(target),
                ], target)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, "/owned/test-binary\n")

    def test_missing_and_duplicate_artifacts_fail_without_selected_output(self):
        for messages in ([], [self.artifact(), self.artifact()]):
            result = self.select(messages)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "")

    def test_compiler_diagnostics_survive_failed_build(self):
        for diagnostic in ({"rendered": "rendered compiler error\n", "message": "plain"},
                           {"message": "plain compiler error"}):
            result = self.select([{"reason": "compiler-message", "message": diagnostic}])
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(diagnostic.get("rendered") or diagnostic["message"], result.stderr)
            self.assertEqual(result.stdout, "")

    def test_diagnostics_do_not_contaminate_successful_path(self):
        result = self.select([{"reason": "compiler-message", "message": {"message": "warning"}},
                              self.artifact()])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "/owned/test-binary\n")
        self.assertEqual(result.stderr, "warning\n")

    def test_malformed_json_fails_closed(self):
        result = subprocess.run([sys.executable, str(SCRIPT), "astrid_core"],
                                input="not JSON\n", capture_output=True, text=True, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
