#!/usr/bin/env python3
"""Exercise the actual bounded CLI helper with separate machine/diagnostic output."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HELPER_SCRIPT = Path(__file__).resolve().parents[1] / "e2e/runtime-crash-smoke.sh"


class BoundedPrincipalCliTests(unittest.TestCase):
    def run_helper(self, program, timeout=2):
        source = HELPER_SCRIPT.read_text()
        helper = source.split("bounded_principal_cli() {", 1)[1].split("\nwait_for_adversarial_command_route()", 1)[0]
        python = helper.split("<<'PY'\n", 1)[1].split("\nPY", 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "fake-cli"
            binary.write_text(f"#!{sys.executable}\n" + program)
            binary.chmod(0o700)
            out = root / "roster.json"
            result = subprocess.run(
                [sys.executable, "-c", python, str(binary), "default", str(timeout), str(out)],
                capture_output=True, text=True, timeout=5,
            )
            return result, out.read_text(), out.with_name(out.name + ".stderr").read_text()

    def test_update_notice_cannot_corrupt_json_roster(self):
        result, output, diagnostic = self.run_helper(
            'import sys\nprint("Update available", file=sys.stderr)\nprint(\'[ {"principal": "alice", "owner_uid": "owned"} ]\')\n'
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(output)[0]["owner_uid"], "owned")
        self.assertEqual(diagnostic, "Update available\n")

    def test_failure_keeps_diagnostics_and_original_exit_code(self):
        result, output, diagnostic = self.run_helper(
            'import sys\nprint("request-output")\nprint("denied", file=sys.stderr)\nsys.exit(7)\n'
        )
        self.assertEqual(result.returncode, 7)
        self.assertEqual(output, "request-output\n")
        self.assertEqual(diagnostic, "denied\n")
        self.assertIn("denied", result.stderr)

    def test_existing_cancellation_assertions_accept_stderr_only_failure(self):
        for name, variable in [("runtime-adversarial-smoke.sh", "timeout_out"), ("runtime-hostcall-cancel-smoke.sh", "out")]:
            with self.subTest(script=name):
                source = HELPER_SCRIPT.with_name(name).read_text()
                assertion = next(line.strip().removesuffix("\\").strip() for line in source.splitlines() if "grep -Eqi 'timed out|timeout|cancelled'" in line)
                with tempfile.TemporaryDirectory() as directory:
                    output = Path(directory) / "result.txt"
                    output.write_text("")
                    output.with_name(output.name + ".stderr").write_text("request cancelled\n")
                    result = subprocess.run(["bash", "-c", f'{variable}="$1"; ' + assertion, "test", str(output)], capture_output=True, text=True, timeout=5)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    output.with_name(output.name + ".stderr").write_text("unrelated failure\n")
                    result = subprocess.run(["bash", "-c", f'{variable}="$1"; ' + assertion, "test", str(output)], capture_output=True, text=True, timeout=5)
                    self.assertNotEqual(result.returncode, 0)

    def test_timeout_retains_both_partial_streams(self):
        result, output, diagnostic = self.run_helper(
            'import sys, time\nprint("partial-output", flush=True)\nprint("partial-diagnostic", file=sys.stderr, flush=True)\ntime.sleep(10)\n',
            timeout=2,
        )
        self.assertEqual(result.returncode, 124)
        self.assertEqual(output, "partial-output\n")
        self.assertEqual(diagnostic, "partial-diagnostic\n")


if __name__ == "__main__":
    unittest.main()
