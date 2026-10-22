#!/usr/bin/env python3
"""Run the actual Windows gate's failure prefix with inert Cargo fixtures."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


WORKFLOW = Path(__file__).resolve().parent.parent / ".github/workflows/windows-filesystem-native.yml"
POWERSHELL = shutil.which("pwsh")


@unittest.skipUnless(POWERSHELL, "PowerShell required for actual workflow execution")
class WindowsCargoDiagnosticTests(unittest.TestCase):
    def run_gate(self, build_exit=0):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = WORKFLOW.read_text().split(
                "      - name: Run storage callback transport tests in trusted staging\n", 1
            )[1].split("        run: |\n", 1)[1].split("\n      - name:", 1)[0]
            code = "\n".join(line[10:] if line.startswith("          ") else line for line in source.splitlines())
            code = code.replace("${{ matrix.target }}", "fixture-target")
            script = root / "gate.ps1"
            script.write_text(
                "function cargo {\n"
                "  if ($args[0] -eq 'build') { $global:LASTEXITCODE = [int]$env:FIXTURE_BUILD_EXIT; return }\n"
                "  '{\"reason\":\"compiler-message\",\"message\":{\"rendered\":\"error[E9999]: fixture compiler failure\"}}'\n"
                "  $global:LASTEXITCODE = 42\n"
                "}\n" + code
            )
            environment = os.environ.copy()
            environment.update(FIXTURE_BUILD_EXIT=str(build_exit))
            try:
                # This bounds a cold PowerShell process, not the tested Cargo gate.
                # Hosted execution of this inert fixture exceeded the former 20 seconds.
                return subprocess.run(
                    [POWERSHELL, "-NoProfile", "-NonInteractive", "-File", str(script)],
                    cwd=root, env=environment, capture_output=True, text=True,
                    timeout=60, check=False,
                )
            except subprocess.TimeoutExpired as error:
                self.fail(
                    "inert PowerShell gate timed out; "
                    f"stdout={error.stdout!r}; stderr={error.stderr!r}"
                )

    def test_compile_error_is_rendered_and_original_exit_precedes_artifact_selection(self):
        result = self.run_gate()
        self.assertEqual(result.returncode, 42, result.stdout + result.stderr)
        self.assertIn("error[E9999]: fixture compiler failure", result.stdout)
        self.assertNotIn("expected exactly one", result.stdout + result.stderr)

    def test_provider_build_failure_stops_before_test_compile(self):
        result = self.run_gate(build_exit=17)
        self.assertEqual(result.returncode, 17, result.stdout + result.stderr)
        self.assertNotIn("fixture compiler failure", result.stdout + result.stderr)
        self.assertNotIn("expected exactly one", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
