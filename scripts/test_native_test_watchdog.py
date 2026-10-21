#!/usr/bin/env python3
"""Exercise the real PowerShell native-test watchdog with owned subprocesses."""

from pathlib import Path
import shutil
import queue
import threading
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
WATCHDOG = ROOT / "scripts/run-bounded-native-test.ps1"
POWERSHELL = shutil.which("pwsh")


class NativeWatchdogWorkflowTests(unittest.TestCase):
    def test_trusted_binary_has_an_external_watchdog(self):
        workflow = (ROOT / ".github/workflows/windows-filesystem-native.yml").read_text()
        step = workflow.split("      - name: Run storage callback transport tests in trusted staging\n", 1)[1].split("\n      - name:", 1)[0]
        self.assertIn("run-bounded-native-test.ps1", step)
        self.assertIn("-FilePath $stagedTestExecutable", step)
        self.assertIn("-TimeoutSeconds 600", step)
        self.assertNotIn("& $stagedTestExecutable storage_mount", step)


@unittest.skipUnless(POWERSHELL, "PowerShell required for actual owned-process tests")
class NativeWatchdogTests(unittest.TestCase):
    def command(self, script, timeout=20, executable=POWERSHELL):
        def quote(value):
            return "'" + str(value).replace("'", "''") + "'"
        arguments = ", ".join(quote(value) for value in
                              ["-NoProfile", "-NonInteractive", "-File", script])
        code = (f"& {quote(WATCHDOG)} -FilePath {quote(executable)} "
                f"-TimeoutSeconds {timeout} -Arguments @({arguments}); exit $LASTEXITCODE")
        return [POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", code]

    def run_fixture(self, code, timeout=20):
        with tempfile.TemporaryDirectory() as temporary:
            script = Path(temporary) / "owned fixture.ps1"
            script.write_text(code)
            return subprocess.run(self.command(script, timeout), capture_output=True,
                                  text=True, timeout=60, check=False)

    def test_success_and_argument_boundaries(self):
        result = self.run_fixture('[Console]::Out.WriteLine("success"); exit 0')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("success", result.stdout)

    def test_nonzero_exit_and_stderr_are_preserved(self):
        result = self.run_fixture('[Console]::Error.WriteLine("failure detail"); exit 37')
        self.assertEqual(result.returncode, 37, result.stdout + result.stderr)
        self.assertIn("failure detail", result.stderr)

    def test_start_failure_is_explicit(self):
        result = subprocess.run(self.command("unused", executable="missing-native-test-executable"),
                                capture_output=True, text=True, timeout=30, check=False)
        self.assertEqual(result.returncode, 125, result.stdout + result.stderr)
        self.assertIn("native test harness failure", result.stderr)

    def test_output_is_immediate_and_timeout_observes_owned_child_exit(self):
        with tempfile.TemporaryDirectory() as temporary:
            script = Path(temporary) / "owned hang.ps1"
            marker = Path(temporary) / "owned-child.json"
            marker_literal = str(marker).replace("'", "''")
            script.write_text(
                f"@{{pid=$PID;started=(Get-Process -Id $PID).StartTime.ToUniversalTime().Ticks}} | "
                f"ConvertTo-Json | Set-Content -LiteralPath '{marker_literal}'; "
                '[Console]::Out.WriteLine("owned-pid=$PID"); '
                '[Console]::Error.WriteLine("before timeout"); Start-Sleep 30')
            process = subprocess.Popen(self.command(script, 5), stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, text=True)
            lines = queue.Queue()
            output, errors = [], []

            def collect(pipe, destination, signal=False):
                for line in pipe:
                    destination.append(line)
                    if signal:
                        lines.put(line)
                pipe.close()

            readers = [threading.Thread(target=collect, args=(process.stdout, output, True), daemon=True),
                       threading.Thread(target=collect, args=(process.stderr, errors), daemon=True)]
            for reader in readers:
                reader.start()
            try:
                line = lines.get(timeout=20)
                self.assertTrue(line.startswith("owned-pid="), line)
                self.assertIsNone(process.poll(), "output must arrive before process exit")
                process.wait(timeout=30)
                for reader in readers:
                    reader.join(timeout=5)
                    self.assertFalse(reader.is_alive(), "owned output reader did not settle")
                stderr = "".join(errors)
                self.assertEqual(process.returncode, 124, "".join(output) + stderr)
                self.assertIn("before timeout", stderr)
                self.assertIn("observed owned process exit", stderr)
                child_pid = int(line.strip().split("=", 1)[1])
                check = subprocess.run(
                    [POWERSHELL, "-NoProfile", "-NonInteractive", "-Command",
                     f"try {{ $null = Get-Process -Id {child_pid} -ErrorAction Stop; exit 1 }} catch {{ exit 0 }}"],
                    capture_output=True, text=True, timeout=30, check=False)
                self.assertEqual(check.returncode, 0, "owned child remains alive")
            finally:
                # Independent marker survives failed/missing stdout. Match creation
                # time before cleanup so a recycled numeric PID is never targeted.
                cleanup = (
                    f"$marker = '{marker_literal}'; "
                    "if (Test-Path -LiteralPath $marker) { "
                    "$owned = Get-Content -Raw -LiteralPath $marker | ConvertFrom-Json; "
                    "$child = Get-Process -Id $owned.pid -ErrorAction SilentlyContinue; "
                    "if ($child -and $child.StartTime.ToUniversalTime().Ticks -eq $owned.started) { "
                    "$child.Kill($true); if (-not $child.WaitForExit(5000)) { exit 125 } } }; exit 0")
                cleaned = subprocess.run([POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", cleanup],
                                         capture_output=True, text=True, timeout=30, check=False)
                if process.poll() is None:
                    process.kill()  # Popen retains the exact outer process handle.
                process.wait(timeout=10)
                for reader in readers:
                    reader.join(timeout=5)
                self.assertEqual(cleaned.returncode, 0, cleaned.stderr)
                self.assertFalse(any(reader.is_alive() for reader in readers), "output custody leaked")


if __name__ == "__main__":
    unittest.main()
