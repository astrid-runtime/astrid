"""Check shutdown failure reporting without launching or killing a real daemon."""

from pathlib import Path
import subprocess
import unittest


class ShutdownDiagnosticsTests(unittest.TestCase):
    def run_stop(self, scenario):
        helper = Path(__file__).parent / "e2e/runtime-process-helpers.sh"
        return subprocess.run(
            ["bash", "-c", r'''
set -euo pipefail
source "$1"
scenario=$2
DAEMON_PID=12345
killed=false
kill() {
  if [[ $1 == -KILL ]]; then killed=true; return 0; fi
  if [[ $1 == -0 ]]; then [[ $scenario == timeout ]]; return; fi
  return 0
}
sleep() { :; }
wait() {
  case $scenario in clean) return 0;; nonzero) return 7;; timeout) return 137;; esac
}
status=0
stop_daemon || status=$?
printf 'status=%s pid=%s killed=%s\n' "$status" "$DAEMON_PID" "$killed"
exit "$status"
''', "shutdown-test", str(helper), scenario],
            capture_output=True, text=True, check=False, timeout=5,
        )

    def test_clean_exit_stays_successful(self):
        result = self.run_stop("clean")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("pid= killed=false", result.stdout)

    def test_nonzero_exit_is_reported_and_remains_failure(self):
        result = self.run_stop("nonzero")
        self.assertEqual(result.returncode, 1)
        self.assertIn("exit_status=7", result.stderr)
        self.assertIn("forced_kill=false", result.stderr)
        self.assertIn("pid= killed=false", result.stdout)

    def test_timeout_is_reported_and_remains_failure(self):
        result = self.run_stop("timeout")
        self.assertEqual(result.returncode, 1)
        self.assertIn("exit_status=137", result.stderr)
        self.assertIn("forced_kill=true", result.stderr)
        self.assertIn("pid= killed=true", result.stdout)


if __name__ == "__main__":
    unittest.main()
