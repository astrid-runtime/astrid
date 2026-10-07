"""Exercise the shipped shell handoff with bounded process-table fixtures."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


MANAGER = Path(__file__).with_name("manage-macos-fskit.sh")


class AppHandoff(unittest.TestCase):
    def run_handoff(self, *, live=True, mounted=False, foreign=False,
                    ignores_term=False, relaunch=False, reused=False,
                    process_error=False, mount_error=False):
        source = MANAGER.read_text()
        start = source.index("stop_app_before_replacement() {")
        end = source.index("\n}\n", start) + 3
        function = source[start:end]
        for command in ("pgrep", "ps", "kill", "mount", "sleep"):
            function = function.replace(f"/usr/bin/{command}", command)
            function = function.replace(f"/bin/{command}", command)
            function = function.replace(f"/sbin/{command}", command)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            if live:
                (root / "live").touch()
            prelude = r'''
set -eu
DESTINATION_APP=/owned/AstridFS.app
pgrep() {
  [ "$PROCESS_ERROR" = 0 ] || return 2
  if [ -e "$ROOT/live" ]; then echo 123; return 0; fi
  if [ "$RELAUNCH" = 1 ] && [ -e "$ROOT/signals" ]; then echo 456; return 0; fi
  return 1
}
mount() {
  [ "$MOUNT_ERROR" = 0 ] || return 1
  if [ "$MOUNTED" = 1 ]; then echo '/owned on /mount (astridfs)'; fi
}
app_process_matches() {
  echo "$1 $2" >> "$ROOT/validated"
  [ "$FOREIGN" = 0 ] && [ "$2" = 0 ]
}
ps() {
  [ -e "$ROOT/live" ] || return 1
  if [ -e "$ROOT/reused" ]; then echo NEW; else echo ORIGINAL; fi
}
kill() {
  echo "$*" >> "$ROOT/signals"
  if [ "$REUSED" = 1 ]; then touch "$ROOT/reused";
  elif [ "$IGNORE_TERM" = 0 ]; then rm "$ROOT/live"; fi
}
sleep() { :; }
'''
            env = dict(os.environ, ROOT=str(root), MOUNTED=str(int(mounted)),
                       FOREIGN=str(int(foreign)), IGNORE_TERM=str(int(ignores_term)),
                       RELAUNCH=str(int(relaunch)), REUSED=str(int(reused)),
                       PROCESS_ERROR=str(int(process_error)), MOUNT_ERROR=str(int(mount_error)))
            result = subprocess.run(["/bin/bash", "-c", prelude + function +
                                     "\nstop_app_before_replacement\n"],
                                    env=env, capture_output=True, text=True, timeout=5)
            signals = (root / "signals").read_text() if (root / "signals").exists() else ""
            return result, signals

    def test_cold_install_does_not_signal(self):
        result, signals = self.run_handoff(live=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(signals, "")

    def test_verified_old_app_exits_before_replacement(self):
        result, signals = self.run_handoff()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(signals, "-TERM 123\n")

    def test_active_mount_refuses_before_signal(self):
        result, signals = self.run_handoff(mounted=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Unmount", result.stderr)
        self.assertEqual(signals, "")

    def test_foreign_identity_refuses_before_signal(self):
        result, signals = self.run_handoff(foreign=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Cannot safely stop", result.stderr)
        self.assertEqual(signals, "")

    def test_unresponsive_app_is_not_force_killed(self):
        result, signals = self.run_handoff(ignores_term=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("has not been replaced", result.stderr)
        self.assertEqual(signals, "-TERM 123\n")

    def test_concurrent_relaunch_refuses_replacement(self):
        result, signals = self.run_handoff(relaunch=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("launched during", result.stderr)
        self.assertEqual(signals, "-TERM 123\n")

    def test_reused_pid_is_not_signalled_again(self):
        result, signals = self.run_handoff(reused=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(signals, "-TERM 123\n")

    def test_handoff_precedes_moving_old_bundle(self):
        source = MANAGER.read_text()
        install = source[source.index("install_app() {"):]
        self.assertLess(install.index("  stop_app_before_replacement\n"),
                        install.index('/bin/mv "$DESTINATION_APP" "$APP_BACKUP"'))

    def test_process_query_error_is_not_no_processes(self):
        result, signals = self.run_handoff(process_error=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(signals, "")

    def test_mount_query_error_refuses_signal(self):
        result, signals = self.run_handoff(mount_error=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(signals, "")


if __name__ == "__main__":
    unittest.main()
