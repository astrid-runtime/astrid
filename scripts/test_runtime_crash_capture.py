"""Exercise the real crash-smoke capture helper with noisy CLI diagnostics."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class CaptureTests(unittest.TestCase):
    def test_json_preserves_stdout_and_records_stderr(self):
        script = Path(__file__).parent / "e2e/runtime-crash-smoke.sh"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "target/debug/astrid"
            binary.parent.mkdir(parents=True)
            binary.write_text(
                "#!/bin/sh\n"
                "echo 'Update available: v2026.9.1 -> v2026.9.0' >&2\n"
                "echo '[{\"principal\":\"default\",\"owner_uid\":\"test-owner\"}]'\n"
                'exit "${FAKE_EXIT:-0}"\n'
            )
            binary.chmod(0o755)
            output = root / "roster.json"
            for status in (0, 7):
                with self.subTest(status=status):
                    result = subprocess.run(
                        ["bash", "-c", 'source "$1"; bounded_principal_cli default 8 "$2" agent list --format json',
                         "capture-test", str(script), str(output)],
                        env={**os.environ, "CORE_DIR": str(root), "PYTHON": sys.executable,
                             "FAKE_EXIT": str(status)},
                        capture_output=True, text=True, check=False,
                    )
                    self.assertEqual(result.returncode, status, result.stderr)
                    self.assertEqual(json.loads(output.read_text())[0]["owner_uid"], "test-owner")
                    self.assertIn("Update available", (root / "roster.json.stderr").read_text())


if __name__ == "__main__":
    unittest.main()
