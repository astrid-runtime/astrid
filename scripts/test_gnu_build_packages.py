#!/usr/bin/env python3
"""Exercise package-source scope, argument forwarding and update failure."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).parent / "ci/install_gnu_build_packages.sh"


class PackageSetupTests(unittest.TestCase):
    def run_setup(self, fail_update=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / "calls.jsonl"
            apt = root / "apt-get"
            apt.write_text(
                "#!/usr/bin/env python3\n"
                "import json, os, pathlib, sys\n"
                "args = sys.argv[1:]\n"
                "source = next(a.split('=', 1)[1] for a in args "
                "if a.startswith('Dir::Etc::sourcelist='))\n"
                "with open(os.environ['APT_TEST_LOG'], 'a') as log:\n"
                " log.write(json.dumps({'args': args, 'path': source, "
                "'sources': pathlib.Path(source).read_text()}) + '\\n')\n"
                "if 'update' in args and os.environ['APT_TEST_FAIL'] == '1': "
                "sys.exit(100)\n"
            )
            apt.chmod(0o755)
            env = dict(os.environ, PATH=f"{root}:{os.environ['PATH']}",
                       APT_TEST_LOG=str(log), APT_TEST_FAIL=str(int(fail_update)))
            result = subprocess.run(
                ["bash", str(SCRIPT), "cmake", "gcc-aarch64-linux-gnu"],
                env=env, check=False,
            )
            calls = [json.loads(line) for line in log.read_text().splitlines()]
            for call in calls:
                self.assertFalse(Path(call["path"]).exists(), "temporary source leaked")
            return result.returncode, calls

    def test_signed_snapshot_sources_and_forwarded_packages(self):
        code, calls = self.run_setup()
        self.assertEqual(code, 0)
        self.assertEqual(len(calls), 2)
        for call in calls:
            self.assertIn("Dir::Etc::sourceparts=-", call["args"])
            self.assertNotIn("--allow-unauthenticated", call["args"])
            lines = call["sources"].splitlines()
            self.assertEqual(len(lines), 2)
            for line in lines:
                self.assertIn("https://snapshot.debian.org/archive/", line)
                self.assertIn("/20260901T000000Z/", line)
                self.assertIn("[check-valid-until=no]", line)
                self.assertNotIn("trusted=yes", line)
        self.assertEqual(calls[0]["sources"], calls[1]["sources"])
        self.assertEqual(calls[1]["args"][-5:],
                         ["install", "-y", "--no-install-recommends",
                          "cmake", "gcc-aarch64-linux-gnu"])

    def test_failed_update_never_installs(self):
        code, calls = self.run_setup(fail_update=True)
        self.assertEqual(code, 100)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["args"][-1], "update")


if __name__ == "__main__":
    unittest.main()
