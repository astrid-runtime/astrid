"""Causal refusal checks; no Cargo, benchmark, daemon, or live fixture access."""

import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "matched_packing", Path(__file__).with_name("matched_volume_packing.py"))
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
HEAD = "a" * 40


class RefusalTests(unittest.TestCase):
    def test_clean_source_and_identical_injection_are_distinct_states(self):
        with patch.object(MODULE, "command", side_effect=[HEAD, "", ""]):
            MODULE.clean_checkout(Path("unused"), HEAD)
        with patch.object(MODULE, "command", side_effect=[HEAD, "", MODULE.INJECTION]):
            MODULE.clean_checkout(Path("unused"), HEAD, injected=True)

    def test_wrong_head_dirty_source_and_extra_untracked_each_refuse(self):
        for answers in [["b" * 40], [HEAD, "tracked diff"],
                        [HEAD, "", "unexpected.rs"],
                        [HEAD, "", MODULE.INJECTION + "\nextra.rs"]]:
            with self.subTest(answers=answers), patch.object(
                    MODULE, "command", side_effect=answers):
                with self.assertRaises(RuntimeError):
                    MODULE.clean_checkout(Path("unused"), HEAD, injected=True)

    def test_non_sha_ref_refuses_before_git(self):
        with patch.object(MODULE, "command") as command:
            with self.assertRaises(RuntimeError):
                MODULE.clean_checkout(Path("unused"), "main; echo unsafe")
            command.assert_not_called()

    def test_busy_background_holds_without_signalling(self):
        with patch.object(MODULE, "command", return_value="9.5 runner\n1.0 service"):
            self.assertFalse(MODULE.quiet_snapshot()["quiet"])
        with patch.object(MODULE, "command", return_value="0.5 runner\n1.0 service"):
            self.assertTrue(MODULE.quiet_snapshot()["quiet"])

    def test_local_host_refuses_before_output_or_build(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "must-not-exist"
            argv = ["probe", "--baseline", directory, "--candidate", directory,
                    "--baseline-head", HEAD, "--candidate-head", HEAD,
                    "--output", str(output)]
            with patch("sys.argv", argv), patch.dict("os.environ", {}, clear=True), \
                    patch.object(MODULE, "build") as build:
                with self.assertRaisesRegex(RuntimeError, "GitHub-hosted"):
                    MODULE.main()
                build.assert_not_called()
                self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
