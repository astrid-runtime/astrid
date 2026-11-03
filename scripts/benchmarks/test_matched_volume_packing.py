"""Causal refusal checks; no Cargo, benchmark, daemon, or live fixture access."""

import importlib.util
from pathlib import Path
import tempfile
import subprocess
import unittest
from unittest.mock import MagicMock, patch


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
        # Two cores, 200 ticks: 15 busy ticks are 15% of one core, not 7.5%.
        with patch.object(MODULE, "command", side_effect=["2", "0.0 observer"]), \
                patch.object(MODULE, "cpu_ticks", side_effect=[
                    [100, 100, 100, 100], [110, 105, 285, 100]]), \
                patch.object(MODULE.time, "sleep"), \
                patch.object(MODULE.os, "killpg") as signal:
            result = MODULE.quiet_snapshot()
        self.assertFalse(result["quiet"])
        self.assertEqual(result["background_cpu_percent"], 15.0)
        signal.assert_not_called()

    def test_idle_observer_is_not_busy_because_of_prior_hashing(self):
        # Causal reproduction of run41598553008: stale observer ps=40.9%.
        with patch.object(MODULE, "command", side_effect=["2", "40.9 observer"]), \
                patch.object(MODULE, "cpu_ticks", side_effect=[
                    [100, 100, 100, 100], [100, 100, 300, 100]]), \
                patch.object(MODULE.time, "sleep"):
            result = MODULE.quiet_snapshot()
        self.assertTrue(result["quiet"])
        self.assertEqual(result["background_cpu_percent"], 0)
        self.assertEqual(result["rows"], ["40.9 observer"])

    def test_quiet_threshold_and_counter_wrap(self):
        for busy, accepted in [(10, True), (11, False)]:
            with self.subTest(busy=busy), patch.object(
                    MODULE, "command", side_effect=["2", ""]), \
                    patch.object(MODULE, "cpu_ticks", side_effect=[
                        [(1 << 32) - 5, 0, 0, 0],
                        [busy - 5, 0, 200 - busy, 0]]), \
                    patch.object(MODULE.time, "sleep"):
                result = MODULE.quiet_snapshot()
            self.assertEqual(result["quiet"], accepted)
            self.assertEqual(result["background_cpu_percent"], busy)

    def test_unavailable_cpu_measurement_fails_closed(self):
        with patch.object(MODULE, "command", return_value="2"), \
                patch.object(MODULE, "cpu_ticks", return_value=[1, 1, 1, 1]), \
                patch.object(MODULE.time, "sleep"):
            with self.assertRaisesRegex(RuntimeError, "did not advance"):
                MODULE.quiet_snapshot()

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

    def test_corrupted_copy_refuses_before_cargo(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / MODULE.INJECTION).parent.mkdir(parents=True)

            def corrupt_copy(_source, target):
                target.write_bytes(b"wrong probe")

            with patch.object(MODULE, "clean_checkout"), \
                    patch.object(MODULE.shutil, "copyfile", side_effect=corrupt_copy), \
                    patch.object(MODULE.subprocess, "Popen") as cargo:
                with self.assertRaisesRegex(RuntimeError, "changed during copy"):
                    MODULE.build(root, HEAD, root / "unused", root, "main", float("inf"))
                cargo.assert_not_called()

    def test_timeout_and_postsample_hold_preserve_fixture_and_output(self):
        for timed_out in [False, True]:
            with self.subTest(timed_out=timed_out), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                fixture = root / "fixture"
                fixture.mkdir()
                sample = {"count": 32768, "regions": 7, "phase": "timed"}
                response = subprocess.CompletedProcess([], 0, b"complete=true\n", b"")
                timeout = subprocess.TimeoutExpired("fake", 180, output=b"partial", stderr=b"late")
                with patch.object(MODULE.subprocess, "run", return_value=response,
                                  side_effect=timeout if timed_out else None), \
                        patch.object(MODULE, "quiet_snapshot", return_value={"quiet": timed_out}):
                    with self.assertRaises(RuntimeError):
                        MODULE.run_sample("fake", fixture, root, 0, sample)
                self.assertTrue(sample["child_reaped"])
                self.assertTrue(sample["fixture_preserved"])
                self.assertTrue(fixture.exists())
                self.assertEqual(sample["timed_out"], timed_out)
                self.assertIn("quiet_after", sample)
                self.assertEqual(sample["stdout_sha256"], MODULE.sha(root / "sample-00.stdout"))
                self.assertEqual((root / "sample-00.stdout").read_bytes(),
                                 b"partial" if timed_out else b"complete=true\n")

    def test_success_reaps_fixture_only_after_quiet_validity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = root / "fixture"
            fixture.mkdir()
            sample = {"count": 32768, "regions": 7, "phase": "timed"}
            response = subprocess.CompletedProcess([], 0, b"complete=true\n", b"")
            with patch.object(MODULE.subprocess, "run", return_value=response), \
                    patch.object(MODULE, "quiet_snapshot", return_value={"quiet": True}):
                MODULE.run_sample("fake", fixture, root, 0, sample)
            self.assertTrue(sample["fixture_reaped"])
            self.assertFalse(sample["fixture_preserved"])
            self.assertFalse(fixture.exists())

    def test_build_deadline_refuses_before_cargo(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / MODULE.INJECTION).parent.mkdir(parents=True)
            probe = Path(__file__).with_name("volume_packing_probe.rs")
            with patch.object(MODULE, "clean_checkout"), \
                    patch.object(MODULE.subprocess, "Popen") as cargo:
                with self.assertRaisesRegex(RuntimeError, "budget exhausted"):
                    MODULE.build(root, HEAD, probe, root, "main", 0)
                cargo.assert_not_called()

    def test_build_timeout_reaps_only_its_new_process_group(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / MODULE.INJECTION).parent.mkdir(parents=True)
            probe = Path(__file__).with_name("volume_packing_probe.rs")
            process = MagicMock(pid=123456)
            process.wait.side_effect = [subprocess.TimeoutExpired("fake-cargo", 900), 0]
            with patch.object(MODULE, "clean_checkout"), \
                    patch.object(MODULE.subprocess, "Popen", return_value=process) as cargo, \
                    patch.object(MODULE.os, "killpg") as kill:
                with self.assertRaises(subprocess.TimeoutExpired):
                    MODULE.build(root, HEAD, probe, root, "main", float("inf"))
                self.assertTrue(cargo.call_args.kwargs["start_new_session"])
                kill.assert_called_once_with(123456, MODULE.signal.SIGKILL)
                self.assertEqual(process.wait.call_count, 2)


if __name__ == "__main__":
    unittest.main()
