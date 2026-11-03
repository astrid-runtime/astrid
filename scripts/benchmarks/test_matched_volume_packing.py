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

    def test_postbuild_settling_requires_two_consecutive_quiet_windows(self):
        receipt = {}
        with patch.object(MODULE, "quiet_snapshot", side_effect=[
                {"quiet": False}, {"quiet": True}, {"quiet": False},
                {"quiet": True}, {"quiet": True}]), \
                patch.object(MODULE, "run_sample") as sample:
            save = MagicMock()
            MODULE.settle_after_builds(receipt, save, float("inf"))
        self.assertEqual(len(receipt["postbuild_settling"]["windows"]), 5)
        self.assertEqual(receipt["postbuild_settling"]["consecutive_quiet"], 2)
        self.assertEqual(save.call_count, 5)
        sample.assert_not_called()

    def test_persistent_load_holds_after_bounded_settling(self):
        receipt = {}
        with patch.object(MODULE, "quiet_snapshot", return_value={"quiet": False}), \
                patch.object(MODULE, "run_sample") as sample:
            with self.assertRaisesRegex(RuntimeError, "did not settle"):
                MODULE.settle_after_builds(receipt, MagicMock(), float("inf"))
        self.assertEqual(len(receipt["postbuild_settling"]["windows"]), 30)
        sample.assert_not_called()

    def test_settling_does_not_spend_reserved_sample_budget(self):
        with patch.object(MODULE, "quiet_snapshot") as snapshot:
            with self.assertRaisesRegex(RuntimeError, "run budget"):
                MODULE.settle_after_builds({}, MagicMock(), 0)
        snapshot.assert_not_called()

    def test_presample_burst_wait_keeps_every_window_without_executing_a_sample(self):
        receipt = {"samples": []}
        windows = [{"quiet": value, "rows": ["context"]}
                   for value in (False, True, False, True, True)]
        with patch.object(MODULE, "quiet_snapshot", side_effect=windows), \
                patch.object(MODULE, "run_sample") as sample:
            save = MagicMock()
            result = MODULE.settle_before_sample(receipt, save, float("inf"), {"index": 7})
        state = receipt["presample_settling"][0]
        self.assertEqual(state["identity"], {"index": 7})
        self.assertEqual(state["windows"], windows)
        self.assertIs(result, windows[-1])
        self.assertEqual(save.call_count, 5)
        self.assertEqual(receipt["samples"], [])
        sample.assert_not_called()
        summary = MODULE.terminal_receipt(receipt)
        retained = summary["presample_settling"][0]["windows"]
        self.assertEqual([w["quiet"] for w in retained], [False, True, False, True, True])
        self.assertTrue(all(w["rows_omitted_from_terminal"] for w in retained))

    def test_presample_persistent_load_is_bounded_without_discarding_history(self):
        receipt = {"samples": [{"complete": True, "arm": "main"}]}
        with patch.object(MODULE, "quiet_snapshot", return_value={"quiet": False}):
            with self.assertRaisesRegex(RuntimeError, "presample background load did not settle"):
                MODULE.settle_before_sample(receipt, MagicMock(), float("inf"), {"ordinal": 1})
        self.assertEqual(len(receipt["presample_settling"][0]["windows"]), 30)
        self.assertEqual(receipt["samples"], [{"complete": True, "arm": "main"}])

    def test_presample_does_not_admit_after_observation_spends_remaining_budget(self):
        receipt = {}
        with patch.object(MODULE.time, "monotonic", side_effect=[0, 0, 200]), \
                patch.object(MODULE, "quiet_snapshot", return_value={"quiet": True}):
            with self.assertRaisesRegex(RuntimeError, "full sample after settling"):
                MODULE.settle_before_sample(receipt, MagicMock(), 300, {"index": 0})
        self.assertEqual(len(receipt["presample_settling"][0]["windows"]), 2)

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
                    patch.object(MODULE.os, "killpg") as kill, \
                    patch.object(MODULE.source_build, "prepare", return_value={}):
                with self.assertRaises(subprocess.TimeoutExpired):
                    MODULE.build(root, HEAD, probe, root, "main", float("inf"))
                self.assertTrue(cargo.call_args.kwargs["start_new_session"])
                kill.assert_called_once_with(123456, MODULE.signal.SIGKILL)
                self.assertEqual(process.wait.call_count, 2)


    def test_terminal_receipt_is_compact_and_truthful_on_hold(self):
        receipt = {
            "complete": False,
            "performance_accepted": False,
            "failure": "background load before sample: HOLD",
            "workflow_sha": HEAD,
            "protocol_checkout_head": HEAD,
            "protocol_tree": "c" * 40,
            "builds": {
                "main": {
                    "head": HEAD,
                    "tree": "d" * 40,
                    "lock_sha256": "e" * 64,
                    "binary": "/tmp/main-probe",
                    "binary_sha256": "f" * 64,
                    "artifacts": [{"sha256": "1" * 64, "path": "/huge"}],
                    "rustc": "rustc 1.95.0",
                }
            },
            "postbuild_settling": {
                "windows": [{
                    "quiet": True,
                    "background_cpu_percent": 1.0,
                    "rows": ["40.9 observer"] * 50,
                }]
            },
            "quiet_gate_before_sample": {
                "index": 0,
                "quiet": False,
                "background_cpu_percent": 18.5,
                "rows": ["busy"] * 20,
            },
            "samples": [],
            "schedule": [("main", 32768, 7, "warmup")],
        }
        summary = MODULE.terminal_receipt(receipt)
        self.assertEqual(summary["schema"], MODULE.TERMINAL_RECEIPT_MARKER)
        self.assertFalse(summary["complete"])
        self.assertEqual(summary["failure"], "background load before sample: HOLD")
        self.assertTrue(summary["samples_present"])
        self.assertEqual(summary["sample_count"], 0)
        self.assertEqual(summary["samples"], [])
        self.assertEqual(summary["builds"]["main"]["artifact_count"], 1)
        self.assertNotIn("rows", summary["quiet_observations"][0])
        self.assertEqual(summary["quiet_observations"][0]["observation"]["row_count"], 50)
        self.assertEqual(summary["quiet_observations"][1]["kind"], "quiet_gate_before_sample")
        self.assertEqual(summary["quiet_observations"][1]["observation"]["index"], 0)
        self.assertFalse(summary["quiet_observations"][1]["observation"]["quiet"])
        encoded = MODULE.json.dumps(summary)
        self.assertNotIn("40.9 observer", encoded)
        self.assertLess(len(encoded), 8000)

    def test_terminal_fallback_preserves_malformed_quiet_evidence(self):
        receipt = {"failure": "original failure", "postbuild_settling": {"windows": [None]},
                   "quiet_gate_before_sample": "incomplete"}
        summary = MODULE.terminal_receipt(receipt)
        self.assertEqual(summary["failure"], "original failure")
        self.assertIsNone(summary["postbuild_settling"]["windows"][0])
        self.assertEqual(summary["quiet_gate_before_sample"], "incomplete")
        self.assertIsNone(summary["sample_count"])

    def test_terminal_receipt_missing_samples_not_reinterpreted_as_zero(self):
        summary = MODULE.terminal_receipt({"complete": False})
        self.assertFalse(summary["samples_present"])
        self.assertIsNone(summary["sample_count"])
        self.assertIsNone(summary["samples"])
        missing = MODULE.terminal_receipt("absent")
        self.assertIsNone(missing["sample_count"])
        self.assertIn("not reinterpreted", missing["failure"])

    def test_terminal_fallback_preserves_client_identity_and_memory_evidence(self):
        # Artifact finalization can fail after collection. The fallback must
        # retain evidence needed to interpret timings, not just their values.
        receipt = {
            "client": {"path": "owned-client", "sha256": "a" * 64,
                       "artifacts": [{"identity_sha256": "b" * 64}]},
            "runs": [{"ordinal": 0, "first_upgrade": {
                "ready_process_metrics": {"rss_bytes": 1234},
                "terminal_process_metrics": {"max_rss_bytes": 5678},
                "shutdown_deadline_exceeded": True,
            }, "operations": [{"daemon_before": {"rss_bytes": 9012}}]}],
        }
        original = MODULE.json.dumps(receipt, sort_keys=True)
        summary = MODULE.terminal_receipt(receipt)
        self.assertEqual(summary["client"], receipt["client"])
        self.assertEqual(summary["runs"], receipt["runs"])
        self.assertEqual(MODULE.json.dumps(receipt, sort_keys=True), original)

    def test_compiler_inventory_hash_binds_the_complete_ordered_inventory(self):
        artifacts = [{"z": 1, "a": "duplicate"}, {"a": "duplicate", "z": 2}]
        receipt = {"builds": {"main": {"artifacts": artifacts}}}
        summary = MODULE.terminal_receipt(receipt)["builds"]["main"]
        canonical = MODULE.json.dumps(artifacts, sort_keys=True, separators=(",", ":")).encode()
        self.assertEqual(summary["artifact_inventory_sha256"], MODULE.hashlib.sha256(canonical).hexdigest())
        self.assertEqual(summary["artifact_count"], 2)

    def test_terminal_fallback_cannot_mask_the_primary_failure(self):
        for failure in (BrokenPipeError("closed stdout"), TypeError("bad JSON")):
            with self.subTest(failure=failure), patch("builtins.print", side_effect=failure):
                with self.assertRaisesRegex(RuntimeError, "original quiet HOLD"):
                    try:
                        raise RuntimeError("original quiet HOLD")
                    finally:
                        MODULE.emit_terminal_receipt({"complete": False})

    def test_packing_publication_excludes_preserved_volumes_and_binaries(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            receipt = {"complete": False, "performance_accepted": False}
            (root / "receipt.json").write_text(MODULE.json.dumps(receipt))
            fixture = root / "packing-failed"
            fixture.mkdir()
            (fixture / "volume").write_bytes(b"preserved synthetic volume")
            (root / "main-probe").write_bytes(b"binary")
            (root / "sample-00.stdout").write_text("complete=false")
            with patch.object(MODULE, "emit_terminal_receipt"):
                MODULE.finalize_evidence(root, receipt, lambda: None)
            files = sorted(str(p.relative_to(root / "public"))
                           for p in (root / "public").rglob("*") if p.is_file())
            self.assertEqual(files, ["manifest.json", "receipt.json", "sample-00.stdout"])
            self.assertTrue((fixture / "volume").exists())
            workflow = Path(__file__).resolve().parents[2] / ".github/workflows/storage-benchmark.yml"
            self.assertIn("path: astrid-benchmark.noindex/packing-evidence/public", workflow.read_text())

    def test_packing_final_save_failure_still_publishes_and_emits(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "receipt.json").write_text('{"complete": false}')
            receipt = {"complete": True}
            with patch.object(MODULE, "emit_terminal_receipt") as emit:
                with self.assertRaisesRegex(OSError, "save failed"):
                    MODULE.finalize_evidence(root, receipt, MagicMock(side_effect=OSError("save failed")))
            self.assertFalse(receipt["complete"])
            self.assertTrue((root / "public/receipt.json").exists())
            emit.assert_called_once_with(receipt)

if __name__ == "__main__":
    unittest.main()
