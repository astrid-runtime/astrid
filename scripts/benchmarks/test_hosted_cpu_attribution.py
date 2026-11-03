"""All native APIs, sleeping, child execution and guard platform are mocked."""
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location("cpu_attribution", Path(__file__).with_name("hosted_cpu_attribution.py"))
D = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(D)


def row(start=1, user=0, system=0, at=0, read=0, written=0):
    return {"proc_start_abstime": start, "user_time": user, "system_time": system,
            "at_ns": at, "diskio_bytesread": read, "diskio_byteswritten": written, "name": "mock"}


def snapshot(rows=None, missing=None):
    return {"rows": rows or {}, "missing": missing or [], "enumeration_ns": 50,
            "enumeration_saturated": False}


class PureTests(unittest.TestCase):
    def test_host_counter_failure_is_preserved_when_port_release_also_fails(self):
        api = object.__new__(D.Darwin)
        api.task = 9
        api.mach = SimpleNamespace(mach_host_self=Mock(return_value=7),
                                   host_statistics=Mock(return_value=1),
                                   mach_port_deallocate=Mock(return_value=1))
        with self.assertRaisesRegex(RuntimeError, "Mach CPU counters unavailable"):
            api.ticks()
        api.mach.mach_port_deallocate.assert_called_once_with(9, 7)

    def test_port_release_failure_is_reported_when_host_counter_read_succeeds(self):
        api = object.__new__(D.Darwin)
        api.task = 9
        api.mach = SimpleNamespace(mach_host_self=Mock(return_value=7),
                                   host_statistics=Mock(return_value=0),
                                   mach_port_deallocate=Mock(return_value=1))
        with self.assertRaisesRegex(RuntimeError, "Mach host port release failed"):
            api.ticks()

    def test_sdk_v2_layout(self):
        self.assertEqual(ctypes.sizeof(D.Usage), 160)
        self.assertEqual(D.Usage.proc_start_abstime.offset, 80)
        self.assertEqual(D.Usage.diskio_bytesread.offset, 144)
        self.assertEqual(D.Usage.diskio_byteswritten.offset, 152)

    def test_nonunit_mach_timebase_and_io_conversion(self):
        before = snapshot({1: row(user=12, system=24, at=100, read=10, written=20)})
        after = snapshot({1: row(user=36, system=48, at=2100, read=40, written=70)})
        result = D.compare(before, after, 125, 3)["process_deltas"][0]
        self.assertEqual((result["user_ns"], result["system_ns"]), (1000, 1000))
        self.assertEqual(result["one_core_cpu_percent"], 100)
        self.assertEqual(result["raw_delta"]["diskio_byteswritten"], 50)

    def test_pid_reuse_is_never_subtracted(self):
        result = D.compare(snapshot({7: row(start=1, user=100)}),
                           snapshot({7: row(start=2, user=300, at=100)}), 1, 1)
        self.assertEqual(result["process_deltas"], [])
        self.assertEqual(result["identity_gaps"]["reused"], [7])

    def test_missing_new_disappeared_and_counter_regression_are_gaps(self):
        before = snapshot({1: row(), 3: row(user=5)}, [{"pid": 2, "errno": 1}])
        after = snapshot({2: row(at=1), 3: row(user=2, at=1)}, [{"pid": 1, "errno": 3}])
        result = D.compare(before, after, 1, 1)
        self.assertEqual(result["identity_gaps"]["disappeared"], [1])
        self.assertEqual(result["identity_gaps"]["new"], [2])
        self.assertEqual(result["identity_gaps"]["counter_regression"], [3])
        self.assertEqual(result["missing_before"], before["missing"])
        self.assertTrue(result["unseen_short_lived_processes_possible"])

    def test_observer_accounting_and_host_ticks_have_same_bracket(self):
        api = SimpleNamespace(numer=125, denom=3, cores=3,
                              ticks=Mock(side_effect=[[0, 0, 0, 0], [10, 10, 280, 0]]),
                              snapshot=Mock(side_effect=[snapshot(), snapshot()]))
        with patch.object(D, "self_cpu", side_effect=[2, 2.02]), \
                patch.object(D.time, "monotonic_ns", side_effect=[0, 1_000_000_000]), \
                patch.object(D.time, "sleep") as sleep:
            result = D.interval(api)
        self.assertEqual(result["host_one_core_cpu_percent"], 20)
        self.assertAlmostEqual(result["observer_one_core_cpu_percent"], 2)
        self.assertEqual(result["before"]["enumeration_ns"], 50)
        self.assertEqual(result["wall_ns"], 1_000_000_000)
        sleep.assert_called_once_with(1)

    def test_pid_enumeration_records_read_failures_and_saturation(self):
        api = object.__new__(D.Darwin)
        def enumerate_pids(buffer, size):
            buffer[0] = 17
            return 8192
        api.proc = SimpleNamespace(proc_listallpids=Mock(side_effect=enumerate_pids),
                                   proc_pid_rusage=Mock(return_value=-1))
        with patch.object(D.C, "get_errno", return_value=13):
            observed = api.snapshot()
        self.assertTrue(observed["enumeration_saturated"])
        self.assertEqual(observed["missing"], [{"pid": 17, "errno": 13}])

    def test_unavailable_start_identity_is_an_explicit_gap(self):
        api = object.__new__(D.Darwin)
        def enumerate_pids(buffer, size):
            buffer[0] = 17
            return 1
        api.proc = SimpleNamespace(proc_listallpids=Mock(side_effect=enumerate_pids),
                                   proc_pid_rusage=Mock(return_value=0))
        observed = api.snapshot()
        self.assertEqual(observed["rows"], {})
        self.assertEqual(observed["missing"], [{"pid": 17, "reason": "start identity unavailable"}])


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.workspace = Path(self.temp.name).resolve()
        self.root = self.workspace / "astrid-benchmark.noindex"
        self.source = self.root / "diagnostic/hosted_cpu_attribution.py"
        self.source.parent.mkdir(parents=True)
        self.source.write_text("# mocked staged source")
        self.root.chmod(0o700)
        self.environment = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
                            "RUNNER_OS": "macOS", "GITHUB_REPOSITORY": "astrid-runtime/astrid",
                            "GITHUB_JOB": "matched-packing", "GITHUB_WORKSPACE": str(self.workspace)}
        for context in (patch.dict(os.environ, self.environment, clear=True),
                        patch.object(D, "__file__", str(self.source)),
                        patch.object(D.platform, "system", return_value="Darwin")):
            context.start()
            self.addCleanup(context.stop)

    def test_native_initialization_and_child_never_run_for_invalid_context(self):
        for key, value in (("GITHUB_ACTIONS", "false"), ("RUNNER_ENVIRONMENT", "self-hosted"),
                           ("RUNNER_OS", "Linux"), ("GITHUB_REPOSITORY", "other/repo"),
                           ("GITHUB_JOB", "benchmark"), ("GITHUB_WORKSPACE", "relative")):
            with self.subTest(key=key), patch.dict(os.environ, {key: value}), \
                    patch.object(D, "Darwin") as native, patch.object(D.subprocess, "run") as child:
                with self.assertRaises(RuntimeError):
                    D.run()
                native.assert_not_called()
                child.assert_not_called()
                self.assertFalse((self.root / "cpu-attribution").exists())
        with patch.object(D.platform, "system", return_value="Linux"):
            with self.assertRaises(RuntimeError):
                D.guard()

    def test_alias_or_public_namespace_rejected(self):
        self.root.chmod(0o755)
        with self.assertRaises(RuntimeError):
            D.guard()
        self.root.chmod(0o700)
        other = self.workspace / "other"
        self.root.rename(other)
        self.root.symlink_to(other, target_is_directory=True)
        with self.assertRaises(RuntimeError):
            D.guard()

    def binary(self):
        binary = self.root / "packing-evidence/main-storage-io"
        binary.parent.mkdir()
        binary.write_bytes(b"fixed mocked executable")
        (self.root / "baseline").mkdir()
        return binary, D.sha(binary)

    def test_optional_binary_requires_exact_location_and_hash(self):
        binary, expected = self.binary()
        self.assertEqual(D.guard(binary, expected), self.root)
        with self.assertRaises(RuntimeError):
            D.guard(binary, "a" * 64)
        with self.assertRaises(RuntimeError):
            D.guard(self.source, D.sha(self.source))

    def test_native250_observer_is_allowed_but_baseline_pulse_is_refused(self):
        binary, expected = self.binary()
        with patch.dict(os.environ, {"GITHUB_JOB": "matched-native250"}), \
                patch.object(D, "Darwin") as native, patch.object(D.subprocess, "run") as child:
            self.assertEqual(D.guard(), self.root)
            with self.assertRaisesRegex(RuntimeError, "baseline pulse requires matched-packing"):
                D.run(binary, expected)
            native.assert_not_called()
            child.assert_not_called()
            self.assertFalse((self.root / "cpu-attribution").exists())
        with patch.dict(os.environ, {"GITHUB_JOB": "matched-native250"}), \
                patch.object(D, "Darwin", return_value=SimpleNamespace(numer=125, denom=3, cores=3)), \
                patch.object(D, "interval", return_value={}) as window:
            output = D.run()
        self.assertTrue(json.loads((output / "receipt.json").read_text())["complete"])
        self.assertEqual(window.call_count, 3)

    def test_observer_only_is_three_windows_and_has_no_performance_verdict(self):
        with patch.object(D, "Darwin", return_value=SimpleNamespace(numer=125, denom=3, cores=3)), patch.object(D, "interval", return_value={"mocked": True}) as window:
            output = D.run()
        receipt = json.loads((output / "receipt.json").read_text())
        self.assertEqual(window.call_count, 3)
        self.assertTrue(receipt["complete"])
        self.assertIsNone(receipt["performance_verdict"])
        self.assertIsNone(receipt["causal_verdict"])

    def test_invocation_failure_preserves_raw_logs_exit_and_receipt(self):
        binary, expected = self.binary()
        with patch.object(D, "Darwin", return_value=SimpleNamespace(numer=125, denom=3, cores=3)), patch.object(D, "interval", return_value={"mocked": True}) as window, \
                patch.object(D.shutil, "disk_usage", return_value=SimpleNamespace(free=2 * 1024**3)), \
                patch.object(D.subprocess, "run", return_value=subprocess.CompletedProcess([], 9, b"raw out", b"raw err")) as child:
            with self.assertRaisesRegex(RuntimeError, "baseline invocation failed"):
                D.run(binary, expected)
        output = self.root / "cpu-attribution"
        receipt = json.loads((output / "receipt.json").read_text())
        self.assertFalse(receipt["complete"])
        self.assertEqual(receipt["invocation"]["exit"], 9)
        self.assertEqual(window.call_count, 6)
        self.assertEqual((output / "baseline.stdout").read_bytes(), b"raw out")
        self.assertEqual((output / "baseline.stderr").read_bytes(), b"raw err")
        self.assertEqual(child.call_args.kwargs["timeout"], 180)
        self.assertNotIn("shell", child.call_args.kwargs)
        self.assertEqual(child.call_args.args[0][1:5], ["--only", "evolving-kv", "--samples", "1"])

    def test_child_launch_exception_still_saves_receipt(self):
        binary, expected = self.binary()
        with patch.object(D, "Darwin", return_value=SimpleNamespace(numer=125, denom=3, cores=3)), patch.object(D, "interval", return_value={}), \
                patch.object(D.shutil, "disk_usage", return_value=SimpleNamespace(free=2 * 1024**3)), \
                patch.object(D.subprocess, "run", side_effect=OSError("launch failed")):
            with self.assertRaisesRegex(OSError, "launch failed"):
                D.run(binary, expected)
        receipt = json.loads((self.root / "cpu-attribution/receipt.json").read_text())
        self.assertFalse(receipt["complete"])
        self.assertIn("launch failed", receipt["failure"])

    def test_timeout_preserves_partial_output_and_tail_windows(self):
        binary, expected = self.binary()
        with patch.object(D, "Darwin", return_value=SimpleNamespace(numer=125, denom=3, cores=3)), patch.object(D, "interval", return_value={}), \
                patch.object(D.shutil, "disk_usage", return_value=SimpleNamespace(free=2 * 1024**3)), \
                patch.object(D.subprocess, "run", side_effect=subprocess.TimeoutExpired([], 180, output=b"partial")):
            with self.assertRaisesRegex(RuntimeError, "baseline invocation failed"):
                D.run(binary, expected)
        output = self.root / "cpu-attribution"
        receipt = json.loads((output / "receipt.json").read_text())
        self.assertTrue(receipt["invocation"]["timed_out"])
        self.assertEqual((output / "baseline.stdout").read_bytes(), b"partial")
        self.assertEqual(len(receipt["tail_windows"]), 3)

    def test_successful_baseline_starts_three_tail_windows_before_log_publication(self):
        binary, expected = self.binary()
        count = 0
        def window(api):
            nonlocal count
            count += 1
            if count > 3:
                self.assertFalse((self.root / "cpu-attribution/baseline.stdout").exists())
            return {"mocked": count}
        def child(argv, **kwargs):
            fixture = Path(argv[argv.index("--root") + 1])
            self.assertTrue(fixture.is_dir())
            self.assertEqual(fixture.stat().st_mode & 0o777, 0o700)
            Path(argv[-1]).write_bytes(b"raw report")
            return subprocess.CompletedProcess(argv, 0, b"stdout", b"stderr")
        with patch.object(D, "Darwin", return_value=SimpleNamespace(numer=125, denom=3, cores=3)), \
                patch.object(D, "interval", side_effect=window), \
                patch.object(D.shutil, "disk_usage", return_value=SimpleNamespace(free=2 * 1024**3)), \
                patch.object(D.subprocess, "run", side_effect=child):
            output = D.run(binary, expected)
        receipt = json.loads((output / "receipt.json").read_text())
        self.assertEqual(count, 6)
        self.assertTrue(receipt["complete"])
        self.assertEqual((output / "baseline.report.json").read_bytes(), b"raw report")

    def test_tail_api_failure_still_preserves_raw_child_logs_and_primary_error(self):
        binary, expected = self.binary()
        with patch.object(D, "Darwin", return_value=SimpleNamespace(numer=125, denom=3, cores=3)), \
                patch.object(D, "interval", side_effect=[{}, {}, {}, RuntimeError("tail API failed")]), \
                patch.object(D.shutil, "disk_usage", return_value=SimpleNamespace(free=2 * 1024**3)), \
                patch.object(D.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, b"out", b"err")):
            with self.assertRaisesRegex(RuntimeError, "tail API failed"):
                D.run(binary, expected)
        output = self.root / "cpu-attribution"
        receipt = json.loads((output / "receipt.json").read_text())
        self.assertIn("tail API failed", receipt["failure"])
        self.assertIn("baseline report missing", receipt["preservation_error"])
        self.assertEqual((output / "baseline.stdout").read_bytes(), b"out")
