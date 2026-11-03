"""Pure refusal/provenance tests: no Cargo, daemon or benchmark execution."""
import ast
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("evolving_mode", Path(__file__).with_name("evolving_kv.py"))
MODE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODE)
HEAD = "a" * 40
DIGEST = "b" * 64


def envelope(payload):
    text = json.dumps(payload, separators=(",", ":"))
    return {"format": MODE.FORMAT, "payload_json": text, "payload": payload,
            "payload_digest": {"algorithm": "sha-256", "scope": f"utf8:payload_json:{MODE.FORMAT}",
                               "hex": hashlib.sha256(text.encode()).hexdigest()}}


def fixture():
    argv = ["/binary", "--only", "evolving-kv", "--samples", "1", "--root", "/root", "--output", "/report"]
    build = {"head": HEAD, "binary": "/binary", "binary_sha256": DIGEST,
             "binary_bytes": 12, "overlay_porcelain": []}
    payload = {"package_version": "2026.10.1", "os": "macos", "architecture": "aarch64", "logical_cpus": 3,
               "provenance": {"repository": "astrid-runtime/astrid", "git_revision": HEAD,
                             "git_tree": {"state": "clean"}, "executable_argv": argv,
                             "executable": {"sha256": DIGEST, "bytes": 12}},
               "config": {"selection": "evolving_kv", "samples": 1, "object_cache_bytes": None,
                          "root": "/root", "output": "/report"}, "metrics": [],
               "write_amplifications": [], "substrate_comparisons": [], "throughput_scaling": [],
               "representation_metadata": [], "resource_peaks": []}
    for prefix, size in [("kv_512k", 524288), ("kv_8m", 8388608)]:
        for suffix in ["initial", "insert_cas", "read_warm", "close", "reopen", "reopen_read", "closed_sequence"]:
            byte_count = size if suffix == "initial" else size + 16384 if "read" in suffix else None
            payload["metrics"].append({"name": f"{prefix}_{suffix}", "bytes_per_sample": byte_count,
                                       "operations_per_sample": None if byte_count else 1,
                                       "samples_nanoseconds": [100] * (4 if suffix == "insert_cas" else 1),
                                       "minimum_milliseconds": 0.0001, "median_milliseconds": 0.0001,
                                       "maximum_milliseconds": 0.0001,
                                       "median_mib_per_second": byte_count / 1048576 / 1e-7 if byte_count else None,
                                       "median_operations_per_second": None if byte_count else 1e7})
        for suffix, count, denominator in [("closed_sequence", 1, size + 16384)]:
            payload["write_amplifications"].append({"name": f"{prefix}_{suffix}",
                                                  "authoritative_bytes_appended": [100] * count,
                                                  "logical_bytes_per_sample": denominator,
                                                  "minimum_authoritative_bytes_appended": 100,
                                                  "median_authoritative_bytes_appended": 100,
                                                  "maximum_authoritative_bytes_appended": 100,
                                                  "median_physical_to_logical_ratio": 100 / denominator})
    return payload, build, argv


class ReportTests(unittest.TestCase):
    def test_even_duration_midpoint_rounding_and_zero_rate_match_rust(self):
        for values, median in [([1, 2, 5, 8], 3), ([0, 0, 0, 0], 0)]:
            payload, build, argv = fixture()
            row = payload["metrics"][1]
            row.update(samples_nanoseconds=values, minimum_milliseconds=values[0] / 1e9 * 1000,
                       median_milliseconds=median / 1e9 * 1000, maximum_milliseconds=values[-1] / 1e9 * 1000,
                       median_operations_per_second=1 / (median / 1e9) if median else None)
            with self.subTest(values=values):
                MODE.validate_report(json.dumps(envelope(payload)), build, argv, [])

    def test_rehashed_summary_and_schema_tampering_fails(self):
        for category in ["minimum", "median", "maximum", "throughput", "operation-rate",
                         "growth-minimum", "growth-median", "growth-maximum", "growth-ratio",
                         "extra-payload", "missing-payload", "extra-metric", "missing-metric-summary",
                         "extra-growth", "missing-growth-summary", "boolean-growth-summary"]:
            payload, build, argv = fixture()
            if category in ("minimum", "median", "maximum"):
                payload["metrics"][0][f"{category}_milliseconds"] += 1
            if category == "throughput": payload["metrics"][0]["median_mib_per_second"] *= 2
            if category == "operation-rate": payload["metrics"][1]["median_operations_per_second"] *= 2
            if category in ("growth-minimum", "growth-median", "growth-maximum"):
                payload["write_amplifications"][0][f"{category[7:]}_authoritative_bytes_appended"] += 1
            if category == "growth-ratio": payload["write_amplifications"][0]["median_physical_to_logical_ratio"] *= 2
            if category == "extra-payload": payload["unreviewed"] = []
            if category == "missing-payload": del payload["architecture"]
            if category == "extra-metric": payload["metrics"][0]["unreviewed"] = 1
            if category == "missing-metric-summary": del payload["metrics"][0]["maximum_milliseconds"]
            if category == "extra-growth": payload["write_amplifications"][0]["unreviewed"] = 1
            if category == "missing-growth-summary": del payload["write_amplifications"][0]["maximum_authoritative_bytes_appended"]
            if category == "boolean-growth-summary": payload["write_amplifications"][0]["minimum_authoritative_bytes_appended"] = True
            with self.subTest(category=category), self.assertRaises(RuntimeError):
                MODE.validate_report(json.dumps(envelope(payload)), build, argv, [])

    def test_valid_report_and_full_payload_are_retained(self):
        payload, build, argv = fixture()
        report = envelope(payload)
        self.assertEqual(MODE.validate_report(json.dumps(report), build, argv, []), report)

    def test_malformed_missing_duplicate_and_nonfinite_json_fail(self):
        payload, build, argv = fixture()
        for raw in ["", "{}", "[]", '{"x":1,"x":2}', '{"x":NaN}', '{"x":1e309}', '{"format":null}']:
            with self.subTest(raw=raw), self.assertRaises((RuntimeError, ValueError, TypeError, AttributeError)):
                MODE.validate_report(raw, build, argv, [])

    def test_digest_and_payload_must_match(self):
        payload, build, argv = fixture()
        wrong_digest = envelope(payload)
        wrong_digest["payload_digest"]["hex"] = "0" * 64
        wrong_body = envelope(payload)
        wrong_body["payload"]["config"]["samples"] = 99
        for value in [wrong_digest, wrong_body]:
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                MODE.validate_report(json.dumps(value), build, argv, [])

    def test_superseded_per_call_growth_report_fails_closed(self):
        payload, build, argv = fixture()
        payload["metrics"] = [row for row in payload["metrics"] if not row["name"].endswith("_closed_sequence")]
        for row in payload["metrics"]:
            row["name"] = row["name"].replace("_read_warm", "_read")
        payload["write_amplifications"] = []
        for prefix, size in [("kv_512k", 524288), ("kv_8m", 8388608)]:
            for suffix, count, denominator in [("initial", 1, size), ("insert_cas", 4, 4096)]:
                payload["write_amplifications"].append({"name": f"{prefix}_{suffix}",
                    "authoritative_bytes_appended": [100] * count, "logical_bytes_per_sample": denominator})
        with self.assertRaisesRegex(RuntimeError, "metric rows"):
            MODE.validate_report(json.dumps(envelope(payload)), build, argv, [])

    def test_producer_binary_argv_tree_and_config_mismatch_fail(self):
        for category in ["head", "binary", "argv", "tree", "mode", "samples", "cache", "root", "output"]:
            payload, build, argv = fixture()
            if category == "head": payload["provenance"]["git_revision"] = "c" * 40
            if category == "binary": payload["provenance"]["executable"]["sha256"] = "c" * 64
            if category == "argv": payload["provenance"]["executable_argv"] = ["other"]
            if category == "tree": payload["provenance"]["git_tree"] = {"state": "dirty", "porcelain_v1": ["unknown"]}
            if category == "mode": payload["config"]["selection"] = "existing"
            if category == "samples": payload["config"]["samples"] = True
            if category == "cache": payload["config"]["object_cache_bytes"] = 100
            if category in ("root", "output"): payload["config"][category] = "/different"
            with self.subTest(category=category), self.assertRaises(RuntimeError):
                MODE.validate_report(json.dumps(envelope(payload)), build, argv, [])

    def test_missing_duplicate_metric_growth_or_wrong_cardinality_fail(self):
        for category in ["missing-metric", "duplicate-metric", "cas-cardinality", "read-bytes",
                         "negative-duration", "missing-growth", "duplicate-growth", "growth-cardinality",
                         "growth-denominator", "unrelated", "boolean-operation", "float-bytes"]:
            payload, build, argv = fixture()
            if category == "missing-metric": payload["metrics"].pop()
            if category == "duplicate-metric": payload["metrics"][0] = copy.deepcopy(payload["metrics"][1])
            if category == "cas-cardinality": payload["metrics"][1]["samples_nanoseconds"] = [1]
            if category == "read-bytes": payload["metrics"][2]["bytes_per_sample"] -= 1
            if category == "negative-duration": payload["metrics"][0]["samples_nanoseconds"] = [-1]
            if category == "missing-growth": payload["write_amplifications"].pop()
            if category == "duplicate-growth": payload["write_amplifications"][0] = copy.deepcopy(payload["write_amplifications"][1])
            if category == "growth-cardinality": payload["write_amplifications"][1]["authoritative_bytes_appended"] = [1, 2]
            if category == "growth-denominator": payload["write_amplifications"][1]["logical_bytes_per_sample"] = 4096
            if category == "unrelated": payload["resource_peaks"] = [123]
            if category == "boolean-operation": payload["metrics"][1]["operations_per_sample"] = True
            if category == "float-bytes": payload["metrics"][0]["bytes_per_sample"] = 524288.0
            with self.subTest(category=category), self.assertRaises(RuntimeError):
                MODE.validate_report(json.dumps(envelope(payload)), build, argv, [])


class OverlayTests(unittest.TestCase):
    def test_only_approved_module_closure_and_exact_regular_files(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as raw:
            root = Path(raw).resolve()
            for relative in MODE.SOURCES:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("source")
            sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
            manifest = MODE.source_manifest(root, {"sha": sha})
            self.assertEqual(set(manifest), set(MODE.SOURCES))
            extra = root / MODE.BENCH_ROOT / "storage_io/extra.rs"
            extra.write_text("unreviewed import")
            with self.assertRaises(RuntimeError): MODE.source_manifest(root, {"sha": sha})
            extra.unlink()
            path = root / MODE.SOURCES[-1]
            path.unlink()
            path.symlink_to(root / MODE.SOURCES[0])
            with self.assertRaises(RuntimeError): MODE.source_manifest(root, {"sha": sha})

    def test_allowed_overlay_is_not_unrestricted_dirty_tree_permission(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as raw:
            root = Path(raw).resolve()
            target = root / "allowed.rs"
            target.write_text("approved")
            manifest = {"allowed.rs": DIGEST}
            good = [HEAD, "allowed.rs", "", "", "M allowed.rs"]
            hooks = {"command": Mock(side_effect=good), "sha": lambda _: DIGEST}
            self.assertEqual(MODE.verify_overlay(root, HEAD, manifest, hooks), ["M allowed.rs"])
            for answers in [["c" * 40], [HEAD, "Cargo.toml", ""], [HEAD, "", "rogue.rs"],
                            [HEAD, "allowed.rs", "", "allowed.rs"]]:
                with self.subTest(answers=answers), self.assertRaises(RuntimeError):
                    MODE.verify_overlay(root, HEAD, manifest,
                                        {"command": unittest.mock.Mock(side_effect=answers), "sha": lambda _: DIGEST})
            with self.assertRaises(RuntimeError):
                MODE.verify_overlay(root, HEAD, manifest,
                                    {"command": unittest.mock.Mock(side_effect=good), "sha": lambda _: "c" * 64})


class BuildTests(unittest.TestCase):
    def test_locked_bench_compilation_freezes_selected_producer_executable(self):
        for case in ["valid", "wrong-source", "not-bench", "missing-executable"]:
            with self.subTest(case=case), tempfile.TemporaryDirectory(dir=Path(__file__).parent) as raw:
                root = Path(raw).resolve()
                producer, output = root / "producer", root / "output"
                producer.mkdir()
                output.mkdir()
                executable = root / "cargo-storage-io"
                executable.write_bytes(b"first producer binary")
                (producer / "Cargo.lock").write_text("authentic producer lock")
                event = {"reason": "compiler-artifact", "filenames": [str(executable)],
                         "package_id": "authentic-storage", "features": [], "profile": {"opt_level": "3"},
                         "target": {"name": "storage_io", "kind": ["bench"],
                                    "src_path": str(producer / MODE.BENCH_ROOT / "storage_io.rs")},
                         "executable": str(executable)}
                if case == "wrong-source": event["target"]["src_path"] = str(root / "wrong.rs")
                if case == "not-bench": event["target"]["kind"] = ["example"]
                if case == "missing-executable": event["executable"] = None
                def start(command, **kwargs):
                    kwargs["stdout"].write(json.dumps(event) + "\n")
                    return Mock(wait=Mock(return_value=0))
                sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
                preparation = {"workspace_packages": []}
                source_build = SimpleNamespace(prepare=Mock(return_value=preparation), verify_artifact=Mock())
                hooks = {"sha": sha, "command": Mock(side_effect=["tree", "rustc-1.95"]),
                         "source_build": source_build}
                with patch.object(MODE, "prepare_overlay", return_value=[]), \
                        patch.object(MODE, "verify_overlay", return_value=[]), \
                        patch.object(MODE.subprocess, "Popen", side_effect=start) as launch, \
                        patch.object(MODE.shutil, "disk_usage", return_value=SimpleNamespace(free=10 * 1024**3)):
                    if case != "valid":
                        with self.assertRaises(RuntimeError):
                            MODE.build(producer, HEAD, root, {}, output, "main", MODE.time.monotonic() + 10000, hooks)
                        continue
                    receipt = MODE.build(producer, HEAD, root, {}, output, "main", MODE.time.monotonic() + 10000, hooks)
                self.assertIs(receipt["source_build"], preparation)
                self.assertEqual(source_build.prepare.call_args.args[:3],
                                 (producer, output / "cargo-target", output / "main-build.jsonl"))
                source_build.verify_artifact.assert_called_once_with(event, producer, preparation)
                command = launch.call_args.args[0]
                self.assertEqual(command[:4], ["cargo", "bench", "--no-run", "--locked"])
                self.assertEqual(command[command.index("--bench") + 1], "storage_io")
                self.assertEqual(launch.call_args.kwargs["cwd"], producer)
                self.assertEqual(launch.call_args.kwargs["env"]["CARGO_TARGET_DIR"], str(output / "cargo-target"))
                self.assertEqual(receipt["artifacts"][0]["sha256"], sha(executable))
                executable.write_bytes(b"overwritten by other arm")
                self.assertEqual(Path(receipt["binary"]).read_bytes(), b"first producer binary")
                self.assertEqual(receipt["binary_sha256"], sha(Path(receipt["binary"])))


class SampleTests(unittest.TestCase):
    def test_failed_sample_preserves_exit_logs_and_fixture(self):
        for result in [subprocess.CompletedProcess([], 1, b"partial", b"exact failure"),
                       subprocess.TimeoutExpired([], 180, output=b"partial", stderr=b"timeout")]:
            with self.subTest(result=result), tempfile.TemporaryDirectory(dir=Path(__file__).parent) as raw:
                root = Path(raw).resolve()
                fixture_root = root / "fixture"
                fixture_root.mkdir()
                _, build, _ = fixture()
                build["binary"] = str(root / "binary")
                sample = {"complete": False}
                hooks = {"sha": lambda _: DIGEST, "quiet_snapshot": lambda: {"quiet": True}}
                with patch.object(MODE, "verify_overlay", return_value=[]), \
                        patch.object(MODE.subprocess, "run", side_effect=result if isinstance(result, Exception) else None,
                                     return_value=result), self.assertRaises(RuntimeError):
                    MODE.run_sample(build, root, fixture_root, root, 0, sample, {}, hooks)
                self.assertFalse(sample["complete"])
                self.assertTrue(sample["fixture_preserved"])
                self.assertTrue(sample["child_reaped"])
                self.assertIn("failure", sample)
                self.assertEqual((root / "sample-00.stdout").read_bytes(), b"partial")
                self.assertTrue((root / "sample-00.stderr").is_file())

    def test_success_retains_full_content_bound_report_before_reaping_fixture(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as raw:
            root = Path(raw).resolve()
            fixture_root = root / "fixture"
            fixture_root.mkdir()
            payload, build, _ = fixture()
            sample = {}
            def execute(argv, **kwargs):
                payload["provenance"]["executable_argv"] = argv
                payload["config"]["root"] = str(fixture_root)
                payload["config"]["output"] = argv[argv.index("--output") + 1]
                Path(payload["config"]["output"]).write_text(json.dumps(envelope(payload)))
                return subprocess.CompletedProcess(argv, 0, b"complete public report", b"")
            with patch.object(MODE, "verify_overlay", return_value=[]), \
                    patch.object(MODE.subprocess, "run", side_effect=execute):
                MODE.run_sample(build, root, fixture_root, root, 0, sample, {},
                                {"sha": lambda _: DIGEST, "quiet_snapshot": lambda: {"quiet": True}})
            self.assertTrue(sample["complete"])
            self.assertTrue(sample["fixture_reaped"])
            self.assertFalse(sample["fixture_preserved"])
            self.assertEqual(len(sample["storage_io_evidence"]["payload"]["metrics"]), 14)
            self.assertEqual(len(sample["storage_io_evidence"]["payload"]["write_amplifications"]), 2)
            self.assertEqual(sample["storage_io_evidence"]["payload"], payload)

    def test_successful_exit_without_report_is_failure_not_empty_sample(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as raw:
            root = Path(raw).resolve()
            fixture_root = root / "fixture"
            fixture_root.mkdir()
            _, build, _ = fixture()
            sample = {}
            with patch.object(MODE, "verify_overlay", return_value=[]), \
                    patch.object(MODE.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, b"", b"")), \
                    self.assertRaisesRegex(RuntimeError, "report missing"):
                MODE.run_sample(build, root, fixture_root, root, 0, sample, {},
                                {"sha": lambda _: DIGEST, "quiet_snapshot": lambda: {"quiet": True}})
            self.assertTrue(sample["fixture_preserved"])
            self.assertFalse(sample["complete"])

    def test_build_timeout_kills_only_owned_unreaped_group_and_waits(self):
        process = unittest.mock.Mock(pid=123)
        process.wait.side_effect = [subprocess.TimeoutExpired([], 900), -9]
        with patch.object(MODE.os, "killpg") as kill, self.assertRaises(subprocess.TimeoutExpired):
            MODE.wait_build(process, 900)
        kill.assert_called_once_with(123, MODE.signal.SIGKILL)
        self.assertEqual(process.wait.call_count, 2)

    def test_default_packing_mode_and_controls_remain_selected(self):
        path = Path(__file__).with_name("matched_volume_packing.py")
        source = path.read_text()
        tree = ast.parse(source)
        main = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "main")
        mode = next(n for n in ast.walk(main) if isinstance(n, ast.Call) and n.args and
                    isinstance(n.args[0], ast.Constant) and n.args[0].value == "--mode")
        self.assertEqual(next(k.value.value for k in mode.keywords if k.arg == "default"), "packing")
        self.assertIn('if args.mode in ("evolving-kv", "route-selection"):', source)
        self.assertIn('abba_schedule([(32768, 7), (600000, 1)], builds)', source)
        self.assertIn('("main", 699051, 1, "negative-control")', source)


def shared_schedule():
    source = Path(__file__).with_name("matched_volume_packing.py").read_text()
    node = next(n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name == "abba_schedule")
    namespace = {}
    exec(compile(ast.Module(body=[node], type_ignores=[]), "actual-abba-helper", "exec"), namespace)
    return namespace["abba_schedule"]


class PublicationTests(unittest.TestCase):
    def test_evolving_publication_extends_allowlist_without_homes_or_targets(self):
        source = Path(__file__).with_name("matched_volume_packing.py").read_text()
        node = next(n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name == "finalize_evidence")
        publish = Mock()
        namespace = {"evolving_kv": MODE, "evidence": SimpleNamespace(finalize=publish),
                     "emit_terminal_receipt": Mock()}
        exec(compile(ast.Module(body=[node], type_ignores=[]), "actual-finalizer", "exec"), namespace)
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as raw:
            root = Path(raw).resolve()
            (root / "sample-00.stdout").write_text("stdout")
            (root / "sample-00.stderr").write_text("stderr")
            (root / "sample-00.report.json").write_text("malformed failure report retained")
            (root / "private-home").mkdir()
            (root / "private-home/key").write_text("synthetic private key")
            (root / "cargo-target").mkdir()
            (root / "cargo-target/lib.rlib").write_text("not evidence")
            namespace["finalize_evidence"](root, {"mode": "evolving-kv"}, Mock())
            selected = publish.call_args.kwargs["log_paths"]
            self.assertIn(root / "sample-00.report.json", selected)
            self.assertIn(root / "sample-00.stdout", selected)
            self.assertTrue(set(MODE.public_source_paths(root)) <= set(selected))
            self.assertFalse(any("private-home" in str(p) or "cargo-target" in str(p) for p in selected))


class ScheduleTests(unittest.TestCase):
    def test_existing_packing_configurations_keep_their_warmups_and_order(self):
        actual = shared_schedule()([(32768, 7), (600000, 1)], ["main", "candidate"])
        expected = []
        for count, regions in [(32768, 7), (600000, 1)]:
            expected.extend((arm, count, regions, "warmup") for arm in ["main", "candidate"])
            expected.extend((arm, count, regions, "timed") for arm in ["main", "candidate", "candidate", "main"] * 4)
        self.assertEqual(actual, expected)
        self.assertEqual(len(actual), 36)

    def run_protocol(self, root, fail=False, quiet=None, settle=None):
        protocol, output = root / "protocol", root / "output"
        protocol.mkdir()
        output.mkdir()
        manifest = {}
        for relative in MODE.SOURCES:
            source = protocol / relative
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text("approved")
            manifest[relative] = hashlib.sha256(source.read_bytes()).hexdigest()
        args = SimpleNamespace(baseline=root / "baseline", candidate=root / "candidate",
                               baseline_head=HEAD, candidate_head="c" * 40)
        receipt = {"samples": [], "performance_accepted": False}
        save = Mock()
        def frozen_build(path, head, _protocol, _manifest, _output, arm, _deadline, _hooks):
            return {"head": head, "binary": str(output / arm), "binary_sha256": DIGEST,
                    "overlay_porcelain": [], "rustc": "identical-pinned-toolchain"}
        def sample(_build, _path, _fixture, _output, _index, item, _manifest, _hooks):
            item["synthetic_test_only"] = True
            if fail:
                item["failure"] = "retained synthetic failure"
                raise RuntimeError("retained synthetic failure")
            item["complete"] = True
        sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else DIGEST
        hooks = {"sha": sha, "quiet_snapshot": quiet or (lambda: {"quiet": True}),
                 "settle_after_builds": Mock(),
                 "settle_before_sample": settle or (lambda *args: {"quiet": True}),
                 "abba_schedule": shared_schedule()}
        with patch.object(MODE, "build", side_effect=frozen_build), \
                patch.object(MODE, "verify_overlay", return_value=[]), \
                patch.object(MODE, "run_sample", side_effect=sample), \
                patch.object(MODE.shutil, "disk_usage", return_value=SimpleNamespace(free=10 * 1024**3)):
            if fail:
                with self.assertRaisesRegex(RuntimeError, "retained synthetic failure"):
                    MODE.run(args, protocol, output, receipt, save, MODE.time.monotonic() + 10000, hooks)
            else:
                MODE.run(args, protocol, output, receipt, save, MODE.time.monotonic() + 10000, hooks)
        return receipt, save

    def test_transient_admission_burst_waits_without_retrying_or_skipping_abba_samples(self):
        spec = importlib.util.spec_from_file_location(
            "evolving_admission_protocol", Path(__file__).with_name("matched_volume_packing.py"))
        packing = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(packing)
        windows = [{"quiet": value} for value in [False, True, True] + [True] * 34]
        quiet = Mock(side_effect=windows)
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as raw, \
                patch.object(packing, "quiet_snapshot", quiet):
            receipt, _ = self.run_protocol(Path(raw).resolve(), quiet=quiet,
                                           settle=packing.settle_before_sample)
        self.assertEqual(len(receipt["samples"]), 18)
        self.assertEqual(len(receipt["presample_settling"]), 18)
        self.assertEqual(receipt["presample_settling"][0]["windows"], windows[:3])
        self.assertEqual(quiet.call_count, 37)
        self.assertEqual([(s["arm"], s["phase"]) for s in receipt["samples"]], receipt["schedule"])

    def test_two_warmups_and_sixteen_timed_abba_without_speed_verdict(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as raw:
            receipt, save = self.run_protocol(Path(raw).resolve())
        expected = [("main", "warmup"), ("candidate", "warmup")]
        expected += [(arm, "timed") for arm in ["main", "candidate", "candidate", "main"] * 4]
        self.assertEqual(receipt["schedule"], expected)
        self.assertEqual(len(receipt["samples"]), 18)
        self.assertTrue(all(s["complete"] for s in receipt["samples"]))
        self.assertFalse(receipt["performance_accepted"])
        self.assertEqual(receipt["workload_definition"]["growth_logical_denominators"], [540672, 8404992])
        self.assertIn("unused_legacy_config_fields", receipt["workload_definition"])
        self.assertGreater(save.call_count, 18)

    def test_failed_sample_is_registered_before_execution_and_not_retried(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as raw:
            receipt, save = self.run_protocol(Path(raw).resolve(), fail=True)
        self.assertEqual(len(receipt["samples"]), 1)
        self.assertEqual(receipt["samples"][0]["failure"], "retained synthetic failure")
        self.assertFalse(receipt["samples"][0]["complete"])
        self.assertFalse(receipt["performance_accepted"])
        self.assertGreater(save.call_count, 1)


if __name__ == "__main__":
    unittest.main()
