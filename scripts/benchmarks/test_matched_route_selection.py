"""Synthetic matched route protocol checks; no Rust build or benchmark execution."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location("route_packing", Path(__file__).with_name("matched_volume_packing.py"))
PACK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PACK)
MODE, SHARED = PACK.route_selection, PACK.evolving_kv
HEAD = "a" * 40


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def report(build, foreign=0, arm="main"):
    return (f"route_selection_bench label={arm} foreign={foreign} iters=2000 warmups=2 "
            f"total_ns=200001 per_publish_ns=100 exe={build['binary']}\n").encode()


class RouteTests(unittest.TestCase):
    def test_parser_exact_schema_identity_and_duration(self):
        build = {"binary": "/frozen/main-route", "head": HEAD, "binary_sha256": "b" * 64}
        for foreign in (0, 10000):
            sample = {"arm": "main", "foreign": foreign}
            raw = report(build, foreign)
            self.assertEqual(MODE.validate_report(raw, build, sample)["foreign"], foreign)
            for invalid in (b"", raw + raw, raw.replace(b"iters=2000", b"iters=1"),
                            raw.replace(b"warmups=2", b"warmups=0"), raw.replace(b"main-route", b"other"),
                            raw.replace(b"label=main", b"label=candidate"),
                            raw.replace(b"total_ns=200001", b"total_ns=0"),
                            raw.replace(b"per_publish_ns=100", b"per_publish_ns=99"),
                            raw.replace(f"foreign={foreign}".encode(), b"foreign=2")):
                with self.subTest(raw=invalid), self.assertRaises(RuntimeError):
                    MODE.validate_report(invalid, build, sample)

    def test_overlay_is_identical_allowlisted_source_and_rejects_drift(self):
        protocol = Path(__file__).resolve().parents[2]
        manifest = MODE.source_manifest(protocol, {"sha": sha})
        self.assertEqual(manifest, {MODE.SOURCE: MODE.HARNESS_SHA})
        with tempfile.TemporaryDirectory() as raw:
            target = Path(raw).resolve()
            hooks = {"clean_checkout": Mock(), "sha": sha,
                     "command": Mock(side_effect=[HEAD, "", MODE.SOURCE, "", "?? " + MODE.SOURCE])}
            SHARED.prepare_overlay(target, HEAD, protocol, manifest, hooks)
            self.assertEqual((target / MODE.SOURCE).read_bytes(), (protocol / MODE.SOURCE).read_bytes())
            hooks["clean_checkout"].assert_called_once_with(target, HEAD)
            with self.assertRaises(RuntimeError):
                MODE.source_manifest(protocol, {"sha": lambda _: "c" * 64})
            for changed, untracked in (("Cargo.toml", ""), ("", "rogue.rs")):
                hooks["command"] = Mock(side_effect=[HEAD, changed, untracked])
                with self.assertRaises(RuntimeError): SHARED.verify_overlay(target, HEAD, manifest, hooks)

    def test_release_example_uses_authentic_artifact_guard_and_freezes_binary(self):
        for invalid in (None, "wrong-source", "freshness"):
            with self.subTest(invalid=invalid), tempfile.TemporaryDirectory() as raw:
                root = Path(raw).resolve()
                producer, output = root / "producer", root / "output"
                producer.mkdir(); output.mkdir()
                (producer / "Cargo.lock").write_text("producer lock")
                executable = root / "target-example"; executable.write_bytes(b"compiled producer")
                event = {"reason": "compiler-artifact", "package_id": "authentic-events", "fresh": False,
                         "filenames": [str(executable)], "features": [], "profile": {"opt_level": "3"},
                         "target": {"name": "route_selection_bench", "kind": ["example"],
                                    "src_path": str(producer / MODE.SOURCE)}, "executable": str(executable)}
                if invalid == "wrong-source": event["target"]["src_path"] = str(root / "wrong.rs")
                guard = SimpleNamespace(prepare=Mock(return_value={}), verify_artifact=Mock())
                if invalid == "freshness": guard.verify_artifact.side_effect = RuntimeError("stale product")
                def launch(command, **kwargs):
                    kwargs["stdout"].write(json.dumps(event) + "\n")
                    return Mock(wait=Mock(return_value=0))
                hooks = {"sha": sha, "command": Mock(side_effect=["tree", "rustc"]), "source_build": guard}
                with patch.object(SHARED, "prepare_overlay", return_value=[]), \
                        patch.object(SHARED, "verify_overlay", return_value=[]), \
                        patch.object(SHARED.subprocess, "Popen", side_effect=launch) as start:
                    if invalid:
                        with self.assertRaises(RuntimeError):
                            SHARED.build(producer, HEAD, root, {}, output, "main", SHARED.time.monotonic()+900, hooks, MODE.TARGET)
                        continue
                    built = SHARED.build(producer, HEAD, root, {}, output, "main", SHARED.time.monotonic()+900, hooks, MODE.TARGET)
                command = start.call_args.args[0]
                self.assertEqual(command[:7], ["cargo", "build", "--release", "--example", "route_selection_bench", "-p", "astrid-events"])
                self.assertIn("--locked", command)
                guard.prepare.assert_called_once(); guard.verify_artifact.assert_called_once_with(event, producer, {})
                executable.write_bytes(b"next producer")
                self.assertEqual(Path(built["binary"]).read_bytes(), b"compiled producer")

    def test_sample_success_and_failures_keep_logs_and_noisy_sample(self):
        for failure in (None, "exit", "timeout", "noise", "malformed"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as raw:
                root = Path(raw).resolve(); fixture = root / "fixture"; fixture.mkdir()
                binary = root / "frozen"; binary.write_bytes(b"compiled")
                built = {"binary": str(binary), "binary_sha256": sha(binary), "head": HEAD, "overlay_porcelain": []}
                sample = {"arm": "main", "foreign": 10000}
                stdout = report(built, 10000) if failure != "malformed" else b"bad report"
                process = Mock(returncode=1 if failure == "exit" else 0)
                communicate = Mock(return_value=(stdout, b"diagnostic"))
                if failure == "timeout": communicate.side_effect = subprocess.TimeoutExpired([], 180, output=stdout, stderr=b"timeout")
                hooks = {"sha": sha, "overlay": SHARED, "source_build": SimpleNamespace(communicate_owned=communicate),
                         "quiet_snapshot": lambda: {"quiet": failure != "noise"}}
                with patch.object(SHARED, "verify_overlay", return_value=[]), \
                        patch.object(MODE.subprocess, "Popen", return_value=process) as launch:
                    if failure:
                        with self.assertRaises(RuntimeError): MODE.run_sample(built, root, fixture, root, 0, sample, {}, hooks)
                    else: MODE.run_sample(built, root, fixture, root, 0, sample, {}, hooks)
                self.assertEqual(launch.call_args.kwargs["start_new_session"], True)
                communicate.assert_called_once_with(process, 180)
                self.assertEqual((root / "sample-00.stdout").read_bytes(), stdout)
                self.assertTrue((root / "sample-00.stderr").is_file())
                self.assertEqual(sample["complete"], failure is None)
                self.assertEqual(sample["fixture_preserved"], failure is not None)
                if failure == "noise": self.assertIn("route_selection", sample)

    def test_timeout_kills_only_new_owned_group_and_drains_complete_logs(self):
        process = Mock(pid=99999999)
        process.communicate.side_effect = [subprocess.TimeoutExpired([], 180), (b"complete out", b"complete err")]
        with patch.object(PACK.source_build.os, "killpg") as kill, self.assertRaises(subprocess.TimeoutExpired) as raised:
            PACK.source_build.communicate_owned(process, 180)
        kill.assert_called_once_with(process.pid, PACK.source_build.signal.SIGKILL)
        self.assertEqual(raised.exception.output, b"complete out")
        self.assertEqual(raised.exception.stderr, b"complete err")
        self.assertEqual(process.communicate.call_count, 2)

    def test_existing_schedule_and_quiet_gates_for_n1_and_10k(self):
        protocol = Path(__file__).resolve().parents[2]
        for noisy in (False, True):
            with self.subTest(noisy=noisy), tempfile.TemporaryDirectory() as raw:
                root = Path(raw).resolve(); binary = root / "frozen"; binary.write_bytes(b"compiled")
                args = SimpleNamespace(baseline=root, candidate=root, baseline_head=HEAD, candidate_head="b"*40)
                receipt = {"samples": []}; before = Mock(return_value={"quiet": not noisy}); save = Mock()
                hooks = {"sha": sha, "command": Mock(), "clean_checkout": Mock(),
                         "abba_schedule": PACK.abba_schedule, "settle_after_builds": Mock(), "settle_before_sample": before}
                build = {"rustc": "same", "binary": str(binary), "binary_sha256": sha(binary), "head": HEAD, "overlay_porcelain": []}
                with patch.object(SHARED, "build", return_value=build) as compile_, \
                        patch.object(SHARED, "verify_overlay", return_value=[]), patch.object(MODE, "run_sample") as sample:
                    if noisy:
                        with self.assertRaisesRegex(RuntimeError, "before sample: HOLD"):
                            SHARED.run(args, protocol, root, receipt, save, SHARED.time.monotonic()+2000, hooks, MODE)
                        self.assertEqual(sample.call_count, 0)
                    else:
                        SHARED.run(args, protocol, root, receipt, save, SHARED.time.monotonic()+2000, hooks, MODE)
                        self.assertEqual(sample.call_count, 68)
                        self.assertEqual(before.call_count, 68)
                self.assertEqual(compile_.call_count, 2)
                self.assertEqual(compile_.call_args.kwargs["target"], MODE.TARGET)
                for foreign in (0, 10000):
                    rows = [r for r in receipt["schedule"] if r[1] == foreign]
                    self.assertEqual([r[0] for r in rows[:2]], ["main", "candidate"])
                    self.assertEqual([r[0] for r in rows[2:]], ["main", "candidate", "candidate", "main"]*8)
                    self.assertEqual([r[-1] for r in rows], ["warmup"]*2+["timed"]*32)
                    for arm in ("main", "candidate"):
                        self.assertEqual(sum(r[0] == arm and r[-1] == "timed" for r in rows), 16)
                self.assertEqual(receipt["workload_definition"]["in_process_warmup_publishes_per_invocation"], 2)
                self.assertEqual(receipt["workload_definition"]["warmup_invocations_per_arm_per_case"], 1)

    def test_publication_allowlist_preserves_failed_receipt_and_excludes_private_data(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); receipt = {"mode": "route-selection", "complete": False, "failure": "HOLD"}
            def save(): (root / "receipt.json").write_text(json.dumps(receipt))
            source = root / "protocol-source" / MODE.SOURCE; source.parent.mkdir(parents=True); source.write_text("frozen harness")
            (root / "sample-00.stderr").write_text("failure diagnostic")
            (root / "sample-00.stdout").write_text("route assertion partial report")
            for private in ("home", "cargo-target", "volume"):
                directory = root / private; directory.mkdir(); (directory / "secret").write_text("private")
            PACK.finalize_evidence(root, receipt, save, primary_error=RuntimeError("HOLD"))
            public = root / "public"
            self.assertEqual(json.loads((public / "receipt.json").read_text())["failure"], "HOLD")
            self.assertTrue((public / "protocol-source" / MODE.SOURCE).is_file())
            self.assertTrue((public / "sample-00.stderr").is_file())
            self.assertEqual((public / "sample-00.stdout").read_text(), "route assertion partial report")
            self.assertFalse(any((public / name).exists() for name in ("home", "volume", "cargo-target")))

    def test_existing_entrypoint_and_workflow_select_route_without_new_architecture(self):
        runner = Path(PACK.__file__)
        result = subprocess.run(["python3", "-B", str(runner), "--help"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0); self.assertIn("route-selection", result.stdout)
        workflow = (runner.parents[2] / ".github/workflows/storage-benchmark.yml").read_text()
        self.assertIn("options: [packing, evolving-kv, route-selection]", workflow)
        self.assertEqual(workflow.count("astrid-benchmark.noindex/protocol/scripts/benchmarks/matched_volume_packing.py"), 1)
