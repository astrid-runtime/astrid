"""Causal synthetic checks for portable native250; no cargo, daemon, or live volume."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch


SPEC = importlib.util.spec_from_file_location(
    "matched_native250", Path(__file__).with_name("matched_native250.py"))
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
HEAD = "a" * 40
CAND = "b" * 40


def _artifact(name: str, path: Path, *, opt_level: str = "3", test: bool = False,
              package_id: str | None = None, extra_filenames: list[str] | None = None):
    filenames = [str(path)]
    if extra_filenames:
        filenames.extend(extra_filenames)
    return {
        "target": name,
        "package_id": package_id or f"pkg/{name}@0.0.0",
        "profile": {"opt_level": opt_level, "test": test},
        "filenames": filenames,
    }


class Native250SyntheticTests(unittest.TestCase):
    def test_first_build_can_check_disk_before_target_exists(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            checkout = root / "checkout"
            checkout.mkdir()
            (checkout / "Cargo.lock").write_text("fixture")
            target = root / "cargo-target" / "main"
            process = MagicMock()
            process.wait.return_value = 0
            with patch.object(MODULE.packing, "clean_checkout"), \
                    patch.object(MODULE.packing, "command", return_value=HEAD), \
                    patch.object(MODULE.subprocess, "Popen", return_value=process):
                result = MODULE.cargo_build(checkout, HEAD, ["fixture"], target,
                                            root / "build.log", float("inf"))
            self.assertEqual(result["target_dir"], str(target))
            self.assertTrue(target.is_dir())

    def test_wait4_does_not_poll_and_reap_the_child_first(self):
        process = MagicMock(pid=123456)
        process.poll.side_effect = AssertionError("Popen.poll can steal wait4 rusage")
        usage = MagicMock(ru_utime=1, ru_stime=2, ru_maxrss=3)
        with patch.object(MODULE.os, "wait4", return_value=(123456, 0, usage)):
            result = MODULE.wait_owned(process, 8, {"pid": 123456})
        self.assertEqual(process.returncode, 0)
        self.assertEqual(result["max_rss_bytes"], 3)

    def test_shared_target_cannot_replace_the_frozen_baseline_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            checkout = root / "checkout"
            checkout.mkdir()
            (checkout / "Cargo.lock").write_text("fixture")
            target = root / "cargo-target"
            executable = root / "producer-astrid"
            process = MagicMock()
            process.wait.return_value = 0

            def produce(*_args, **kwargs):
                executable.write_bytes(b"baseline executable")
                event = {"reason": "compiler-artifact", "target": {"name": "astrid"},
                         "executable": str(executable), "filenames": [str(executable)]}
                kwargs["stdout"].write(json.dumps(event) + "\n")
                kwargs["stdout"].flush()
                return process

            with patch.object(MODULE.packing, "clean_checkout"), \
                    patch.object(MODULE.packing, "command", return_value=HEAD), \
                    patch.object(MODULE.subprocess, "Popen", side_effect=produce):
                result = MODULE.cargo_build(checkout, HEAD, ["fixture"], target,
                                            root / "main-build.log", float("inf"))
            frozen = Path(result["binaries"]["astrid"]["path"])
            executable.write_bytes(b"candidate replaces target binary")
            self.assertEqual(frozen.read_bytes(), b"baseline executable")
            self.assertEqual(MODULE.sha(frozen), result["binaries"]["astrid"]["sha256"])

    def test_schedule_is_two_warmups_plus_sixteen_timed_abba(self):
        arms = MODULE.schedule_arms()
        self.assertEqual(arms[:2], ["main", "candidate"])
        self.assertEqual(arms[2:], ["main", "candidate", "candidate", "main"] * 4)
        self.assertEqual(len(arms), MODULE.WARMUPS + MODULE.TIMED)
        self.assertEqual(MODULE.WARMUPS + MODULE.TIMED, 18)

    def test_local_host_refuses_before_output_or_build(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "must-not-exist"
            argv = [
                "native250",
                "--baseline", directory,
                "--candidate", directory,
                "--baseline-head", HEAD,
                "--candidate-head", CAND,
                "--output", str(output),
            ]
            with patch("sys.argv", argv), patch.dict("os.environ", {}, clear=True), \
                    patch.object(MODULE, "cargo_build") as build, \
                    patch.object(MODULE, "generate_seed") as seed:
                with self.assertRaisesRegex(RuntimeError, "GitHub-hosted"):
                    MODULE.main()
                build.assert_not_called()
                seed.assert_not_called()
                self.assertFalse(output.exists())

    def test_non_github_hosted_runner_refuses(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "out"
            argv = [
                "native250",
                "--baseline", directory,
                "--candidate", directory,
                "--baseline-head", HEAD,
                "--candidate-head", CAND,
                "--output", str(output),
            ]
            env = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "self-hosted"}
            with patch("sys.argv", argv), patch.dict("os.environ", env, clear=True), \
                    patch.object(MODULE.platform, "system", return_value="Darwin"), \
                    patch.object(MODULE.platform, "machine", return_value="arm64"), \
                    patch.object(MODULE, "cargo_build") as build:
                with self.assertRaisesRegex(RuntimeError, "GitHub-hosted"):
                    MODULE.main()
                build.assert_not_called()
                self.assertFalse(output.exists())

    def test_short_sha_refuses_before_git(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "out"
            argv = [
                "native250",
                "--baseline", directory,
                "--candidate", directory,
                "--baseline-head", "deadbeef",
                "--candidate-head", CAND,
                "--output", str(output),
            ]
            env = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}
            with patch("sys.argv", argv), patch.dict("os.environ", env, clear=True), \
                    patch.object(MODULE.platform, "system", return_value="Darwin"), \
                    patch.object(MODULE.platform, "machine", return_value="arm64"), \
                    patch.object(MODULE.packing, "command") as command, \
                    patch.object(MODULE, "cargo_build") as build:
                with self.assertRaisesRegex(RuntimeError, "40-char"):
                    MODULE.main()
                command.assert_not_called()
                build.assert_not_called()

    def test_make_owned_dir_refuses_path_escape_and_reuse(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            owned = MODULE.make_owned_dir(root, "life-00-main")
            self.assertEqual((owned / "ownership.txt").read_text(), MODULE.OWNERSHIP_SENTINEL)
            with self.assertRaisesRegex(RuntimeError, "refusing reuse"):
                MODULE.make_owned_dir(root, "life-00-main")
            with self.assertRaisesRegex(RuntimeError, "owned name traversal"):
                MODULE.make_owned_dir(root, "../outside")

    def test_protected_pid_refusal_does_not_signal(self):
        process = MagicMock(pid=next(iter(MODULE.PROTECTED_PIDS)))
        with patch.object(MODULE.os, "kill") as kill, \
                patch.object(MODULE.subprocess, "check_output") as ps:
            with self.assertRaisesRegex(RuntimeError, "protected"):
                MODULE.sample_owned(process)
            with self.assertRaisesRegex(RuntimeError, "protected"):
                MODULE.wait_owned(process, 0.01)
            kill.assert_not_called()
            ps.assert_not_called()

    def test_assert_owned_refuses_protected_and_identity_mismatch(self):
        daemon = MODULE.OwnedDaemon(
            Path("/tmp/astrid-daemon"), Path("/tmp/home"), Path("/tmp/ws"),
            Path("/tmp/run"), Path("/tmp/log"))
        daemon.process = MagicMock(pid=next(iter(MODULE.PROTECTED_PIDS)))
        daemon.identity = {
            "pid": daemon.process.pid,
            "ppid": os.getpid(),
            "lstart": "fake",
            "command": f"{daemon.binary} --workspace {daemon.workspace}",
            "binary": str(daemon.binary),
            "workspace": str(daemon.workspace),
        }
        with patch.object(MODULE.subprocess, "check_output") as ps, \
                patch.object(MODULE, "sample_owned") as sample:
            with self.assertRaisesRegex(RuntimeError, "protected"):
                daemon.assert_owned()
            ps.assert_not_called()
            sample.assert_not_called()

        daemon.process = MagicMock(pid=424242)
        daemon.identity = {
            "pid": 424242,
            "ppid": os.getpid(),
            "lstart": "Thu Jan  1 00:00:00 1970",
            "command": f"{daemon.binary} --workspace {daemon.workspace}",
            "binary": str(daemon.binary),
            "workspace": str(daemon.workspace),
        }

        def fake_ps(args, text=True):
            flag = args[args.index("-o") + 1]
            if flag == "ppid=":
                return f"{os.getpid()}\n"
            if flag == "lstart=":
                return "Thu Jan  1 00:00:00 1970\n"
            if flag == "command=":
                return "other-bin --workspace /elsewhere\n"
            raise AssertionError(args)

        with patch.object(MODULE.subprocess, "check_output", side_effect=fake_ps), \
                patch.object(MODULE, "sample_owned") as sample:
            with self.assertRaisesRegex(RuntimeError, "daemon identity mismatch"):
                daemon.assert_owned()
            sample.assert_not_called()

    def test_force_kill_requires_identity_before_signal_and_preserves_error(self):
        daemon = MODULE.OwnedDaemon(
            Path("/tmp/astrid-daemon"), Path("/tmp/home"), Path("/tmp/ws"),
            Path("/tmp/run"), Path("/tmp/log"))
        daemon.process = MagicMock(pid=424242)
        daemon.process.poll.return_value = None
        daemon.identity = {
            "pid": 424242,
            "ppid": os.getpid(),
            "lstart": "Thu Jan  1 00:00:00 1970",
            "command": f"{daemon.binary} --workspace {daemon.workspace}",
            "binary": str(daemon.binary),
            "workspace": str(daemon.workspace),
        }
        record = {}
        process = daemon.process
        with patch.object(daemon, "assert_owned") as owned:
            daemon.force_kill_owned(record)
            owned.assert_called()
            process.kill.assert_called_once()
            self.assertTrue(record["failure_cleanup_child_reaped"])
            self.assertIsNone(daemon.process)

        process = MagicMock(pid=424243)
        process.poll.return_value = None
        daemon.process = process
        daemon.identity = {
            "pid": 424243,
            "ppid": os.getpid(),
            "lstart": "Thu Jan  1 00:00:00 1970",
            "command": f"{daemon.binary} --workspace {daemon.workspace}",
            "binary": str(daemon.binary),
            "workspace": str(daemon.workspace),
        }
        original = RuntimeError("seed boom")
        record = {}
        with patch.object(daemon, "assert_owned", side_effect=RuntimeError("identity drifted")):
            with self.assertRaises(RuntimeError) as ctx:
                daemon.force_kill_owned(record, original_error=original)
            self.assertIs(ctx.exception, original)
            self.assertIsInstance(ctx.exception.__cause__, RuntimeError)
            self.assertIn("identity drifted", record["failure_cleanup_error"])
            process.kill.assert_not_called()

    def test_quiet_hold_before_boot_cycle_preserves_no_false_complete(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            rec = {"ordinal": 0, "label": "main", "complete": False, "operations": []}
            with patch.object(MODULE.packing, "quiet_snapshot",
                              return_value={"quiet": False, "background_cpu_percent": 22.0}):
                with self.assertRaisesRegex(RuntimeError, "HOLD"):
                    MODULE.boot_cycle(
                        rec, "first_upgrade", Path("/bin/false"), output / "h", output / "w",
                        output / "d", Path("/bin/false"), Path("/bin/false"), output / "c",
                        output, lambda *args: None)
            self.assertFalse(rec.get("complete", False))
            self.assertIn("quiet_before", rec["first_upgrade"])
            self.assertFalse(rec["first_upgrade"]["quiet_before"]["quiet"])
            self.assertTrue(Path(rec["first_upgrade"]["run_dir"]).exists())

    def test_failure_preserves_fixture_and_marks_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            seed_volume = root / "seed.volume"
            seed_volume.write_bytes(b"seed-bytes-aaaaaaaa")
            seed = {
                "volume": str(seed_volume),
                "sha256": MODULE.sha(seed_volume),
                "bytes": seed_volume.stat().st_size,
            }
            fixture_dir = root / "life-00-main"
            fixture_dir.mkdir()
            (fixture_dir / "home").mkdir()
            (fixture_dir / "workspace").mkdir()
            (fixture_dir / "home" / "astrid.volume").write_bytes(b"seed-bytes-aaaaaaaa")
            fixture = {
                "directory": str(fixture_dir),
                "home": str(fixture_dir / "home"),
                "workspace": str(fixture_dir / "workspace"),
                "volume": str(fixture_dir / "home" / "astrid.volume"),
                "seed_sha256": seed["sha256"],
            }
            receipt = {"runs": []}
            saves = []

            def save():
                saves.append(json.loads(json.dumps(receipt)))

            with patch.object(MODULE, "provision_life", return_value=fixture), \
                    patch.object(MODULE, "disk_policy"), \
                    patch.object(MODULE, "boot_cycle",
                                 side_effect=RuntimeError("first_upgrade failed")):
                with self.assertRaisesRegex(RuntimeError, "first_upgrade failed"):
                    MODULE.run_one(
                        0, "main", Path("/bin/false"), Path("/bin/false"), Path("/bin/false"),
                        Path("/tmp/c"), seed, root, root, receipt, save)
            self.assertEqual(len(receipt["runs"]), 1)
            self.assertFalse(receipt["runs"][0]["complete"])
            self.assertTrue(receipt["runs"][0]["failed_state_preserved"])
            self.assertTrue(fixture_dir.exists())
            self.assertTrue(saves)

    def test_clone_volume_refuses_sha_mismatch_and_alias(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            destination = root / "destination"
            source.write_bytes(b"alpha")
            digest = MODULE.sha(source)

            def fake_copy(cmd, check=True):
                destination.write_bytes(b"beta")
                return MagicMock(returncode=0)

            with patch.object(MODULE, "lsof_idle"), \
                    patch.object(MODULE.subprocess, "run", side_effect=fake_copy):
                with self.assertRaisesRegex(RuntimeError, "clone sha mismatch"):
                    MODULE.clone_volume(source, destination, digest)

            aliased = MagicMock(st_dev=1, st_ino=9)

            def copy_ok(cmd, check=True):
                destination.write_bytes(b"alpha")
                return MagicMock(returncode=0)

            with patch.object(MODULE, "lsof_idle"), \
                    patch.object(MODULE.subprocess, "run", side_effect=copy_ok), \
                    patch.object(Path, "stat", return_value=aliased):
                with self.assertRaisesRegex(RuntimeError, "aliased seed inode"):
                    MODULE.clone_volume(source, destination, digest)

    def test_seed_provenance_flags_are_explicitly_new(self):
        expected = {
            "kind": "source-generated-on-runner",
            "not_byte_identical_to_historical_cfa7": True,
            "historical_cfa7_sha256":
                "cfa7fe7e403b65d94c2a96b113edc02ffc5f8a1d1c771e25a8a083465fee4be9",
            "identity_minted_once_per_job": True,
            "released_2026_10_1_cli_used": False,
        }
        source = Path(__file__).with_name("matched_native250.py").read_text()
        for key, value in expected.items():
            if isinstance(value, bool):
                needle = f'"{key}": {str(value)}'
            else:
                needle = f'"{key}": "{value}"'
            self.assertIn(needle, source)
        self.assertIn('"performance_accepted": False', source)
        self.assertIn("not historical cfa7", source)

    def test_generate_seed_preserves_every_boot_and_operation_in_source(self):
        source = Path(__file__).with_name("matched_native250.py").read_text()
        self.assertIn("boots: list[dict] = []", source)
        self.assertIn("operations: list[dict] = []", source)
        self.assertIn("boots.append(boot)", source)
        self.assertIn('"boots": boots', source)
        self.assertIn('"operations": operations', source)
        for name in ("install-daemon", "roots-daemon", "derive-daemon"):
            self.assertIn(f'boot_seed("{name}")', source)
        self.assertIn('lsof_idle(home / "astrid.volume")', source)
        self.assertIn("owned.force_kill_owned", source)

    def test_volume_only_final_freeze_checked_on_stop(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            (home / "astrid.volume").write_bytes(b"v")
            (home / "extra").mkdir()
            daemon = MODULE.OwnedDaemon(
                Path("/tmp/astrid-daemon"), home, home / "ws", home / "run", home / "log")
            daemon.process = MagicMock(pid=777001, returncode=0, args=["daemon"])
            daemon.process.poll.return_value = 0
            daemon.identity = {"pid": 777001}
            boot = {}
            with patch.object(daemon, "assert_owned"), \
                    patch.object(MODULE, "sample_owned", return_value={"pid": 777001}), \
                    patch.object(MODULE, "wait_owned", return_value={
                        "user_cpu_ns": 1, "system_cpu_ns": 1, "max_rss_bytes": 1,
                        "source": "wait4 exact owned child"}):
                with self.assertRaisesRegex(RuntimeError, "volume-only"):
                    daemon.stop(boot, require_volume_only=True)
                daemon.process = MagicMock(pid=777002, returncode=0, args=["daemon"])
                daemon.process.poll.return_value = 0
                daemon.identity = {"pid": 777002}
                daemon.stop(boot, require_volume_only=False)

    def test_child_env_strips_allocator_logging_and_inherited_principal(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            run = Path(directory) / "run"
            home.mkdir()
            run.mkdir()
            poisoned = {
                "PATH": "/usr/bin",
                "MallocStackLogging": "1",
                "ASTRID_ALLOC_LOG": "1",
                "DYLD_INSERT_LIBRARIES": "x",
                "RUST_LOG": "trace",
                "ASTRID_PRINCIPAL": "leaked-principal",
                "ASTRID_PRINCIPAL_ID": "leaked-id",
                "ASTRID_CLIENT_CONFIG": "x",
                "ASTRID_WORKSPACE_STATE_DIR": "y",
            }
            with patch.dict(os.environ, poisoned, clear=True):
                env = MODULE.child_env(home, run)
                sanitized = MODULE.sanitized_env()
            self.assertEqual(env["ASTRID_HOME"], str(home))
            self.assertEqual(env["ASTRID_RUN_DIR"], str(run))
            for key in poisoned:
                if key == "PATH":
                    continue
                self.assertNotIn(key, env)
                self.assertNotIn(key, sanitized)

    def test_install_capsule_uses_daemon_workspace_yes_and_approve_untrusted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            workspace = root / "workspace"
            run = root / "run"
            capsule = root / "fixture.capsule"
            cli = root / "astrid"
            log_path = root / "install.log"
            home.mkdir()
            workspace.mkdir()
            run.mkdir()
            capsule.write_bytes(b"capsule")
            cli.write_bytes(b"cli")
            captured = {}

            def fake_run(command, env=None, capture_output=True, text=True, timeout=None):
                captured["command"] = command
                captured["env"] = env
                return MagicMock(returncode=0, stdout="installed\n", stderr="")

            with patch.dict(os.environ, {
                "PATH": "/usr/bin",
                "ASTRID_PRINCIPAL": "should-clear",
                "ASTRID_PRINCIPAL_ID": "should-clear-too",
            }, clear=True), patch.object(MODULE.subprocess, "run", side_effect=fake_run):
                item = MODULE.install_capsule(
                    cli, capsule, home, workspace, run, "scale-agent-00000", log_path)
            self.assertEqual(captured["command"], [
                str(cli), "--daemon-workspace", str(workspace), "--principal", "scale-agent-00000",
                "capsule", "install", str(capsule), "--yes", "--approve-untrusted",
            ])
            self.assertNotIn("ASTRID_PRINCIPAL", captured["env"])
            self.assertNotIn("ASTRID_PRINCIPAL_ID", captured["env"])
            self.assertEqual(captured["env"]["ASTRID_HOME"], str(home))
            self.assertEqual(item["daemon_workspace"], str(workspace))
            self.assertEqual(item["exit"], 0)

    def test_build_capsule_uses_sanitized_child_env_not_raw_environ(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            staged = root / "capsule-src"
            staged.mkdir()
            (staged / "src").mkdir()
            (staged / "src" / "lib.rs").write_text("fn main() {}\n")
            hashes = {"src/lib.rs": MODULE.sha(staged / "src" / "lib.rs")}
            out = root / "out"
            out.mkdir()
            cli = root / "astrid"
            cli.write_bytes(b"cli")
            captured = {}

            def fake_run(command, env=None, stdout=None, stderr=None, timeout=None):
                captured["env"] = dict(env)
                capsule = out / "capsule-dist" / "fixture.capsule"
                capsule.parent.mkdir(parents=True, exist_ok=True)
                capsule.write_bytes(b"built")
                return MagicMock(returncode=0)

            with patch.dict(os.environ, {
                "PATH": "/usr/bin",
                "ASTRID_PRINCIPAL": "raw-leak",
                "MallocStackLogging": "1",
            }, clear=True), \
                    patch.object(MODULE, "stage_capsule_source", return_value=(staged, hashes)), \
                    patch.object(MODULE, "private_run_dir", return_value=root / "run"), \
                    patch.object(MODULE.subprocess, "run", side_effect=fake_run), \
                    patch.object(MODULE, "tree_file_hashes", side_effect=[hashes, hashes]):
                (root / "run").mkdir()
                MODULE.build_capsule(cli, root, out, MODULE.time.monotonic() + 60)
            self.assertNotIn("ASTRID_PRINCIPAL", captured["env"])
            self.assertNotIn("MallocStackLogging", captured["env"])
            self.assertEqual(captured["env"]["ASTRID_HOME"], str(root / "capsule-builder-home"))

    def test_lsof_idle_requires_empty_stderr_and_fails_closed(self):
        path = Path("/tmp/native250-lsof-probe")
        with patch.object(MODULE.subprocess, "run",
                          return_value=MagicMock(returncode=1, stdout="", stderr="")):
            MODULE.lsof_idle(path)
        with patch.object(MODULE.subprocess, "run",
                          return_value=MagicMock(returncode=1, stdout="",
                                                 stderr="lsof: status error on /tmp: Permission denied\n")):
            with self.assertRaisesRegex(RuntimeError, "stderr not empty"):
                MODULE.lsof_idle(path)
        with patch.object(MODULE.subprocess, "run",
                          return_value=MagicMock(returncode=2, stdout="", stderr="")):
            with self.assertRaisesRegex(RuntimeError, "failed closed"):
                MODULE.lsof_idle(path)
        with patch.object(MODULE.subprocess, "run",
                          return_value=MagicMock(returncode=0, stdout="1234\n", stderr="")):
            with self.assertRaisesRegex(RuntimeError, "is open"):
                MODULE.lsof_idle(path)

    def test_select_release_rlibs_uses_compiler_artifact_provenance_uniquely(self):
        with tempfile.TemporaryDirectory() as directory:
            deps = Path(directory) / "deps"
            deps.mkdir()
            artifacts = []
            for name in sorted(MODULE.WANTED_LIBS):
                path = deps / f"lib{name}-abc.rlib"
                path.write_bytes(name.encode())
                artifacts.append(_artifact(name, path))
            selected = MODULE.select_release_rlibs(artifacts)
            self.assertEqual(set(selected), MODULE.WANTED_LIBS)
            self.assertEqual(Path(selected["astrid_uplink"]["path"]).parent, deps)

            conflict = deps / "libastrid_uplink-other.rlib"
            conflict.write_bytes(b"other")
            bad = artifacts + [_artifact("astrid_uplink", conflict, package_id="pkg/other@1")]
            with self.assertRaisesRegex(RuntimeError, "conflicting compiler-artifact provenance"):
                MODULE.select_release_rlibs(bad)

            ambiguous = artifacts[:-1] + [
                _artifact("uuid", deps / "libuuid-abc.rlib",
                          extra_filenames=[str(deps / "libuuid-extra.rlib")])
            ]
            (deps / "libuuid-abc.rlib").write_bytes(b"uuid")
            (deps / "libuuid-extra.rlib").write_bytes(b"extra")
            with self.assertRaisesRegex(RuntimeError, "ambiguous rlib filenames"):
                MODULE.select_release_rlibs(ambiguous)

            missing = [item for item in artifacts if item["target"] != "anyhow"]
            with self.assertRaisesRegex(RuntimeError, "missing release rlib provenance"):
                MODULE.select_release_rlibs(missing)

            # Non-release / test profiles must not win.
            testish = artifacts + [_artifact("anyhow", deps / "libanyhow-test.rlib",
                                            opt_level="0", test=True)]
            (deps / "libanyhow-test.rlib").write_bytes(b"test")
            again = MODULE.select_release_rlibs(testish)
            self.assertEqual(again["anyhow"]["path"], str(deps / "libanyhow-abc.rlib"))

    def test_stage_capsule_source_freezes_hashes_and_rejects_generated_trees(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            fake_source = root / "native250_capsule"
            fake_source.mkdir()
            (fake_source / "src").mkdir()
            (fake_source / "src" / "lib.rs").write_text("pub fn probe() {}\n")
            ownership = root / "ownership-root"
            ownership.mkdir()
            with patch.object(MODULE, "CAPSULE_SOURCE", fake_source):
                staged, hashes = MODULE.stage_capsule_source(ownership)
            self.assertEqual(hashes["src/lib.rs"], MODULE.sha(fake_source / "src" / "lib.rs"))
            self.assertEqual(MODULE.tree_file_hashes(staged), hashes)
            (fake_source / "dist").mkdir()
            with patch.object(MODULE, "CAPSULE_SOURCE", fake_source):
                with self.assertRaisesRegex(RuntimeError, "must not include dist"):
                    MODULE.stage_capsule_source(ownership / "second")

    def test_disk_policy_keeps_local_floor_and_ci_reserve(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(MODULE.shutil, "disk_usage",
                              return_value=MagicMock(free=39 * 1024 ** 3)):
                with self.assertRaisesRegex(RuntimeError, "40 GiB"):
                    MODULE.disk_policy(root, local=True)
            with patch.object(MODULE.shutil, "disk_usage",
                              return_value=MagicMock(free=1 * 1024 ** 3)):
                with self.assertRaisesRegex(RuntimeError, "disposable CI"):
                    MODULE.disk_policy(root, local=False)

    def test_client_source_pins_compile_time_ownership_contracts(self):
        source = Path(__file__).with_name("native_lifecycle_client.rs").read_text()
        # Pin required contracts; do not re-implement owned_home in Python.
        required = [
            'env!("NATIVE250_OWNERSHIP_ROOT")',
            "isolated native250 portable fixture 20261103",
            "fn reject_traversal",
            "fn require_non_symlink",
            "must not be a symlink",
            "must not contain '.' or '..' components",
            "ASTRID_HOME leaf must be exactly 'home'",
            "home parent escapes compile-time ownership root",
            "ASTRID_HOME parent must be a direct child of the compile-time ownership root",
            "missing or forged ownership guard",
            'std::fs::canonicalize(root)',
            'std::fs::canonicalize(home_path)',
        ]
        for needle in required:
            self.assertIn(needle, source)
        # life-* naming may use starts_with; path containment must still be
        # canonicalize + strip_prefix, not a bare Path::starts_with escape.
        self.assertIn('parent_name.starts_with("life-")', source)
        self.assertNotIn("home_canon.starts_with(", source)
        self.assertNotIn("home_path.starts_with(", source)

    def test_capsule_tree_is_source_only(self):
        capsule = Path(__file__).with_name("native250_capsule")
        self.assertTrue((capsule / "src" / "lib.rs").is_file())
        for forbidden in ("dist", "target", "builder-home"):
            self.assertFalse((capsule / forbidden).exists())
        digest = MODULE.sha(capsule / "src" / "lib.rs")
        self.assertEqual(
            digest, "9e2ad9498ff374c61abd2d3ef7ffd422b6d30633e73657104c2d41cb08c06b76")

    def test_immutable_seed_hash_helper_used_after_life(self):
        source = Path(__file__).with_name("matched_native250.py").read_text()
        self.assertIn(
            'require(sha(Path(seed["volume"])) == seed["sha256"], "seed hash changed after life")',
            source)
        self.assertIn(
            'require(sha(Path(seed["volume"])) == seed["sha256"], "immutable seed hash violated")',
            source)

    def test_private_run_dir_uses_short_private_tmp(self):
        path = MODULE.private_run_dir("unit")
        try:
            self.assertTrue(str(path).startswith("/private/tmp/ast-n250-"))
            self.assertTrue(path.is_dir())
        finally:
            path.rmdir()

    def test_native_metrics_are_honestly_darwin_only(self):
        source = Path(__file__).with_name("matched_native250.py").read_text()
        self.assertIn('require(IS_DARWIN, "sample_owned requires Darwin")', source)
        self.assertIn('raise RuntimeError("native process metrics require Darwin")', source)
        self.assertIn('"darwin_only_native_metrics": True', source)
        process = MagicMock(pid=555001)
        with patch.object(MODULE, "IS_DARWIN", False):
            with self.assertRaisesRegex(RuntimeError, "Darwin"):
                MODULE.sample_owned(process)

    def test_native_reuses_packing_terminal_receipt_fallback(self):
        receipt = {
            "complete": False,
            "performance_accepted": False,
            "failure": "background load before life: HOLD",
            "runs": [],
            "builds": {
                "main": {"head": HEAD, "tree": "c" * 40, "binaries": {
                    "astrid-daemon": {"path": "/tmp/d", "sha256": "1" * 64}},
                          "client": {"path": "/tmp/client", "sha256": "9" * 64}},
            },
            "quiet_gate_before_life": {
                "ordinal": 0, "quiet": False, "background_cpu_percent": 12.0,
                "rows": ["noise"] * 10,
            },
            "seed": {
                "sha256": "2" * 64, "bytes": 1,
                "provenance": {"not_byte_identical_to_historical_cfa7": True},
            },
        }
        summary = MODULE.packing.terminal_receipt(receipt)
        encoded = json.dumps(summary)
        self.assertTrue(summary["runs_present"])
        self.assertEqual(summary["run_count"], 0)
        self.assertEqual(summary["seed"]["sha256"], "2" * 64)
        self.assertIn("not_byte_identical_to_historical_cfa7", encoded)
        self.assertNotIn("noise", encoded)
        # Root packing compact preserves nested identities (e.g. client SHA) via
        # generic row/artifact omission only.
        self.assertEqual(
            summary["builds"]["main"]["client"]["sha256"], "9" * 64)
        self.assertTrue(summary["quiet_observations"][0]["rows_omitted_from_terminal"])


if __name__ == "__main__":
    unittest.main()
