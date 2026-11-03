"""Causal synthetic checks for native250.build; no cargo, daemon, or live volume."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock, patch


SPEC = importlib.util.spec_from_file_location(
    "native250_build",
    Path(__file__).resolve().parent / "native250" / "build.py",
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
HEAD = "a" * 40


def _artifact(
    name: str,
    path: Path,
    *,
    opt_level: str = "3",
    test: bool = False,
    package_id: str | None = None,
    extra_filenames: list[str] | None = None,
):
    filenames = [str(path)]
    if extra_filenames:
        filenames.extend(extra_filenames)
    return {
        "target": name,
        "package_id": package_id or f"pkg/{name}@0.0.0",
        "profile": {"opt_level": opt_level, "test": test},
        "filenames": filenames,
        "filename_sha256s": {
            str(path): MODULE.sha(path) if path.is_file() else None,
            **{
                extra: MODULE.sha(Path(extra)) if Path(extra).is_file() else None
                for extra in (extra_filenames or [])
            },
        },
    }


class Native250BuildSyntheticTests(unittest.TestCase):
    def setUp(self):
        self.source_preparation = {"workspace_packages": []}
        prepare = patch.object(MODULE.packing.source_build, "prepare", return_value=self.source_preparation)
        verify = patch.object(MODULE.packing.source_build, "verify_artifact")
        self.prepare_source = prepare.start()
        self.verify_source = verify.start()
        self.addCleanup(prepare.stop)
        self.addCleanup(verify.stop)

    def test_baseline_seed_client_is_frozen_before_candidate_replaces_shared_libraries(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory).resolve()
            baseline, candidate = {"producer": "main"}, {"producer": "candidate"}
            events = []
            receipt = {}
            def build(path, head, target, log, deadline):
                events.append(head)
                if head == "b" * 40:
                    self.assertIn("seed_client", receipt)
                    self.assertEqual(events, [HEAD, "link-baseline", "b" * 40])
                    return candidate
                return baseline
            def link(producer, ownership, destination, deadline):
                self.assertIs(producer, baseline)
                self.assertTrue(destination.is_dir())
                events.append("link-baseline")
                return {"path": str(destination / "client")}
            with patch.object(MODULE, "build_install_set", side_effect=build), \
                    patch.object(MODULE, "build_shared_client", side_effect=link):
                builds, client = MODULE.build_producers_with_seed_client(
                    [("main", output, HEAD), ("candidate", output, "b" * 40)],
                    output / "owned", output, float("inf"), receipt, lambda: None)
            self.assertIs(builds["candidate"], candidate)
            self.assertEqual(client["producer_head"], HEAD)
            self.assertFalse(client["shared_both_arms"])
            self.assertEqual(client["role"], "baseline-seed-only")

    def test_build_install_set_emits_public_astrid_package_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            checkout = root / "checkout"
            checkout.mkdir()
            (checkout / "Cargo.lock").write_text("fixture")
            target = root / "cargo-target"
            frozen_src = {
                "astrid": root / "producer-astrid",
                "astrid-daemon": root / "producer-daemon",
                "astrid-build": root / "producer-build",
            }
            for path in frozen_src.values():
                path.write_bytes(path.name.encode())

            process = MagicMock()
            process.pid = 424242
            process.wait.return_value = 0

            def produce(*_args, **kwargs):
                for name, path in frozen_src.items():
                    event = {
                        "reason": "compiler-artifact",
                        "target": {"name": name},
                        "executable": str(path),
                        "filenames": [str(path)],
                        "profile": {"opt_level": "3", "test": False},
                        "package_id": "astrid@0.0.0",
                    }
                    kwargs["stdout"].write(json.dumps(event) + "\n")
                kwargs["stdout"].flush()
                return process

            with patch.object(MODULE.packing, "clean_checkout"), \
                    patch.object(MODULE.packing, "command", return_value=HEAD), \
                    patch.object(MODULE.subprocess, "Popen", side_effect=produce) as popen:
                result = MODULE.build_install_set(
                    checkout, HEAD, target, root / "main-cargo.jsonl", float("inf")
                )
            preparation_args = self.prepare_source.call_args.args
            self.assertEqual(preparation_args[:3], (checkout, target, root / "main-cargo.jsonl"))
            self.assertEqual(preparation_args[3]["CARGO_TARGET_DIR"], str(target))
            self.assertGreater(preparation_args[4], MODULE.time.monotonic())
            self.assertIs(result["source_build"], self.source_preparation)
            self.assertEqual(self.verify_source.call_count, 3)
            command = popen.call_args.args[0]
            self.assertEqual(result["packages"], ["astrid"])
            self.assertIn("-p", command)
            self.assertEqual(command[command.index("-p") + 1], "astrid")
            self.assertNotIn("astrid-cli", command)
            self.assertNotIn("-j", command)
            self.assertIn("--release", command)
            self.assertIn("--locked", command)
            self.assertNotIn("astrid-daemon", command[command.index("-p") :])
            self.assertEqual(
                set(result["binaries"]),
                {"astrid", "astrid-daemon", "astrid-build"},
            )
            self.assertEqual(
                result["required_frozen_binaries"],
                ["astrid", "astrid-build", "astrid-daemon"],
            )
            self.assertTrue(popen.call_args.kwargs["start_new_session"])

    def test_build_install_set_fails_closed_when_companion_missing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            checkout = root / "checkout"
            checkout.mkdir()
            (checkout / "Cargo.lock").write_text("fixture")
            target = root / "cargo-target"
            astrid = root / "producer-astrid"
            daemon = root / "producer-daemon"
            astrid.write_bytes(b"cli")
            daemon.write_bytes(b"daemon")
            process = MagicMock()
            process.pid = 515151
            process.wait.return_value = 0

            def produce(*_args, **kwargs):
                for name, path in (("astrid", astrid), ("astrid-daemon", daemon)):
                    kwargs["stdout"].write(
                        json.dumps(
                            {
                                "reason": "compiler-artifact",
                                "target": {"name": name},
                                "executable": str(path),
                                "filenames": [str(path)],
                            }
                        )
                        + "\n"
                    )
                kwargs["stdout"].flush()
                return process

            with patch.object(MODULE.packing, "clean_checkout"), \
                    patch.object(MODULE.packing, "command", return_value=HEAD), \
                    patch.object(MODULE.subprocess, "Popen", side_effect=produce):
                with self.assertRaisesRegex(RuntimeError, "frozen install binaries missing"):
                    MODULE.build_install_set(
                        checkout, HEAD, target, root / "main-cargo.jsonl", float("inf")
                    )

    def test_cargo_inventory_content_binds_every_present_filename(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            checkout = root / "checkout"
            checkout.mkdir()
            (checkout / "Cargo.lock").write_text("fixture")
            target = root / "cargo-target"
            primary = root / "libfoo.rlib"
            secondary = root / "libfoo.rmeta"
            primary.write_bytes(b"rlib-bytes")
            secondary.write_bytes(b"rmeta-bytes")
            process = MagicMock()
            process.pid = 616161
            process.wait.return_value = 0

            def produce(*_args, **kwargs):
                kwargs["stdout"].write(
                    json.dumps(
                        {
                            "reason": "compiler-artifact",
                            "target": {"name": "foo"},
                            "filenames": [str(primary), str(secondary)],
                            "profile": {"opt_level": "3", "test": False},
                            "package_id": "pkg/foo@0",
                        }
                    )
                    + "\n"
                )
                kwargs["stdout"].flush()
                return process

            with patch.object(MODULE.packing, "clean_checkout"), \
                    patch.object(MODULE.packing, "command", return_value=HEAD), \
                    patch.object(MODULE.subprocess, "Popen", side_effect=produce):
                result = MODULE.cargo_build(
                    checkout, HEAD, ["astrid"], target, root / "build.jsonl", float("inf")
                )
            artifact = result["artifacts"][0]
            self.assertEqual(result["artifact_inventory_binding"], "all_present_filenames_sha256")
            self.assertEqual(
                artifact["filename_sha256s"][str(primary)], MODULE.sha(primary)
            )
            self.assertEqual(
                artifact["filename_sha256s"][str(secondary)], MODULE.sha(secondary)
            )

    def test_select_release_rlibs_rejects_inventory_sha_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "libanyhow.rlib"
            path.write_bytes(b"library")
            item = _artifact("anyhow", path)
            item["filename_sha256s"][str(path)] = "0" * 64
            with self.assertRaisesRegex(RuntimeError, "disagrees with artifact inventory"):
                MODULE.select_release_rlibs([item])

    def test_build_capsule_rejects_missing_companion_beside_cli(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            staged = root / "capsule-src"
            staged.mkdir()
            (staged / "src").mkdir()
            (staged / "src" / "lib.rs").write_text("fn main() {}\n")
            hashes = {"src/lib.rs": MODULE.sha(staged / "src" / "lib.rs")}
            out = root / "out"
            out.mkdir()
            cli = root / "frozen" / "astrid"
            cli.parent.mkdir()
            cli.write_bytes(b"cli")
            with patch.object(MODULE, "stage_capsule_source", return_value=(staged, hashes)), \
                    patch.object(MODULE, "private_run_dir", side_effect=[root / "run", root / "target"]):
                (root / "run").mkdir()
                (root / "target").mkdir()
                with self.assertRaisesRegex(RuntimeError, "astrid-build companion missing"):
                    MODULE.build_capsule(cli, root, out, MODULE.time.monotonic() + 60)

    def test_build_capsule_uses_external_target_and_keeps_staged_source_clean(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            ownership = root / "ownership-root"
            ownership.mkdir()
            staged = ownership / "capsule-src"
            staged.mkdir()
            (staged / "src").mkdir()
            (staged / "src" / "lib.rs").write_text("fn main() {}\n")
            hashes = {"src/lib.rs": MODULE.sha(staged / "src" / "lib.rs")}
            out = root / "publication"
            out.mkdir()
            frozen = root / "frozen"
            frozen.mkdir()
            cli = frozen / "astrid"
            companion = frozen / "astrid-build"
            cli.write_bytes(b"cli")
            companion.write_bytes(b"build")
            run = root / "run"
            cargo_target = root / "external-capsule-target"
            run.mkdir()
            cargo_target.mkdir()
            captured = {}

            def fake_popen(command, env=None, stdout=None, stderr=None, start_new_session=None):
                captured["command"] = list(command)
                captured["env"] = dict(env)
                captured["start_new_session"] = start_new_session
                capsule = out / "capsule-dist" / "fixture.capsule"
                capsule.parent.mkdir(parents=True, exist_ok=True)
                capsule.write_bytes(b"built")
                # Simulate a bad builder that would pollute staged source if
                # CARGO_TARGET_DIR were unset; our env must point elsewhere.
                pollution = Path(env["CARGO_TARGET_DIR"]) / "wasm32" / "release"
                pollution.mkdir(parents=True, exist_ok=True)
                (pollution / "mark").write_text("generated")
                process = MagicMock()
                process.pid = 717171
                process.wait.return_value = 0
                return process

            with patch.dict(
                os.environ,
                {"PATH": "/usr/bin", "ASTRID_PRINCIPAL": "raw-leak", "MallocStackLogging": "1"},
                clear=True,
            ), patch.object(MODULE, "stage_capsule_source", return_value=(staged, hashes)), \
                    patch.object(
                        MODULE,
                        "private_run_dir",
                        side_effect=[run, cargo_target],
                    ), patch.object(MODULE.subprocess, "Popen", side_effect=fake_popen), \
                    patch.object(
                        MODULE,
                        "tree_file_hashes",
                        side_effect=[hashes, {"src/lib.rs": hashes["src/lib.rs"]}],
                    ):
                result = MODULE.build_capsule(
                    cli, ownership, out, MODULE.time.monotonic() + 60
                )
            self.assertEqual(
                captured["command"],
                [str(cli), "capsule", "build", str(staged), "--output", str(out / "capsule-dist")],
            )
            self.assertTrue(captured["start_new_session"])
            self.assertEqual(captured["env"]["CARGO_TARGET_DIR"], str(cargo_target))
            self.assertNotIn("CARGO_HOME", captured["env"])
            self.assertNotIn("RUSTUP_HOME", captured["env"])
            self.assertNotIn("ASTRID_PRINCIPAL", captured["env"])
            self.assertNotIn("MallocStackLogging", captured["env"])
            self.assertFalse((staged / "target").exists())
            self.assertTrue((cargo_target / "wasm32" / "release" / "mark").is_file())
            self.assertEqual(result["cargo_target_dir"], str(cargo_target))
            self.assertEqual(result["cli_companion_sha256"], MODULE.sha(companion))

    def test_build_capsule_timeout_kills_owned_process_group(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            ownership = root / "ownership-root"
            ownership.mkdir()
            staged = ownership / "capsule-src"
            staged.mkdir()
            (staged / "src").mkdir()
            (staged / "src" / "lib.rs").write_text("fn main() {}\n")
            hashes = {"src/lib.rs": MODULE.sha(staged / "src" / "lib.rs")}
            out = root / "publication"
            out.mkdir()
            frozen = root / "frozen"
            frozen.mkdir()
            cli = frozen / "astrid"
            (frozen / "astrid-build").write_bytes(b"build")
            cli.write_bytes(b"cli")
            run = root / "run"
            cargo_target = root / "external-capsule-target"
            run.mkdir()
            cargo_target.mkdir()
            process = MagicMock()
            process.pid = 818181
            process.args = ["astrid", "capsule", "build"]
            process.wait.side_effect = [
                subprocess.TimeoutExpired(process.args, 1),
                0,
            ]

            with patch.object(MODULE, "stage_capsule_source", return_value=(staged, hashes)), \
                    patch.object(
                        MODULE,
                        "private_run_dir",
                        side_effect=[run, cargo_target],
                    ), patch.object(MODULE.subprocess, "Popen", return_value=process), \
                    patch.object(MODULE.os, "killpg") as killpg, \
                    patch.object(MODULE.time, "monotonic", side_effect=[0.0, 0.0, 0.0]):
                with self.assertRaises(subprocess.TimeoutExpired):
                    MODULE.build_capsule(cli, ownership, out, 1.0)
            killpg.assert_called_once_with(818181, MODULE.signal.SIGKILL)
            self.assertEqual(process.wait.call_count, 2)

    def test_source_constants_resolve_under_parent_bench_dir(self):
        bench = Path(__file__).resolve().parent
        self.assertEqual(MODULE.BENCH_DIR, bench)
        self.assertEqual(MODULE.CLIENT_SOURCE, bench / "native_lifecycle_client.rs")
        self.assertEqual(MODULE.CLIENT_ADMIN_SOURCE, bench / "native250_admin.rs")
        self.assertEqual(MODULE.CAPSULE_SOURCE, bench / "native250_capsule")
        self.assertEqual(MODULE.PACKING_PATH, bench / "matched_volume_packing.py")
        self.assertEqual(MODULE.INSTALL_PACKAGES, ["astrid"])
        self.assertEqual(
            MODULE.REQUIRED_FROZEN_BINARIES,
            frozenset({"astrid", "astrid-daemon", "astrid-build"}),
        )
        self.assertEqual(
            sorted(MODULE.REQUIRED_FROZEN_BINARIES),
            ["astrid", "astrid-build", "astrid-daemon"],
        )

    def test_build_shared_client_binds_main_and_admin_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            checkout = root / "checkout"
            checkout.mkdir()
            deps = root / "deps"
            deps.mkdir()
            libraries = {}
            artifacts = []
            for name in sorted(MODULE.WANTED_LIBS):
                path = deps / f"lib{name}.rlib"
                path.write_bytes(f"lib-{name}".encode())
                libraries[name] = path
                artifacts.append(_artifact(name, path, package_id=f"pkg/{name}@0"))
            main_src = root / "native_lifecycle_client.rs"
            admin_src = root / "native250_admin.rs"
            main_src.write_text("fn main() {}\n")
            admin_src.write_text("// admin\n")
            output = root / "out"
            output.mkdir()
            ownership = root / "ownership"
            ownership.mkdir()
            candidate = {
                "checkout": str(checkout),
                "rustc": "rustc 1.91.0",
                "artifacts": artifacts,
            }

            def fake_run(cmd, cwd=None, env=None, stdout=None, stderr=None, timeout=None):
                binary = Path(cmd[cmd.index("-o") + 1])
                binary.write_bytes(b"client-bin")
                completed = MagicMock()
                completed.returncode = 0
                return completed

            with patch.object(MODULE, "CLIENT_SOURCE", main_src), \
                    patch.object(MODULE, "CLIENT_ADMIN_SOURCE", admin_src), \
                    patch.object(MODULE.packing, "command", return_value="rustc 1.91.0"), \
                    patch.object(MODULE.subprocess, "run", side_effect=fake_run) as run:
                result = MODULE.build_shared_client(
                    candidate, ownership, output, MODULE.time.monotonic() + 60
                )
            command = run.call_args.args[0]
            self.assertEqual(command[command.index(str(main_src))], str(main_src))
            self.assertNotIn(str(admin_src), command)
            self.assertEqual(
                result["client_sources"],
                [
                    {"source": str(main_src), "sha256": MODULE.sha(main_src)},
                    {"source": str(admin_src), "sha256": MODULE.sha(admin_src)},
                ],
            )
            self.assertEqual(result["source_sha256"], MODULE.sha(main_src))
            self.assertEqual(result["public_command"], command)
            self.assertTrue(result["shared_both_arms"])
            self.assertEqual(Path(result["path"]).read_bytes(), b"client-bin")

    def test_build_shared_client_requires_admin_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            checkout = root / "checkout"
            checkout.mkdir()
            deps = root / "deps"
            deps.mkdir()
            artifacts = []
            for name in sorted(MODULE.WANTED_LIBS):
                path = deps / f"lib{name}.rlib"
                path.write_bytes(f"lib-{name}".encode())
                artifacts.append(_artifact(name, path))
            main_src = root / "native_lifecycle_client.rs"
            missing_admin = root / "missing-native250_admin.rs"
            main_src.write_text("fn main() {}\n")
            candidate = {
                "checkout": str(checkout),
                "rustc": "rustc 1.91.0",
                "artifacts": artifacts,
            }
            with patch.object(MODULE, "CLIENT_SOURCE", main_src), \
                    patch.object(MODULE, "CLIENT_ADMIN_SOURCE", missing_admin), \
                    patch.object(MODULE.packing, "command", return_value="rustc 1.91.0"):
                with self.assertRaisesRegex(RuntimeError, "native250_admin.rs missing"):
                    MODULE.build_shared_client(
                        candidate,
                        root / "ownership",
                        root / "out",
                        MODULE.time.monotonic() + 60,
                    )

    def test_build_shared_client_rejects_source_drift_during_link(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            checkout = root / "checkout"
            checkout.mkdir()
            deps = root / "deps"
            deps.mkdir()
            artifacts = []
            for name in sorted(MODULE.WANTED_LIBS):
                path = deps / f"lib{name}.rlib"
                path.write_bytes(f"lib-{name}".encode())
                artifacts.append(_artifact(name, path))
            main_src = root / "native_lifecycle_client.rs"
            admin_src = root / "native250_admin.rs"
            main_src.write_text("fn main() {}\n")
            admin_src.write_text("// admin\n")
            output = root / "out"
            output.mkdir()
            ownership = root / "ownership"
            ownership.mkdir()
            candidate = {
                "checkout": str(checkout),
                "rustc": "rustc 1.91.0",
                "artifacts": artifacts,
            }

            def mutating_run(cmd, cwd=None, env=None, stdout=None, stderr=None, timeout=None):
                admin_src.write_text("// mutated during link\n")
                binary = Path(cmd[cmd.index("-o") + 1])
                binary.write_bytes(b"client-bin")
                completed = MagicMock()
                completed.returncode = 0
                return completed

            with patch.object(MODULE, "CLIENT_SOURCE", main_src), \
                    patch.object(MODULE, "CLIENT_ADMIN_SOURCE", admin_src), \
                    patch.object(MODULE.packing, "command", return_value="rustc 1.91.0"), \
                    patch.object(MODULE.subprocess, "run", side_effect=mutating_run):
                with self.assertRaisesRegex(RuntimeError, "client compiler inputs changed"):
                    MODULE.build_shared_client(
                        candidate, ownership, output, MODULE.time.monotonic() + 60
                    )


if __name__ == "__main__":
    unittest.main()
