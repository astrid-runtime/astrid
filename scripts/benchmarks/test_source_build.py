"""Synthetic checks for source_build; no cargo, daemon, network, or live builds."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch


SPEC = importlib.util.spec_from_file_location(
    "source_build",
    Path(__file__).resolve().parent / "source_build.py",
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def _ci_env(workspace: Path, **extra: str) -> dict[str, str]:
    env = {
        "GITHUB_ACTIONS": "true",
        "RUNNER_ENVIRONMENT": "github-hosted",
        "GITHUB_WORKSPACE": str(workspace),
        "PATH": "/usr/bin:/bin",
        "HOME": str(workspace / "runner-home"),
    }
    env.update(extra)
    return env


def _metadata(checkout: Path, packages: list[tuple[str, str, str]]) -> dict:
    members = []
    rows = []
    lock_rows = []
    for name, package_id, rel in packages:
        manifest = checkout / rel / "Cargo.toml"
        manifest.parent.mkdir(parents=True, exist_ok=True)
        manifest.write_text("[package]\nname=%r\nversion=\"0.0.0\"\n" % name, encoding="utf-8")
        lock_rows.append(f'[[package]]\nname = "{name}"\nversion = "0.0.0"\n')
        members.append(package_id)
        rows.append(
            {
                "name": name,
                "id": package_id,
                "manifest_path": str(manifest.resolve()),
                "version": "0.0.0",
            }
        )
    (checkout / "Cargo.lock").write_text("\n".join(lock_rows), encoding="utf-8")
    # One registry package that must not be cleaned.
    rows.append(
        {
            "name": "serde",
            "id": "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.0",
            "manifest_path": str((checkout.parent / "registry" / "serde" / "Cargo.toml")),
            "version": "1.0.0",
        }
    )
    return {
        "workspace_root": str(checkout.resolve()),
        "workspace_members": members,
        "packages": rows,
    }


class SourceBuildSyntheticTests(unittest.TestCase):
    def test_child_environment_cache_homes_are_refused_before_cargo(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            checkout = root / "checkout"
            checkout.mkdir()
            hosted = _ci_env(root)
            cases = [
                ({"HOME": str(root / "different-home")}, root / "different-home" / ".cargo" / "cargo-target"),
                ({"HOME": str(root / "different-home")}, root / "different-home" / ".rustup" / "cargo-target"),
                ({"CARGO_HOME": "../relative-cache"}, root / "relative-cache" / "cargo-target"),
                ({"RUSTUP_HOME": "../relative-rustup"}, root / "relative-rustup" / "cargo-target"),
            ]
            with patch.dict(os.environ, hosted, clear=True), \
                    patch.object(MODULE.subprocess, "Popen") as cargo:
                for changes, target in cases:
                    with self.subTest(changes=changes):
                        with self.assertRaisesRegex(RuntimeError, "outside host cache/rustup"):
                            MODULE.prepare(checkout, target, root / "build.log",
                                           dict(hosted, **changes), time.monotonic() + 30)
                cargo.assert_not_called()

    def test_clean_rejects_same_name_registry_or_other_version_before_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            checkout = Path(directory).resolve()
            packages = [{"name": "fixture"}]
            valid = '[[package]]\nname="fixture"\nversion="0.0.0"\n'
            for bad in (valid + '[[package]]\nname="fixture"\nversion="1.0.0"\nsource="registry+test"\n',
                        valid + '[[package]]\nname="fixture"\nversion="1.0.0"\n',
                        valid + 'source="registry+test"\n'):
                (checkout / "Cargo.lock").write_text(bad)
                with self.assertRaisesRegex(RuntimeError, "not unique and local"):
                    MODULE._validate_clean_names(packages, checkout)
            (checkout / "Cargo.lock").write_text(valid)
            self.assertEqual(len(MODULE._validate_clean_names(packages, checkout)), 64)

    def test_prepare_refuses_non_hosted_runner_before_cargo(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            checkout = root / "checkout"
            checkout.mkdir()
            target = root / "cargo-target"
            log = root / "build.jsonl"
            env = {"PATH": "/usr/bin"}
            with patch.dict(os.environ, {}, clear=True), \
                    patch.object(MODULE.subprocess, "Popen") as popen:
                with self.assertRaisesRegex(RuntimeError, "GitHub-hosted"):
                    MODULE.prepare(checkout, target, log, env, time.monotonic() + 30)
                popen.assert_not_called()

    def test_prepare_refuses_target_inside_checkout_or_host_caches(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            home = root / "runner-home"
            home.mkdir()
            checkout = root / "checkout"
            checkout.mkdir()
            log = root / "build.jsonl"
            hosted = _ci_env(root)
            with patch.dict(os.environ, hosted, clear=True), \
                    patch.object(MODULE.subprocess, "Popen") as popen:
                with self.assertRaisesRegex(RuntimeError, "named cargo-target"):
                    MODULE.prepare(checkout, root / "other-target", log, dict(hosted), time.monotonic() + 30)
                with self.assertRaisesRegex(RuntimeError, "outside the producer checkout"):
                    MODULE.prepare(
                        checkout, checkout / "cargo-target", log, dict(hosted), time.monotonic() + 30
                    )
                cargo_home = home / ".cargo"
                cargo_home.mkdir()
                with self.assertRaisesRegex(RuntimeError, "host cache/rustup"):
                    MODULE.prepare(
                        checkout,
                        cargo_home / "cargo-target",
                        log,
                        {**hosted, "CARGO_HOME": str(cargo_home), "HOME": str(home)},
                        time.monotonic() + 30,
                    )
                popen.assert_not_called()

    def test_prepare_refuses_symlink_ancestor(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            real_workspace = root / "real-workspace"
            real_workspace.mkdir()
            link_workspace = root / "link-workspace"
            link_workspace.symlink_to(real_workspace)
            checkout = real_workspace / "checkout"
            checkout.mkdir()
            target = real_workspace / "cargo-target"
            log = real_workspace / "build.jsonl"
            hosted = _ci_env(link_workspace)
            with patch.dict(os.environ, hosted, clear=True), \
                    patch.object(MODULE.subprocess, "Popen") as popen:
                with self.assertRaisesRegex(RuntimeError, "symlink ancestor"):
                    MODULE.prepare(checkout, target, log, dict(hosted), time.monotonic() + 30)
                popen.assert_not_called()

    def test_prepare_cleans_unique_workspace_packages_and_appends_log(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            checkout = root / "checkout"
            checkout.mkdir()
            target = root / "evidence" / "cargo-target"
            target.parent.mkdir()
            log = root / "evidence" / "candidate-build.jsonl"
            hosted = _ci_env(root)
            meta = _metadata(
                checkout,
                [
                    (
                        "astrid-core",
                        f"path+file://{checkout}/crates/astrid-core#0.0.0",
                        "crates/astrid-core",
                    ),
                    (
                        "astrid",
                        f"path+file://{checkout}/crates/astrid-cli#astrid@0.0.0",
                        "crates/astrid-cli",
                    ),
                ],
            )
            metadata_json = json.dumps(meta)
            calls: list[list[str]] = []

            def produce(command, cwd=None, env=None, stdout=None, stderr=None, text=None,
                        start_new_session=None):
                calls.append(list(command))
                process = MagicMock()
                process.pid = 424242 + len(calls)
                if command[:2] == ["cargo", "metadata"]:
                    process.communicate.return_value = (metadata_json + "\n", "warning: unused\n")
                    process.returncode = 0
                elif command[:2] == ["cargo", "clean"]:
                    process.communicate.return_value = ("Removed 2 packages\n", "")
                    process.returncode = 0
                else:
                    raise AssertionError(command)
                return process

            env = dict(hosted)
            with patch.dict(os.environ, hosted, clear=True), \
                    patch.object(MODULE.subprocess, "Popen", side_effect=produce) as popen:
                receipt = MODULE.prepare(checkout, target, log, env, time.monotonic() + 30)

            self.assertEqual(env["CARGO_TARGET_DIR"], str(target.resolve()))
            self.assertEqual(receipt["package_names"], ["astrid", "astrid-core"])
            self.assertEqual(receipt["clean_exit"], 0)
            self.assertEqual(receipt["metadata_exit"], 0)
            self.assertIn("preserving registry dependencies", receipt["provenance"])
            self.assertEqual(calls[0], ["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"])
            self.assertEqual(calls[1][:5], ["cargo", "clean", "--release", "--target-dir", str(target.resolve())])
            self.assertEqual(calls[1][5:], ["-p", "astrid", "-p", "astrid-core"])
            self.assertTrue(all(call.kwargs.get("start_new_session") for call in popen.call_args_list))
            text = log.read_text(encoding="utf-8")
            self.assertIn(metadata_json, text)
            self.assertIn('"reason": "source-build-metadata"', text)
            self.assertIn('"reason": "source-build-clean"', text)
            self.assertNotIn("serde", receipt["package_names"])

    def test_prepare_timeout_kills_owned_process_group(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            checkout = root / "checkout"
            checkout.mkdir()
            target = root / "cargo-target"
            log = root / "build.jsonl"
            hosted = _ci_env(root)
            process = MagicMock()
            process.pid = 777001
            process.communicate.side_effect = [
                subprocess.TimeoutExpired(["cargo", "metadata"], 0.01),
                ("partial\n", "timed out on stderr\n"),
            ]
            with patch.dict(os.environ, hosted, clear=True), \
                    patch.object(MODULE.subprocess, "Popen", return_value=process), \
                    patch.object(MODULE.os, "killpg") as killpg:
                with self.assertRaises(subprocess.TimeoutExpired):
                    MODULE.prepare(checkout, target, log, dict(hosted), time.monotonic() + 0.05)
                killpg.assert_called_once_with(777001, MODULE.signal.SIGKILL)
            self.assertIn("source-build-timeout", log.read_text(encoding="utf-8"))

    def test_prepare_rejects_duplicate_or_escaped_workspace_package(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            checkout = root / "checkout"
            checkout.mkdir()
            target = root / "cargo-target"
            log = root / "build.jsonl"
            hosted = _ci_env(root)
            outside = root / "outside" / "crate"
            outside.mkdir(parents=True)
            (outside / "Cargo.toml").write_text("[package]\nname=\"escaped\"\n", encoding="utf-8")
            meta = {
                "workspace_root": str(checkout.resolve()),
                "workspace_members": [
                    f"path+file://{outside}#escaped@0.0.0",
                ],
                "packages": [
                    {
                        "name": "escaped",
                        "id": f"path+file://{outside}#escaped@0.0.0",
                        "manifest_path": str((outside / "Cargo.toml").resolve()),
                        "version": "0.0.0",
                    }
                ],
            }

            def produce(command, cwd=None, env=None, stdout=None, stderr=None, text=None,
                        start_new_session=None):
                process = MagicMock()
                process.pid = 888001
                process.communicate.return_value = (json.dumps(meta) + "\n", "")
                process.returncode = 0
                return process

            with patch.dict(os.environ, hosted, clear=True), \
                    patch.object(MODULE.subprocess, "Popen", side_effect=produce):
                with self.assertRaisesRegex(RuntimeError, "escapes checkout"):
                    MODULE.prepare(checkout, target, log, dict(hosted), time.monotonic() + 30)

    def test_verify_artifact_rejects_stale_local_fresh_true(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            checkout = root / "checkout"
            src = checkout / "crates" / "astrid-core" / "src" / "lib.rs"
            src.parent.mkdir(parents=True)
            src.write_text("pub fn f() {}", encoding="utf-8")
            package_id = f"path+file://{checkout}/crates/astrid-core#0.0.0"
            receipt = {
                "checkout": str(checkout.resolve()),
                "package_ids": [package_id],
            }
            event = {
                "reason": "compiler-artifact",
                "package_id": package_id,
                "fresh": True,
                "target": {"name": "astrid_core", "src_path": str(src)},
                "filenames": [str(root / "cargo-target" / "release" / "libastrid_core.rlib")],
            }
            with self.assertRaisesRegex(RuntimeError, "must rebuild after owned target clean"):
                MODULE.verify_artifact(event, checkout, receipt)

    def test_verify_artifact_accepts_rebuilt_local_and_cached_registry(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            checkout = root / "checkout"
            src = checkout / "crates" / "astrid-core" / "src" / "lib.rs"
            src.parent.mkdir(parents=True)
            src.write_text("pub fn f() {}", encoding="utf-8")
            package_id = f"path+file://{checkout}/crates/astrid-core#0.0.0"
            receipt = {
                "checkout": str(checkout.resolve()),
                "package_ids": [package_id],
            }
            local = {
                "reason": "compiler-artifact",
                "package_id": package_id,
                "fresh": False,
                "target": {"name": "astrid_core", "src_path": str(src)},
                "filenames": [str(root / "same.bin")],
            }
            registry = {
                "reason": "compiler-artifact",
                "package_id": "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.0",
                "fresh": True,
                "target": {
                    "name": "serde",
                    "src_path": str(root / "registry" / "serde" / "src" / "lib.rs"),
                },
                "filenames": [str(root / "same.bin")],
            }
            MODULE.verify_artifact(local, checkout, receipt)
            MODULE.verify_artifact(registry, checkout, receipt)

    def test_verify_artifact_rejects_unlisted_local_package(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            checkout = root / "checkout"
            src = checkout / "crates" / "surprise" / "src" / "lib.rs"
            src.parent.mkdir(parents=True)
            src.write_text("pub fn f() {}", encoding="utf-8")
            receipt = {
                "checkout": str(checkout.resolve()),
                "package_ids": [f"path+file://{checkout}/crates/astrid-core#0.0.0"],
            }
            event = {
                "reason": "compiler-artifact",
                "package_id": f"path+file://{checkout}/crates/surprise#0.0.0",
                "fresh": False,
                "target": {"name": "surprise", "src_path": str(src)},
            }
            with self.assertRaisesRegex(RuntimeError, "unlisted local package"):
                MODULE.verify_artifact(event, checkout, receipt)

    def test_verify_artifact_never_uses_binary_hash_inequality(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            checkout = root / "checkout"
            src = checkout / "crates" / "astrid-core" / "src" / "lib.rs"
            src.parent.mkdir(parents=True)
            src.write_text("pub fn f() {}", encoding="utf-8")
            package_id = f"path+file://{checkout}/crates/astrid-core#0.0.0"
            receipt = {
                "checkout": str(checkout.resolve()),
                "package_ids": [package_id],
            }
            # Identical optimized bytes across arms remain acceptable when fresh=False.
            event = {
                "reason": "compiler-artifact",
                "package_id": package_id,
                "fresh": False,
                "target": {"name": "astrid_core", "src_path": str(src)},
                "filenames": [str(root / "identical.bin")],
                "sha256": "0" * 64,
            }
            MODULE.verify_artifact(event, checkout, receipt)


    def test_prepare_keeps_metadata_stdout_json_when_warnings_are_on_stderr(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            checkout = root / "checkout"
            checkout.mkdir()
            target = root / "cargo-target"
            log = root / "build.jsonl"
            hosted = _ci_env(root)
            meta = _metadata(
                checkout,
                [
                    (
                        "astrid-core",
                        f"path+file://{checkout}/crates/astrid-core#0.0.0",
                        "crates/astrid-core",
                    ),
                ],
            )
            metadata_json = json.dumps(meta)

            def produce(command, cwd=None, env=None, stdout=None, stderr=None, text=None,
                        start_new_session=None):
                process = MagicMock()
                process.pid = 515151
                if command[:2] == ["cargo", "metadata"]:
                    # Warnings must not ride on stdout or JSON parsing fails closed.
                    process.communicate.return_value = (
                        metadata_json + "\n",
                        "warning: please specify `--format-version`\n",
                    )
                    process.returncode = 0
                else:
                    process.communicate.return_value = ("Removed\n", "")
                    process.returncode = 0
                return process

            with patch.dict(os.environ, hosted, clear=True), \
                    patch.object(MODULE.subprocess, "Popen", side_effect=produce):
                receipt = MODULE.prepare(checkout, target, log, dict(hosted), time.monotonic() + 30)
            self.assertEqual(receipt["package_names"], ["astrid-core"])
            logged = log.read_text(encoding="utf-8")
            self.assertIn("warning: please specify `--format-version`", logged)
            self.assertIn(metadata_json, logged)

    def test_prepare_fails_closed_when_metadata_stdout_is_not_sole_json(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            checkout = root / "checkout"
            checkout.mkdir()
            target = root / "cargo-target"
            log = root / "build.jsonl"
            hosted = _ci_env(root)
            process = MagicMock()
            process.pid = 616161
            process.returncode = 0
            process.communicate.return_value = (
                "warning: noisy\n{\"workspace_root\": \"x\"}\n",
                "",
            )
            with patch.dict(os.environ, hosted, clear=True), \
                    patch.object(MODULE.subprocess, "Popen", return_value=process):
                with self.assertRaisesRegex(RuntimeError, "single JSON object"):
                    MODULE.prepare(checkout, target, log, dict(hosted), time.monotonic() + 30)

    def test_prepare_fails_closed_on_missing_returncode(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            checkout = root / "checkout"
            checkout.mkdir()
            target = root / "cargo-target"
            log = root / "build.jsonl"
            hosted = _ci_env(root)
            process = MagicMock()
            process.pid = 717171
            process.returncode = None
            process.communicate.return_value = ("{}", "")
            with patch.dict(os.environ, hosted, clear=True), \
                    patch.object(MODULE.subprocess, "Popen", return_value=process):
                with self.assertRaisesRegex(RuntimeError, "without a return code"):
                    MODULE.prepare(checkout, target, log, dict(hosted), time.monotonic() + 30)

    def test_prepare_refuses_symlink_target_leaf(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            checkout = root / "checkout"
            checkout.mkdir()
            real = root / "real-target"
            real.mkdir()
            target = root / "cargo-target"
            target.symlink_to(real)
            log = root / "build.jsonl"
            hosted = _ci_env(root)
            with patch.dict(os.environ, hosted, clear=True), \
                    patch.object(MODULE.subprocess, "Popen") as popen:
                with self.assertRaisesRegex(RuntimeError, "regular directory|symlink"):
                    MODULE.prepare(checkout, target, log, dict(hosted), time.monotonic() + 30)
                popen.assert_not_called()

    def test_prepare_shares_original_deadline_without_inflating_timeout(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            checkout = root / "checkout"
            checkout.mkdir()
            target = root / "cargo-target"
            log = root / "build.jsonl"
            hosted = _ci_env(root)
            meta = _metadata(
                checkout,
                [
                    (
                        "astrid-core",
                        f"path+file://{checkout}/crates/astrid-core#0.0.0",
                        "crates/astrid-core",
                    ),
                ],
            )
            seen_timeouts = []

            def produce(command, cwd=None, env=None, stdout=None, stderr=None, text=None,
                        start_new_session=None):
                process = MagicMock()
                process.pid = 818181

                def communicate(timeout=None):
                    seen_timeouts.append(timeout)
                    if command[:2] == ["cargo", "metadata"]:
                        return json.dumps(meta) + "\n", ""
                    return "Removed\n", ""

                process.communicate.side_effect = communicate
                process.returncode = 0
                return process

            deadline = time.monotonic() + 12
            with patch.dict(os.environ, hosted, clear=True), \
                    patch.object(MODULE.subprocess, "Popen", side_effect=produce):
                MODULE.prepare(checkout, target, log, dict(hosted), deadline)
            self.assertEqual(len(seen_timeouts), 2)
            self.assertLessEqual(seen_timeouts[0], 12)
            self.assertLessEqual(seen_timeouts[1], 12)
            self.assertGreater(seen_timeouts[0], 0)
            self.assertGreater(seen_timeouts[1], 0)
