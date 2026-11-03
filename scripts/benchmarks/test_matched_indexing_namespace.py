"""Owned-only indexing isolation; no services, daemons, builds or benchmarks."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "indexing_packing", Path(__file__).with_name("matched_volume_packing.py"))
PACKING = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PACKING)
BUILD_SPEC = importlib.util.spec_from_file_location(
    "indexing_build", Path(__file__).parent / "native250/build.py")
BUILD = importlib.util.module_from_spec(BUILD_SPEC)
BUILD_SPEC.loader.exec_module(BUILD)


class NamespaceTests(unittest.TestCase):
    def test_matched_jobs_create_namespace_before_any_checkout_and_use_it_everywhere(self):
        workflow = (Path(__file__).resolve().parents[2] / ".github/workflows/storage-benchmark.yml").read_text()
        for job in ("matched-packing", "matched-native250"):
            body = workflow.split(f"  {job}:", 1)[1].split("\n  matched-", 1)[0]
            with self.subTest(job=job):
                self.assertIn("- name: Create owned unindexed benchmark namespace", body)
                self.assertLess(body.index("- name: Create owned unindexed benchmark namespace"),
                                body.index("- name: Check out benchmark protocol"))
                self.assertIn('mkdir -m 700 "$GITHUB_WORKSPACE/astrid-benchmark.noindex"', body)
                for role in ("protocol", "baseline", "candidate"):
                    self.assertIn(f"path: astrid-benchmark.noindex/{role}", body)
                    self.assertNotIn(f"path: {role}\n", body)
                self.assertNotIn('"$GITHUB_WORKSPACE/baseline"', body)
                self.assertNotIn('"$GITHUB_WORKSPACE/candidate"', body)
                self.assertIn('"$GITHUB_WORKSPACE/astrid-benchmark.noindex/', body)
                evidence = "packing-evidence" if job == "matched-packing" else "native250-evidence"
                self.assertIn(f"path: astrid-benchmark.noindex/{evidence}/public", body)
                for forbidden in ("mdutil", "killall", "launchctl", ".metadata_never_index"):
                    self.assertNotIn(forbidden, body)
        generic = workflow.split("  matched-packing:", 1)[0]
        self.assertNotIn("astrid-benchmark.noindex", generic)

    def test_namespace_is_existing_owned_ancestor_not_a_git_marker(self):
        with tempfile.TemporaryDirectory() as raw:
            workspace = Path(raw).resolve()
            namespace = workspace / "astrid-benchmark.noindex"
            namespace.mkdir(mode=0o700)
            roles = {name: namespace / name for name in ("protocol", "baseline", "candidate", "output")}
            for name in ("protocol", "baseline", "candidate"):
                roles[name].mkdir()
            with patch.dict(os.environ, {"GITHUB_WORKSPACE": str(workspace)}):
                receipt = PACKING.owned_indexing_namespace(**roles)
            self.assertEqual(receipt["root"], str(namespace))
            self.assertEqual(receipt["paths"], {name: str(path) for name, path in roles.items()})
            self.assertFalse(receipt["proves_quiet"])
            self.assertFalse(roles["output"].exists())
            self.assertEqual(list(roles["protocol"].iterdir()), [])
            self.assertEqual(list(roles["baseline"].iterdir()), [])

    def test_missing_redirected_and_outside_namespaces_fail_before_creation(self):
        with tempfile.TemporaryDirectory() as raw:
            workspace = Path(raw).resolve()
            namespace = workspace / "astrid-benchmark.noindex"
            roles = {name: namespace / name for name in ("protocol", "baseline", "candidate", "output")}
            with patch.dict(os.environ, {"GITHUB_WORKSPACE": str(workspace)}):
                with self.assertRaises(RuntimeError): PACKING.owned_indexing_namespace(**roles)
                namespace.mkdir()
                outside = workspace / "outside"
                outside.mkdir()
                changed = {**roles, "candidate": outside}
                with self.assertRaises(RuntimeError): PACKING.owned_indexing_namespace(**changed)
                redirected = namespace / "redirected"
                redirected.symlink_to(outside, target_is_directory=True)
                with self.assertRaises(RuntimeError):
                    PACKING.owned_indexing_namespace(**{**roles, "output": redirected / "evidence"})
            self.assertFalse(roles["output"].exists())

    def test_namespace_preserves_source_build_owned_target_guards(self):
        with tempfile.TemporaryDirectory() as raw:
            workspace = Path(raw).resolve()
            namespace = workspace / "astrid-benchmark.noindex"
            checkout = namespace / "baseline"
            checkout.mkdir(parents=True)
            target = namespace / "packing-evidence/cargo-target"
            child = {"HOME": str(Path.home()), "CARGO_TARGET_DIR": str(target)}
            with patch.dict(os.environ, {"GITHUB_ACTIONS": "true",
                                         "RUNNER_ENVIRONMENT": "github-hosted",
                                         "GITHUB_WORKSPACE": str(workspace)}):
                actual = PACKING.source_build._validate_owned_target(checkout, target, child)
                self.assertEqual(actual, (workspace, checkout, target))
                nested = checkout / "cargo-target"
                with self.assertRaises(RuntimeError):
                    PACKING.source_build._validate_owned_target(
                        checkout, nested, {**child, "CARGO_TARGET_DIR": str(nested)})
                outside = workspace.parent / "cargo-target"
                with self.assertRaises(RuntimeError):
                    PACKING.source_build._validate_owned_target(
                        checkout, outside, {**child, "CARGO_TARGET_DIR": str(outside)})
            self.assertFalse(target.exists())

    def test_short_native_directories_exclude_indexing_and_fit_darwin_socket_path(self):
        path = BUILD.private_run_dir("17-candidate-first_upgrade")
        try:
            self.assertTrue(str(path).startswith("/private/tmp/ast-n250-"))
            self.assertEqual(path.suffix, ".noindex")
            self.assertEqual(path.stat().st_mode & 0o777, 0o700)
            self.assertLess(len(os.fsencode(path / "system.sock")), 104)
        finally:
            path.rmdir()
