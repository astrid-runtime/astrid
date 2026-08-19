#!/usr/bin/env python3

from __future__ import annotations

import copy
import hashlib
import pathlib
import tempfile
import unittest
from unittest import mock

import release_manifest
import windows_release_manifest


VERSION = "1.2.3"
COMMIT = "a" * 40
CONTRACTS_COMMIT = "b" * 40


def fake_blake3(path: pathlib.Path) -> str:
    return hashlib.sha256(b"blake3:" + path.read_bytes()).hexdigest()


class WindowsReleaseManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.artifacts = pathlib.Path(self.temp.name)
        b3_lines = []
        sha_lines = []
        for target in (*release_manifest.TARGETS, *release_manifest.EXTENSION_TARGETS):
            name = release_manifest.expected_asset(VERSION, target)
            path = self.artifacts / name
            path.write_bytes(f"archive:{target}".encode())
            b3_lines.append(f"{fake_blake3(path)}  {name}")
            sha_lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {name}")
        (self.artifacts / "BLAKE3SUMS.txt").write_text("\n".join(b3_lines) + "\n")
        (self.artifacts / "SHA256SUMS.txt").write_text("\n".join(sha_lines) + "\n")
        with mock.patch.object(release_manifest, "blake3_file", side_effect=fake_blake3):
            legacy = release_manifest.build_manifest(
                self.artifacts,
                VERSION,
                f"v{VERSION}",
                COMMIT,
                CONTRACTS_COMMIT,
            )
        self.legacy_path = self.artifacts / f"astrid-{VERSION}-release.toml"
        self.legacy_path.write_text(release_manifest.render_manifest(legacy))

    def manifest(self) -> dict[str, object]:
        with mock.patch.object(release_manifest, "blake3_file", side_effect=fake_blake3):
            return windows_release_manifest.build_manifest(
                self.artifacts, self.legacy_path
            )

    def validate_bound(self, manifest: dict[str, object]) -> None:
        windows_release_manifest.validate_manifest(
            manifest,
            legacy_manifest=release_manifest.load_manifest(self.legacy_path),
            legacy_manifest_blake3=fake_blake3(self.legacy_path),
        )

    def test_round_trip_is_deterministic_and_bound_to_legacy_release(self) -> None:
        manifest = self.manifest()
        rendered = windows_release_manifest.render_manifest(manifest)
        path = self.artifacts / windows_release_manifest.metadata_name(VERSION)
        path.write_text(rendered)
        loaded = windows_release_manifest.load_manifest(path)
        self.validate_bound(loaded)
        self.assertEqual(windows_release_manifest.render_manifest(loaded), rendered)

    def test_shared_python_rust_schema_fixture_is_accepted(self) -> None:
        fixture = pathlib.Path(__file__).parent / "fixtures/windows-release-extension.toml"
        manifest = windows_release_manifest.load_manifest(fixture)
        manifest["legacy-release"]["metadata-blake3"] = fake_blake3(self.legacy_path)
        self.validate_bound(manifest)

    def test_accepts_only_the_windows_target(self) -> None:
        manifest = self.manifest()
        self.assertEqual(
            [target["triple"] for target in manifest["targets"]],
            ["x86_64-pc-windows-msvc"],
        )
        self.validate_bound(manifest)

    def test_rejects_missing_duplicate_and_unexpected_targets(self) -> None:
        missing = self.manifest()
        missing["targets"].clear()
        with self.assertRaisesRegex(ValueError, "exactly one"):
            windows_release_manifest.validate_manifest(missing)

        duplicate = self.manifest()
        duplicate["targets"].append(copy.deepcopy(duplicate["targets"][0]))
        with self.assertRaisesRegex(ValueError, "exactly one"):
            windows_release_manifest.validate_manifest(duplicate)

        unexpected = self.manifest()
        unexpected["targets"][0]["triple"] = "x86_64-unknown-linux-gnu"
        with self.assertRaisesRegex(ValueError, "target set"):
            windows_release_manifest.validate_manifest(unexpected)

    def test_rejects_release_identity_and_legacy_binding_mismatches(self) -> None:
        for key, value in (
            ("source-commit", "c" * 40),
            (
                "release-workflow-identity",
                "https://github.com/astrid-runtime/astrid/.github/workflows/release.yml@refs/heads/main",
            ),
        ):
            with self.subTest(key=key):
                manifest = self.manifest()
                manifest[key] = value
                with self.assertRaises(ValueError):
                    self.validate_bound(manifest)

        manifest = self.manifest()
        manifest["legacy-release"]["metadata-blake3"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "bind"):
            self.validate_bound(manifest)

    def test_rejects_partial_seven_archive_checksums(self) -> None:
        lines = (self.artifacts / "BLAKE3SUMS.txt").read_text().splitlines()
        (self.artifacts / "BLAKE3SUMS.txt").write_text("\n".join(lines[:-1]) + "\n")
        with self.assertRaisesRegex(ValueError, "four fixed|all seven"):
            self.manifest()


if __name__ == "__main__":
    unittest.main()
