#!/usr/bin/env python3

from __future__ import annotations

import contextlib
import copy
import hashlib
import io
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
        targets = (
            *release_manifest.TARGETS,
            *release_manifest.MUSL_TARGETS,
            *release_manifest.WINDOWS_TARGETS,
        )
        b3_lines = []
        sha_lines = []
        for target in targets:
            name = release_manifest.expected_asset(VERSION, target)
            path = self.artifacts / name
            path.write_bytes(f"archive:{target}".encode())
            b3_lines.append(f"{fake_blake3(path)}  {name}")
            sha_lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {name}")
        (self.artifacts / "BLAKE3SUMS.txt").write_text(
            "\n".join(b3_lines) + "\n"
        )
        (self.artifacts / "SHA256SUMS.txt").write_text(
            "\n".join(sha_lines) + "\n"
        )
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
        legacy = release_manifest.load_manifest(self.legacy_path)
        windows_release_manifest.validate_manifest(
            manifest,
            legacy_manifest=legacy,
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

    def test_accepts_exactly_both_supported_windows_targets(self) -> None:
        manifest = self.manifest()
        self.assertEqual(
            {target["triple"] for target in manifest["targets"]},
            set(release_manifest.WINDOWS_TARGETS),
        )
        self.validate_bound(manifest)

    def test_rejects_missing_duplicate_and_unexpected_targets(self) -> None:
        missing = self.manifest()
        missing["targets"].pop()
        with self.assertRaisesRegex(ValueError, "exactly two"):
            windows_release_manifest.validate_manifest(missing)

        duplicate = self.manifest()
        duplicate["targets"][1] = copy.deepcopy(duplicate["targets"][0])
        with self.assertRaisesRegex(ValueError, "target set"):
            windows_release_manifest.validate_manifest(duplicate)

        unexpected = self.manifest()
        unexpected["targets"][0]["triple"] = "x86_64-unknown-linux-gnu"
        with self.assertRaisesRegex(ValueError, "target set"):
            windows_release_manifest.validate_manifest(unexpected)

    def test_rejects_release_identity_or_legacy_binding_mismatch(self) -> None:
        for key, value in {
            "product": "other",
            "repository": "other/repo",
            "version": "1.2.4",
            "tag": "v9.9.9",
            "source-commit": "c" * 40,
        }.items():
            with self.subTest(key=key):
                manifest = self.manifest()
                manifest[key] = value
                with self.assertRaises(ValueError):
                    self.validate_bound(manifest)

        manifest = self.manifest()
        manifest["legacy-release"]["metadata-blake3"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "bind"):
            self.validate_bound(manifest)

    def test_rejects_partial_combined_checksums(self) -> None:
        lines = (self.artifacts / "BLAKE3SUMS.txt").read_text().splitlines()
        (self.artifacts / "BLAKE3SUMS.txt").write_text("\n".join(lines[:-1]) + "\n")
        with self.assertRaisesRegex(ValueError, "legacy|all eight"):
            self.manifest()

    def test_validate_command_requires_and_checks_legacy_manifest(self) -> None:
        path = self.artifacts / windows_release_manifest.metadata_name(VERSION)
        path.write_text(windows_release_manifest.render_manifest(self.manifest()))
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                windows_release_manifest.main(["validate", str(path)])
        with mock.patch.object(
            release_manifest, "blake3_file", side_effect=fake_blake3
        ):
            self.assertEqual(
                windows_release_manifest.main(
                    [
                        "validate",
                        str(path),
                        "--legacy-manifest",
                        str(self.legacy_path),
                    ]
                ),
                0,
            )

    def test_release_and_promotion_workflows_publish_authenticated_windows_assets(self) -> None:
        root = pathlib.Path(__file__).resolve().parent.parent
        release_workflow = (root / ".github/workflows/release.yml").read_text()
        for snippet in (
            "target: x86_64-pc-windows-msvc",
            "os: windows-2025",
            "target: aarch64-pc-windows-msvc",
            "os: windows-11-arm",
            'SUFFIX="${{ matrix.exe_suffix }}"',
            "python3 scripts/windows_release_manifest.py generate",
            "python3 scripts/windows_release_manifest.py validate",
        ):
            self.assertIn(snippet, release_workflow)

        promotion_workflow = (
            root / ".github/workflows/promote-channel.yml"
        ).read_text()
        self.assertIn(
            'WINDOWS_METADATA="astrid-${VERSION}-windows-release.toml"',
            promotion_workflow,
        )
        self.assertGreaterEqual(
            promotion_workflow.count(
                "python3 scripts/windows_release_manifest.py validate"
            ),
            2,
        )


if __name__ == "__main__":
    unittest.main()
