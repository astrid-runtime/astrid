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

import musl_release_manifest
import release_manifest


VERSION = "1.2.3"
COMMIT = "a" * 40
CONTRACTS_COMMIT = "b" * 40


def fake_blake3(path: pathlib.Path) -> str:
    return hashlib.sha256(b"blake3:" + path.read_bytes()).hexdigest()


class MuslReleaseManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.artifacts = pathlib.Path(self.temp.name)
        b3_lines = []
        sha_lines = []
        for target in (*release_manifest.TARGETS, *release_manifest.MUSL_TARGETS):
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
            return musl_release_manifest.build_manifest(
                self.artifacts, self.legacy_path
            )

    def validate_bound(self, manifest: dict[str, object]) -> None:
        legacy = release_manifest.load_manifest(self.legacy_path)
        musl_release_manifest.validate_manifest(
            manifest,
            legacy_manifest=legacy,
            legacy_manifest_blake3=fake_blake3(self.legacy_path),
        )

    def test_round_trip_is_deterministic_and_bound_to_legacy_release(self) -> None:
        manifest = self.manifest()
        rendered = musl_release_manifest.render_manifest(manifest)
        path = self.artifacts / musl_release_manifest.metadata_name(VERSION)
        path.write_text(rendered)
        loaded = musl_release_manifest.load_manifest(path)
        self.validate_bound(loaded)
        self.assertEqual(musl_release_manifest.render_manifest(loaded), rendered)

    def test_accepts_exactly_the_two_supported_musl_targets(self) -> None:
        manifest = self.manifest()
        self.assertEqual(
            {target["triple"] for target in manifest["targets"]},
            set(release_manifest.MUSL_TARGETS),
        )
        self.validate_bound(manifest)

    def test_rejects_missing_duplicate_and_unexpected_targets(self) -> None:
        missing = self.manifest()
        missing["targets"].pop()
        with self.assertRaisesRegex(ValueError, "exactly two"):
            musl_release_manifest.validate_manifest(missing)

        duplicate = self.manifest()
        duplicate["targets"][1] = copy.deepcopy(duplicate["targets"][0])
        with self.assertRaisesRegex(ValueError, "target set"):
            musl_release_manifest.validate_manifest(duplicate)

        unexpected = self.manifest()
        unexpected["targets"][0]["triple"] = "x86_64-unknown-linux-gnu"
        with self.assertRaisesRegex(ValueError, "target set"):
            musl_release_manifest.validate_manifest(unexpected)

    def test_rejects_every_release_identity_mismatch(self) -> None:
        replacements = {
            "product": "other",
            "repository": "other/repo",
            "version": "1.2.4",
            "tag": "v9.9.9",
            "source-commit": "c" * 40,
            "release-workflow-identity": (
                "https://github.com/astrid-runtime/astrid/.github/workflows/"
                "release.yml@refs/tags/v9.9.9"
            ),
        }
        for key, value in replacements.items():
            with self.subTest(key=key):
                manifest = self.manifest()
                manifest[key] = value
                with self.assertRaises(ValueError):
                    self.validate_bound(manifest)

    def test_rejects_a_different_legacy_manifest_digest_or_asset(self) -> None:
        manifest = self.manifest()
        manifest["legacy-release"]["metadata-blake3"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "bind"):
            self.validate_bound(manifest)

        manifest = self.manifest()
        manifest["legacy-release"]["metadata-asset"] = "other.toml"
        with self.assertRaisesRegex(ValueError, "legacy metadata asset"):
            self.validate_bound(manifest)

    def test_rejects_partial_combined_checksums(self) -> None:
        lines = (self.artifacts / "BLAKE3SUMS.txt").read_text().splitlines()
        (self.artifacts / "BLAKE3SUMS.txt").write_text("\n".join(lines[:-1]) + "\n")
        with self.assertRaisesRegex(ValueError, "four legacy|all six"):
            self.manifest()

    def test_validate_command_requires_and_checks_the_legacy_manifest(self) -> None:
        path = self.artifacts / musl_release_manifest.metadata_name(VERSION)
        path.write_text(musl_release_manifest.render_manifest(self.manifest()))
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                musl_release_manifest.main(["validate", str(path)])
        with mock.patch.object(
            release_manifest, "blake3_file", side_effect=fake_blake3
        ):
            self.assertEqual(
                musl_release_manifest.main(
                    [
                        "validate",
                        str(path),
                        "--legacy-manifest",
                        str(self.legacy_path),
                    ]
                ),
                0,
            )

        manifest = musl_release_manifest.load_manifest(path)
        manifest["legacy-release"]["metadata-blake3"] = "f" * 64
        path.write_text(musl_release_manifest.render_manifest(manifest))
        with mock.patch.object(
            release_manifest, "blake3_file", side_effect=fake_blake3
        ):
            with self.assertRaisesRegex(ValueError, "bind"):
                musl_release_manifest.main(
                    [
                        "validate",
                        str(path),
                        "--legacy-manifest",
                        str(self.legacy_path),
                    ]
                )


if __name__ == "__main__":
    unittest.main()
