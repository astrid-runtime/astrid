#!/usr/bin/env python3

from __future__ import annotations

import copy
import hashlib
import pathlib
import tempfile
import unittest
from unittest import mock

import release_manifest


VERSION = "1.2.3"
COMMIT = "a" * 40
CONTRACTS_COMMIT = "b" * 40


class ReleaseManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.artifacts = pathlib.Path(self.temp.name)
        b3_lines = []
        sha_lines = []
        for index, target in enumerate(release_manifest.TARGETS, 1):
            name = release_manifest.expected_asset(VERSION, target)
            (self.artifacts / name).write_bytes(bytes([index]) * index)
            b3_lines.append(f"{index:064x}  {name}")
            sha_lines.append(f"{index + 8:064x}  {name}")
        (self.artifacts / "BLAKE3SUMS.txt").write_text("\n".join(b3_lines) + "\n")
        (self.artifacts / "SHA256SUMS.txt").write_text("\n".join(sha_lines) + "\n")

    def manifest(self) -> dict[str, object]:
        return release_manifest.build_manifest(
            self.artifacts,
            VERSION,
            f"v{VERSION}",
            COMMIT,
            CONTRACTS_COMMIT,
        )

    def test_round_trip_is_deterministic_and_valid(self) -> None:
        rendered = release_manifest.render_manifest(self.manifest())
        path = self.artifacts / "astrid-release.toml"
        path.write_text(rendered)
        loaded = release_manifest.load_manifest(path)
        release_manifest.validate_manifest(loaded, self.artifacts)
        self.assertEqual(release_manifest.render_manifest(loaded), rendered)

    def test_rejects_noncanonical_tag(self) -> None:
        with self.assertRaisesRegex(ValueError, "tag must be"):
            release_manifest.build_manifest(
                self.artifacts,
                VERSION,
                "latest",
                COMMIT,
                CONTRACTS_COMMIT,
            )

    def test_accepts_canonical_prerelease_and_rejects_numeric_leading_zero(self) -> None:
        self.assertEqual(
            release_manifest.canonical_version("1.2.3-nightly.20260716"),
            "1.2.3-nightly.20260716",
        )
        for invalid in ("01.2.3", "1.02.3", "1.2.03", "1.2.3-01"):
            with self.assertRaisesRegex(ValueError, "canonical"):
                release_manifest.canonical_version(invalid)

    def test_nightly_version_must_embed_source_commit(self) -> None:
        version = f"1.2.4-nightly.20260716.g{COMMIT}"
        manifest = self.manifest()
        manifest["version"] = version
        manifest["tag"] = f"v{version}"
        manifest["release-workflow-identity"] = (
            "https://github.com/astrid-runtime/astrid/.github/workflows/"
            f"release.yml@refs/tags/v{version}"
        )
        for target in manifest["targets"]:
            target["asset"] = f"astrid-{version}-{target['triple']}.tar.gz"
            target["sigstore-bundle"] = f"{target['asset']}.sigstore.json"
        release_manifest.validate_manifest(manifest)
        manifest["source-commit"] = "c" * 40
        with self.assertRaisesRegex(ValueError, "embed its source commit"):
            release_manifest.validate_manifest(manifest)
        manifest["source-commit"] = COMMIT
        bad_version = version.replace("20260716", "20260230")
        manifest["version"] = bad_version
        manifest["tag"] = f"v{bad_version}"
        with self.assertRaisesRegex(ValueError, "malformed"):
            release_manifest.validate_manifest(manifest)

    def test_rejects_missing_or_extra_checksum_assets(self) -> None:
        path = self.artifacts / "BLAKE3SUMS.txt"
        path.write_text(path.read_text() + f"{'f' * 64}  extra.tar.gz\n")
        with self.assertRaisesRegex(ValueError, "exactly the four fixed"):
            self.manifest()

    def test_legacy_manifest_shape_is_unchanged_with_combined_checksums(self) -> None:
        legacy = self.manifest()
        legacy_rendered = release_manifest.render_manifest(legacy)
        b3 = self.artifacts / "BLAKE3SUMS.txt"
        sha = self.artifacts / "SHA256SUMS.txt"
        for index, target in enumerate(release_manifest.EXTENSION_TARGETS, 20):
            name = release_manifest.expected_asset(VERSION, target)
            (self.artifacts / name).write_bytes(bytes([index]) * index)
            with b3.open("a") as output:
                output.write(f"{index:064x}  {name}\n")
            with sha.open("a") as output:
                output.write(f"{index + 8:064x}  {name}\n")
        combined = self.manifest()
        self.assertEqual(combined, legacy)
        self.assertEqual(release_manifest.render_manifest(combined), legacy_rendered)
        self.assertEqual(len(combined["targets"]), 4)

    def test_frozen_base_manifest_remains_four_target_v1_for_released_clients(self) -> None:
        manifest = self.manifest()
        self.assertEqual(manifest["schema-version"], 1)
        self.assertEqual(manifest["kind"], "astrid-release")
        self.assertEqual(
            [target["triple"] for target in manifest["targets"]],
            [
                "aarch64-apple-darwin",
                "aarch64-unknown-linux-gnu",
                "x86_64-apple-darwin",
                "x86_64-unknown-linux-gnu",
            ],
        )

    def test_rejects_duplicate_target(self) -> None:
        manifest = self.manifest()
        manifest["targets"][1]["triple"] = manifest["targets"][0]["triple"]
        with self.assertRaisesRegex(ValueError, "target set"):
            release_manifest.validate_manifest(manifest)

    def test_rejects_unknown_fields(self) -> None:
        manifest = copy.deepcopy(self.manifest())
        manifest["latest"] = True
        with self.assertRaisesRegex(ValueError, "root keys differ"):
            release_manifest.validate_manifest(manifest)

    def test_rejects_size_mismatch(self) -> None:
        manifest = self.manifest()
        manifest["targets"][0]["size"] += 1
        with self.assertRaisesRegex(ValueError, "size does not match"):
            release_manifest.validate_manifest(manifest, self.artifacts)

    def test_rejects_same_size_archive_corruption(self) -> None:
        manifest = self.manifest()
        for target in manifest["targets"]:
            path = self.artifacts / target["asset"]
            target["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        first = manifest["targets"][0]
        path = self.artifacts / first["asset"]
        path.write_bytes(b"x" * first["size"])
        with self.assertRaisesRegex(ValueError, "SHA-256 does not match"):
            release_manifest.validate_manifest(
                manifest,
                self.artifacts,
                verify_artifacts=True,
            )

    def test_rejects_missing_sigstore_bundles(self) -> None:
        with self.assertRaisesRegex(ValueError, "Sigstore bundle is missing"):
            release_manifest.validate_manifest(
                self.manifest(),
                self.artifacts,
                require_bundles=True,
            )

    def test_rejects_blake3_mismatch(self) -> None:
        manifest = self.manifest()
        for target in manifest["targets"]:
            path = self.artifacts / target["asset"]
            target["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        with mock.patch.object(release_manifest, "blake3_file", return_value="f" * 64):
            with self.assertRaisesRegex(ValueError, "BLAKE3 does not match"):
                release_manifest.validate_manifest(
                    manifest,
                    self.artifacts,
                    verify_artifacts=True,
                )

    def test_rejects_scalar_type_confusion(self) -> None:
        for value in (True, 1.0):
            manifest = self.manifest()
            manifest["schema-version"] = value
            with self.assertRaisesRegex(ValueError, "identity is invalid"):
                release_manifest.validate_manifest(manifest)
        manifest = self.manifest()
        manifest["source-commit"] = int(COMMIT, 16)
        with self.assertRaisesRegex(ValueError, "must be a string"):
            release_manifest.validate_manifest(manifest)

    def test_checksum_manifest_matches_authenticated_release(self) -> None:
        manifest = self.manifest()
        release_manifest.validate_checksum_manifest(
            manifest,
            self.artifacts / "BLAKE3SUMS.txt",
            "blake3",
        )
        release_manifest.validate_checksum_manifest(
            manifest,
            self.artifacts / "SHA256SUMS.txt",
            "sha256",
        )

    def test_checksum_manifest_rejects_digest_drift(self) -> None:
        manifest = self.manifest()
        checksums = self.artifacts / "BLAKE3SUMS.txt"
        lines = checksums.read_text().splitlines()
        lines[0] = f"{'f' * 64}  {lines[0].split('  ', 1)[1]}"
        checksums.write_text("\n".join(lines) + "\n")
        with self.assertRaisesRegex(ValueError, "authenticated release manifest"):
            release_manifest.validate_checksum_manifest(manifest, checksums, "blake3")


    def _six_archive_artifacts(self) -> dict[str, str]:
        digests: dict[str, str] = {}
        b3_lines: list[str] = []
        sha_lines: list[str] = []
        for index, target in enumerate(
            (*release_manifest.TARGETS, *release_manifest.EXTENSION_TARGETS), 1
        ):
            name = release_manifest.expected_asset(VERSION, target)
            payload = bytes([index]) * index
            (self.artifacts / name).write_bytes(payload)
            digest = f"{index:064x}"
            digests[name] = digest
            b3_lines.append(f"{digest}  {name}")
            sha_lines.append(f"{hashlib.sha256(payload).hexdigest()}  {name}")
        (self.artifacts / "BLAKE3SUMS.txt").write_text("\n".join(b3_lines) + "\n")
        (self.artifacts / "SHA256SUMS.txt").write_text("\n".join(sha_lines) + "\n")
        return digests

    def _workspace_root(self, version: str = VERSION) -> pathlib.Path:
        root = self.artifacts / "workspace-root"
        root.mkdir()
        (root / "Cargo.toml").write_text(
            f'[workspace.package]\nversion = "{version}"\n',
            encoding="utf-8",
        )
        return root

    def test_materialize_writes_manifests_and_github_env(self) -> None:
        digests = self._six_archive_artifacts()
        root = self._workspace_root()
        env_path = self.artifacts / "github.env"
        env_path.write_text("KEEP=1\n", encoding="utf-8")

        def fake_blake3(path: pathlib.Path) -> str:
            if path.name.endswith(".toml"):
                return "c" * 64
            return digests[path.name]

        with mock.patch.object(release_manifest, "blake3_file", side_effect=fake_blake3):
            version = release_manifest.materialize(
                tag=f"v{VERSION}",
                artifacts=self.artifacts,
                source_commit=COMMIT,
                contracts_commit=CONTRACTS_COMMIT,
                github_env=env_path,
                root=root,
            )
        self.assertEqual(version, VERSION)
        legacy = self.artifacts / f"astrid-{VERSION}-release.toml"
        musl = self.artifacts / f"astrid-{VERSION}-musl-release.toml"
        self.assertTrue(legacy.is_file())
        self.assertTrue(musl.is_file())
        env_text = env_path.read_text(encoding="utf-8")
        self.assertIn("KEEP=1\n", env_text)
        self.assertIn(f"VERSION={VERSION}\n", env_text)
        self.assertIn(f"SOURCE_COMMIT={COMMIT}\n", env_text)
        self.assertIn(f"CONTRACTS_COMMIT={CONTRACTS_COMMIT}\n", env_text)
        loaded = release_manifest.load_manifest(legacy)
        self.assertEqual(loaded["version"], VERSION)
        self.assertEqual(len(loaded["targets"]), len(release_manifest.TARGETS))

    def test_materialize_rejects_windows_artifacts(self) -> None:
        self._six_archive_artifacts()
        root = self._workspace_root()
        windows = release_manifest.expected_asset(
            VERSION, release_manifest.WINDOWS_TARGETS[0]
        )
        (self.artifacts / windows).write_bytes(b"windows")
        with self.assertRaisesRegex(ValueError, "rejects Windows"):
            release_manifest.materialize(
                tag=f"v{VERSION}",
                artifacts=self.artifacts,
                source_commit=COMMIT,
                contracts_commit=CONTRACTS_COMMIT,
                github_env=self.artifacts / "github.env",
                root=root,
            )

    def test_reject_windows_metadata_matches_compgen_toml_wildcard(self) -> None:
        # Preserve old ``astrid-*-windows-release.toml*`` semantics: any version
        # and any suffix (including Sigstore bundles) fail closed.
        cases = (
            f"astrid-{VERSION}-windows-release.toml",
            "astrid-0.0.1-windows-release.toml",
            f"astrid-{VERSION}-windows-release.toml.sigstore.json",
            "astrid-9.9.9-windows-release.toml.backup",
        )
        for name in cases:
            with self.subTest(name=name):
                self.assertTrue(release_manifest.is_windows_release_metadata_name(name))
                marker = self.artifacts / name
                marker.write_bytes(b"windows-meta")
                with self.assertRaisesRegex(ValueError, "rejects Windows"):
                    release_manifest.reject_windows_release_artifacts(self.artifacts)
                marker.unlink()
        self.assertFalse(
            release_manifest.is_windows_release_metadata_name(
                f"astrid-{VERSION}-musl-release.toml"
            )
        )
        self.assertFalse(
            release_manifest.is_windows_release_metadata_name(
                "notes-windows-release.toml"
            )
        )

    def test_materialize_rejects_workspace_version_mismatch(self) -> None:
        self._six_archive_artifacts()
        root = self._workspace_root("9.9.9")
        with self.assertRaisesRegex(ValueError, "does not match workspace package version"):
            release_manifest.materialize(
                tag=f"v{VERSION}",
                artifacts=self.artifacts,
                source_commit=COMMIT,
                contracts_commit=CONTRACTS_COMMIT,
                github_env=self.artifacts / "github.env",
                root=root,
            )

    def test_forbidden_windows_release_names_shared_helper(self) -> None:
        windows = release_manifest.expected_asset(
            VERSION, release_manifest.WINDOWS_TARGETS[0]
        )
        names = release_manifest.forbidden_windows_release_names(
            {windows, "keep.tar.gz"},
            {f"astrid-{VERSION}-windows-release.toml"},
            VERSION,
        )
        self.assertEqual(
            names,
            sorted(
                {
                    windows,
                    f"astrid-{VERSION}-windows-release.toml",
                }
            ),
        )



if __name__ == "__main__":
    unittest.main()
