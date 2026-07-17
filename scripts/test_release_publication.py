#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import release_manifest
import release_publication


VERSION = "0.10.0"
SOURCE_COMMIT = "a" * 40
CONTRACTS_COMMIT = "b" * 40


class ReleasePublicationTests(unittest.TestCase):
    def fixture(self, root: Path) -> Path:
        for target in release_manifest.TARGETS:
            name = release_manifest.expected_asset(VERSION, target)
            (root / name).write_bytes(f"archive:{target}".encode())

        sha_lines = []
        blake_lines = []
        for target in release_manifest.TARGETS:
            name = release_manifest.expected_asset(VERSION, target)
            value = (root / name).read_bytes()
            sha_lines.append(f"{hashlib.sha256(value).hexdigest()}  {name}")
            blake_lines.append(f"{hashlib.sha256(b'blake3:' + value).hexdigest()}  {name}")
        (root / "SHA256SUMS.txt").write_text("\n".join(sha_lines) + "\n")
        (root / "BLAKE3SUMS.txt").write_text("\n".join(blake_lines) + "\n")

        with mock.patch.object(
            release_manifest,
            "blake3_file",
            side_effect=lambda path: hashlib.sha256(b"blake3:" + path.read_bytes()).hexdigest(),
        ):
            manifest = release_manifest.build_manifest(
                root,
                VERSION,
                f"v{VERSION}",
                SOURCE_COMMIT,
                CONTRACTS_COMMIT,
            )
        metadata = root / f"astrid-{VERSION}-release.toml"
        metadata.write_text(release_manifest.render_manifest(manifest))
        payloads = [
            *(target["asset"] for target in manifest["targets"]),
            "BLAKE3SUMS.txt",
            "SHA256SUMS.txt",
            metadata.name,
        ]
        for payload in payloads:
            (root / f"{payload}.sigstore.json").write_text("{}\n")
        return metadata

    def validate(self, root: Path) -> list[str]:
        with mock.patch.object(
            release_manifest,
            "blake3_file",
            side_effect=lambda path: hashlib.sha256(b"blake3:" + path.read_bytes()).hexdigest(),
        ):
            return release_publication.validate_release_assets(
                root,
                version=VERSION,
                source_commit=SOURCE_COMMIT,
                contracts_commit=CONTRACTS_COMMIT,
            )

    def test_accepts_exact_complete_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.fixture(root)
            self.assertEqual(len(self.validate(root)), 7)

    def test_rejects_missing_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.fixture(root)
            next(root.glob("*.tar.gz.sigstore.json")).unlink()
            with self.assertRaisesRegex((ValueError, OSError), "missing|asset set"):
                self.validate(root)

    def test_rejects_unexpected_asset(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.fixture(root)
            (root / "unexpected").write_text("no")
            with self.assertRaisesRegex(ValueError, "asset set differs"):
                self.validate(root)

    def test_rejects_changed_archive(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.fixture(root)
            next(root.glob("*.tar.gz")).write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "size|SHA-256|BLAKE3"):
                self.validate(root)

    def test_rejects_wrong_source_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.fixture(root)
            with mock.patch.object(
                release_manifest,
                "blake3_file",
                side_effect=lambda path: hashlib.sha256(b"blake3:" + path.read_bytes()).hexdigest(),
            ):
                with self.assertRaisesRegex(ValueError, "source commit"):
                    release_publication.validate_release_assets(
                        root,
                        version=VERSION,
                        source_commit="c" * 40,
                        contracts_commit=CONTRACTS_COMMIT,
                    )

    def test_rejects_wrong_contracts_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.fixture(root)
            with mock.patch.object(
                release_manifest,
                "blake3_file",
                side_effect=lambda path: hashlib.sha256(b"blake3:" + path.read_bytes()).hexdigest(),
            ):
                with self.assertRaisesRegex(ValueError, "contracts commit"):
                    release_publication.validate_release_assets(
                        root,
                        version=VERSION,
                        source_commit=SOURCE_COMMIT,
                        contracts_commit="c" * 40,
                    )


if __name__ == "__main__":
    unittest.main()
