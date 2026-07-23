#!/usr/bin/env python3

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import release_draft_recovery


class ReleaseDraftRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.candidate = root / "candidate"
        self.existing = root / "existing"
        self.candidate.mkdir()
        self.existing.mkdir()
        self.payloads = ["archive.tar.gz", "SHA256SUMS.txt"]
        for name in self.payloads:
            (self.candidate / name).write_bytes(f"payload:{name}".encode())
            (self.candidate / f"{name}.sigstore.json").write_bytes(
                f"bundle:{name}".encode()
            )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_partial_draft_preserves_existing_and_lists_only_missing_assets(self) -> None:
        (self.existing / "archive.tar.gz").write_bytes(b"payload:archive.tar.gz")
        (self.existing / "archive.tar.gz.sigstore.json").write_bytes(
            b"old-valid-bundle"
        )

        missing, bundles = release_draft_recovery.plan_recovery(
            self.candidate, self.existing, self.payloads
        )

        self.assertEqual(
            missing,
            ["SHA256SUMS.txt", "SHA256SUMS.txt.sigstore.json"],
        )
        self.assertEqual(bundles, ["archive.tar.gz.sigstore.json"])

    def test_rejects_an_existing_payload_with_different_bytes(self) -> None:
        (self.existing / "archive.tar.gz").write_bytes(b"different")

        with self.assertRaisesRegex(ValueError, "payload differs"):
            release_draft_recovery.plan_recovery(
                self.candidate, self.existing, self.payloads
            )

    def test_rejects_an_unexpected_existing_asset(self) -> None:
        (self.existing / "surprise.txt").write_bytes(b"unexpected")

        with self.assertRaisesRegex(ValueError, "unexpected assets"):
            release_draft_recovery.plan_recovery(
                self.candidate, self.existing, self.payloads
            )

    def test_rejects_a_symlink_in_the_existing_draft_directory(self) -> None:
        target = self.candidate / "archive.tar.gz"
        (self.existing / "archive.tar.gz").symlink_to(target)

        with self.assertRaisesRegex(ValueError, "non-regular"):
            release_draft_recovery.plan_recovery(
                self.candidate, self.existing, self.payloads
            )

    def test_recovers_partial_musl_metadata_and_archives_without_replacement(self) -> None:
        musl_payloads = [
            "astrid-1.2.3-musl-release.toml",
            "astrid-1.2.3-aarch64-unknown-linux-musl.tar.gz",
            "astrid-1.2.3-x86_64-unknown-linux-musl.tar.gz",
        ]
        for name in musl_payloads:
            (self.candidate / name).write_bytes(f"payload:{name}".encode())
            (self.candidate / f"{name}.sigstore.json").write_bytes(
                f"bundle:{name}".encode()
            )
        payloads = [*self.payloads, *musl_payloads]
        existing_names = [
            "astrid-1.2.3-musl-release.toml",
            "astrid-1.2.3-musl-release.toml.sigstore.json",
            "astrid-1.2.3-aarch64-unknown-linux-musl.tar.gz",
        ]
        for name in existing_names:
            (self.existing / name).write_bytes((self.candidate / name).read_bytes())

        missing, bundles = release_draft_recovery.plan_recovery(
            self.candidate, self.existing, payloads
        )

        self.assertIn(
            "astrid-1.2.3-aarch64-unknown-linux-musl.tar.gz.sigstore.json",
            missing,
        )
        self.assertIn(
            "astrid-1.2.3-x86_64-unknown-linux-musl.tar.gz",
            missing,
        )
        self.assertEqual(
            bundles,
            ["astrid-1.2.3-musl-release.toml.sigstore.json"],
        )


if __name__ == "__main__":
    unittest.main()
