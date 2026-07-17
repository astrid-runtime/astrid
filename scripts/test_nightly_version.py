#!/usr/bin/env python3

from __future__ import annotations

import pathlib
import tempfile
import unittest

import nightly_version


COMMIT = "0123456789abcdef0123456789abcdef01234567"
VERSION = f"0.10.0-nightly.20260717.g{COMMIT}"


class NightlyVersionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        (self.root / "release").mkdir()
        (self.root / "crates/astrid-cli").mkdir(parents=True)
        (self.root / "crates/astrid-one").mkdir(parents=True)
        (self.root / "crates/astrid-two").mkdir(parents=True)
        (self.root / "release/nightly.toml").write_text(
            'schema-version = 1\nbase-version = "0.10.0"\n', encoding="utf-8"
        )
        (self.root / "Cargo.toml").write_text(
            '[workspace]\nmembers = ["crates/astrid-cli", "crates/astrid-one", "crates/astrid-two"]\n\n'
            '[workspace.package]\nversion = "0.9.4"\n\n[workspace.dependencies]\n'
            'astrid-one = { path = "crates/astrid-one", version = "0.9.4" }\n'
            'astrid-two = { path = "crates/astrid-two", version = "0.9.4" }\n'
            'unrelated = "0.9.4"\n',
            encoding="utf-8",
        )
        (self.root / "crates/astrid-cli/Cargo.toml").write_text(
            '[package]\nname = "astrid"\nversion.workspace = true\n', encoding="utf-8"
        )
        for name in ("astrid-one", "astrid-two"):
            (self.root / f"crates/{name}/Cargo.toml").write_text(
                f'[package]\nname = "{name}"\nversion.workspace = true\n', encoding="utf-8"
            )
        (self.root / "Cargo.lock").write_text(
            'version = 4\n\n[[package]]\nname = "astrid"\nversion = "0.9.4"\n\n'
            '[[package]]\nname = "astrid-one"\nversion = "0.9.4"\n\n'
            '[[package]]\nname = "astrid-two"\nversion = "0.9.4"\n\n'
            '[[package]]\nname = "external"\nversion = "0.9.4"\nsource = "registry+https://example.invalid"\n',
            encoding="utf-8",
        )

    def test_derivation_is_deterministic(self) -> None:
        self.assertEqual(nightly_version.derive("0.10.0", "20260717", COMMIT), VERSION)
        nightly_version.validate_dispatch_date("20260717", "2026-07-17T23:59:59Z")
        nightly_version.validate_dispatch_date("20260717", "2026-07-18T00:00:01Z")
        with self.assertRaisesRegex(ValueError, "dispatch date"):
            nightly_version.validate_dispatch_date("20991231", "2026-07-17T00:00:00Z")

    def test_stage_updates_only_workspace_versions(self) -> None:
        nightly_version.stage(self.root, VERSION)
        cargo = (self.root / "Cargo.toml").read_text()
        self.assertEqual(cargo.count(VERSION), 3)
        self.assertIn('unrelated = "0.9.4"', cargo)
        lock = (self.root / "Cargo.lock").read_text()
        self.assertEqual(lock.count(VERSION), 3)
        self.assertIn(f'name = "astrid"\nversion = "{VERSION}"', lock)
        self.assertIn('name = "external"\nversion = "0.9.4"', lock)

    def test_rejects_bad_train_and_commit(self) -> None:
        with self.assertRaisesRegex(ValueError, "release/nightly.toml"):
            nightly_version.stage(self.root, f"0.11.0-nightly.20260717.g{COMMIT}")
        with self.assertRaisesRegex(ValueError, "source commit"):
            nightly_version.derive("0.10.0", "20260717", "A" * 40)

    def test_rejects_boolean_schema_version(self) -> None:
        (self.root / "release/nightly.toml").write_text(
            'schema-version = true\nbase-version = "0.10.0"\n', encoding="utf-8"
        )
        with self.assertRaisesRegex(ValueError, "schema-version must be integer 1"):
            nightly_version.base_version(self.root)

    def test_rejects_externalized_workspace_lock_entry(self) -> None:
        lock = self.root / "Cargo.lock"
        lock.write_text(lock.read_text().replace('name = "astrid-one"\nversion = "0.9.4"', 'name = "astrid-one"\nversion = "0.9.4"\nsource = "registry+https://example.invalid"'), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "missing source-less"):
            nightly_version.stage(self.root, VERSION)


if __name__ == "__main__":
    unittest.main()
