#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import pathlib
import tarfile
import tempfile
import unittest


def load_script(name: str):
    path = pathlib.Path(__file__).with_name(name)
    spec = importlib.util.spec_from_file_location(name.removesuffix(".py"), path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


packager = load_script("package_release_archive.py")
validator = load_script("validate_macos_release.py")


def write_release(root: pathlib.Path) -> None:
    app = root / "AstridFS.app/Contents"
    extension = app / "Extensions/AstridFSAppEx.appex/Contents"
    macos = root / "macos"
    app.mkdir(parents=True)
    extension.mkdir(parents=True)
    macos.mkdir()
    (app / "Info.plist").write_bytes(b"app plist\n")
    (app / "MacOS").mkdir()
    (app / "MacOS/AstridFS").write_bytes(b"app binary\n")
    (app / "MacOS/AstridFS").chmod(0o755)
    (extension / "Info.plist").write_bytes(b"extension plist\n")
    (extension / "MacOS").mkdir()
    (extension / "MacOS/AstridFSAppEx").write_bytes(b"extension binary\n")
    (extension / "MacOS/AstridFSAppEx").chmod(0o755)
    (root / "astrid-storage-provider-fskit").write_bytes(b"provider\n")
    (root / "astrid-storage-provider-fskit").chmod(0o755)
    for name in ("manage-macos-fskit.sh", "validate-macos-fskit.sh"):
        (macos / name).write_bytes(b"#!/bin/sh\n")
        (macos / name).chmod(0o755)


class MacOSReleasePackagingTests(unittest.TestCase):
    def test_package_is_deterministic_and_validates(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = pathlib.Path(temporary)
            root = base / "astrid-1.0.0-aarch64-apple-darwin"
            first = base / "first.tar.gz"
            second = base / "second.tar.gz"
            write_release(root)

            packager.package(root, first, 123456)
            packager.package(root, second, 123456)
            validator.validate(first, 123456)

            self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_packaging_rejects_redirects(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = pathlib.Path(temporary)
            root = base / "release"
            write_release(root)
            target = base / "outside"
            target.write_bytes(b"outside\n")
            (root / "redirect").symlink_to(target)

            with self.assertRaisesRegex(ValueError, "symlink"):
                packager.package(root, base / "release.tar.gz", 123456)

    def test_packaging_rejects_output_inside_the_release_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = pathlib.Path(temporary)
            root = base / "release"
            write_release(root)

            with self.assertRaisesRegex(ValueError, "outside the release root"):
                packager.package(root, root / "inside.tar.gz", 123456)

    def test_validation_rejects_noncanonical_modes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = pathlib.Path(temporary)
            root = base / "release"
            archive = base / "release.tar.gz"
            unsafe = base / "unsafe.tar.gz"
            write_release(root)
            packager.package(root, archive, 123456)
            with tarfile.open(archive, "r:gz") as source, tarfile.open(
                unsafe, "w:gz", format=tarfile.PAX_FORMAT
            ) as target:
                for member in source.getmembers():
                    if member.isfile() and member.name.endswith("Info.plist"):
                        member.mode = 0o777
                    target.addfile(member, source.extractfile(member) if member.isfile() else None)

            with self.assertRaisesRegex(ValueError, "unsafe"):
                validator.validate(unsafe, 123456)


if __name__ == "__main__":
    unittest.main()
