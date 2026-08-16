#!/usr/bin/env python3

from __future__ import annotations

import pathlib
import importlib.util
import tarfile
import tempfile
import unittest


def load_validator():
    path = pathlib.Path(__file__).with_name("validate_release_archive.py")
    spec = importlib.util.spec_from_file_location("validate_release_archive", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


validator = load_validator()


def write_archive(base: pathlib.Path, target: str) -> pathlib.Path:
    root = base / f"astrid-1.2.3-{target}"
    root.mkdir()
    for relative, executable in validator.required_members(target):
        path = root / relative
        path.write_bytes(relative.encode())
        path.chmod(0o755 if executable else 0o644)
    archive = base / f"{root.name}.tar.gz"
    with tarfile.open(archive, "w:gz") as output:
        output.add(root, arcname=root.name)
    return archive


class ReleaseArchiveValidationTests(unittest.TestCase):
    def test_linux_and_windows_inventories_validate(self) -> None:
        for target in (
            "x86_64-unknown-linux-gnu",
            "aarch64-unknown-linux-musl",
            "x86_64-pc-windows-msvc",
        ):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temporary:
                archive = write_archive(pathlib.Path(temporary), target)
                validator.validate(archive, target)

    def test_missing_provider_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = pathlib.Path(temporary)
            target = "x86_64-unknown-linux-gnu"
            archive = write_archive(base, target)
            root = base / archive.name.removesuffix(".tar.gz")
            (root / "astrid-storage-provider-fuse").unlink()
            with tarfile.open(archive, "w:gz") as output:
                output.add(root, arcname=root.name)
            with self.assertRaisesRegex(ValueError, "provider-fuse"):
                validator.validate(archive, target)

    def test_redirecting_member_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = pathlib.Path(temporary)
            target = "x86_64-pc-windows-msvc"
            archive = write_archive(base, target)
            unsafe = base / f"astrid-unsafe-{target}.tar.gz"
            unsafe_root = unsafe.name.removesuffix(".tar.gz")
            with tarfile.open(archive, "r:gz") as source, tarfile.open(
                unsafe, "w:gz"
            ) as output:
                for member in source.getmembers():
                    renamed = member
                    original_root = archive.name.removesuffix(".tar.gz")
                    renamed.name = member.name.replace(original_root, unsafe_root, 1)
                    output.addfile(
                        renamed,
                        source.extractfile(member) if member.isfile() else None,
                    )
                redirect = tarfile.TarInfo(f"{unsafe_root}/redirect")
                redirect.type = tarfile.SYMTYPE
                redirect.linkname = "../outside"
                output.addfile(redirect)
            with self.assertRaisesRegex(ValueError, "redirects"):
                validator.validate(unsafe, target)


if __name__ == "__main__":
    unittest.main()
