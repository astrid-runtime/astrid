#!/usr/bin/env python3
"""Validate Linux and Windows release archive contents before publication."""

from __future__ import annotations

import argparse
import pathlib
import tarfile


MAX_MEMBERS = 20_000
MAX_LOGICAL_BYTES = 2 * 1024 * 1024 * 1024
COMMON = ("astrid", "astrid-daemon", "astrid-build", "astrid-emit")


def fail(message: str) -> None:
    raise ValueError(message)


def required_members(target: str) -> tuple[tuple[str, bool], ...]:
    if target.endswith("-unknown-linux-gnu") or target.endswith("-unknown-linux-musl"):
        return tuple((name, True) for name in COMMON) + (
            ("astrid-storage-provider-fuse", True),
        )
    if target == "x86_64-pc-windows-msvc":
        return tuple((f"{name}.exe", False) for name in COMMON) + (
            ("astrid-storage-provider-winfsp.exe", False),
            ("winfsp-x64.dll", False),
            ("winfsp-2.1.25156.msi", False),
            ("install-windows.ps1", False),
            ("uninstall-windows.ps1", False),
        )
    fail(f"unsupported release archive target: {target}")


def validate(archive_path: pathlib.Path, target: str) -> None:
    if archive_path.is_symlink() or not archive_path.is_file():
        fail(f"release archive is not a regular file: {archive_path}")
    expected_root = archive_path.name.removesuffix(".tar.gz")
    if not expected_root.startswith("astrid-") or not expected_root.endswith(f"-{target}"):
        fail("release archive name does not bind its target")

    logical_bytes = 0
    names: set[str] = set()
    top_names: set[str] = set()
    with tarfile.open(archive_path, mode="r:gz") as archive:
        members = archive.getmembers()
        if len(members) > MAX_MEMBERS:
            fail("release archive contains too many members")
        for member in members:
            name = member.name.rstrip("/") if member.isdir() else member.name
            if not name or name in names:
                fail(f"release archive has a duplicate or empty member: {member.name}")
            names.add(name)
            pure = pathlib.PurePosixPath(name)
            parts = pure.parts
            if not parts or pure.is_absolute() or parts[0] in ("", "..") or ".." in parts:
                fail(f"release archive member escapes its root: {member.name}")
            top_names.add(parts[0])
            logical_bytes += member.size
            if logical_bytes > MAX_LOGICAL_BYTES:
                fail("release archive exceeds its logical-size ceiling")
            if member.issym() or member.islnk() or not (member.isfile() or member.isdir()):
                fail(f"release archive member redirects or is special: {member.name}")

        if top_names != {expected_root}:
            fail("release archive must contain its exact target-bound top-level directory")
        for relative, executable in required_members(target):
            name = f"{expected_root}/{relative}"
            try:
                member = archive.getmember(name)
            except KeyError:
                fail(f"required release member is missing: {name}")
            if not member.isfile() or (executable and member.mode & 0o100 == 0):
                fail(f"required release member is invalid: {name}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=pathlib.Path)
    parser.add_argument("--target", required=True)
    arguments = parser.parse_args(argv)
    try:
        validate(arguments.archive, arguments.target)
    except (OSError, ValueError, tarfile.TarError) as error:
        print(error, file=__import__("sys").stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
