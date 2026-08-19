#!/usr/bin/env python3
"""Validate macOS release archive structure before cryptographic publication."""

from __future__ import annotations

import argparse
import pathlib
import tarfile


MAX_MEMBERS = 20_000
MAX_LOGICAL_BYTES = 2 * 1024 * 1024 * 1024


def fail(message: str) -> None:
    raise ValueError(message)


def validate(archive_path: pathlib.Path, mtime: int | None = None) -> None:
    if archive_path.is_symlink() or not archive_path.is_file():
        fail(f"release archive is not a regular file: {archive_path}")
    logical_bytes = 0
    top_names: set[str] = set()
    names: set[str] = set()
    with tarfile.open(archive_path, mode="r:gz") as archive:
        members = archive.getmembers()
        if len(members) > MAX_MEMBERS:
            fail("release archive contains too many members")
        for member in members:
            name = member.name.rstrip("/") if member.isdir() else member.name
            if not name or name in names:
                fail(f"release archive has a duplicate or empty member: {member.name}")
            names.add(name)
            parts = pathlib.PurePosixPath(name).parts
            if (
                not parts
                or pathlib.PurePosixPath(name).is_absolute()
                or parts[0] in ("", "..")
                or ".." in parts
            ):
                fail(f"release archive member escapes its root: {member.name}")
            top_names.add(parts[0])
            logical_bytes += member.size
            if logical_bytes > MAX_LOGICAL_BYTES:
                fail("release archive exceeds its logical-size ceiling")
            if member.issym() or member.islnk() or not (member.isfile() or member.isdir()):
                fail(f"release archive member redirects or is special: {member.name}")
            if member.uid != 0 or member.gid != 0 or member.uname or member.gname:
                fail(f"release archive ownership is not deterministic: {member.name}")
            if mtime is not None and member.mtime != mtime:
                fail(f"release archive timestamp is not deterministic: {member.name}")
            if member.isdir() and member.mode != 0o755:
                fail(f"release archive directory mode is unsafe: {member.name}")
            if member.isfile() and member.mode not in (0o644, 0o755):
                fail(f"release archive file mode is unsafe: {member.name}")

    if len(top_names) != 1:
        fail("release archive must contain exactly one top-level directory")
    root = next(iter(top_names))
    expected = {
        f"{root}/astrid": 0o755,
        f"{root}/astrid-daemon": 0o755,
        f"{root}/astrid-build": 0o755,
        f"{root}/astrid-emit": 0o755,
        f"{root}/astrid-storage-provider-fskit": 0o755,
        f"{root}/macos/manage-macos-fskit.sh": 0o755,
        f"{root}/macos/validate-macos-fskit.sh": 0o755,
        f"{root}/AstridFS.app/Contents/MacOS/AstridFS": 0o755,
        f"{root}/AstridFS.app/Contents/Extensions/AstridFSAppEx.appex/Contents/MacOS/AstridFSAppEx": 0o755,
    }
    with tarfile.open(archive_path, mode="r:gz") as archive:
        for name, mode in expected.items():
            try:
                member = archive.getmember(name)
            except KeyError:
                fail(f"required macOS release member is missing: {name}")
            if not member.isfile() or member.mode != mode:
                fail(f"required macOS release member is missing or non-executable: {name}")
        app_info = archive.getmember(f"{root}/AstridFS.app/Contents/Info.plist")
        extension_info = archive.getmember(
            f"{root}/AstridFS.app/Contents/Extensions/AstridFSAppEx.appex/Contents/Info.plist"
        )
        if not app_info.isfile() or not extension_info.isfile():
            fail("required AstridFS Info.plist members are missing")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=pathlib.Path)
    parser.add_argument("--mtime", type=int)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    arguments = parse_args(argv)
    try:
        validate(arguments.archive, arguments.mtime)
    except (OSError, ValueError, tarfile.TarError) as error:
        print(error, file=__import__("sys").stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
