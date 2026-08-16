#!/usr/bin/env python3
"""Create a deterministic release archive without redirecting members."""

from __future__ import annotations

import argparse
import gzip
import os
import pathlib
import stat
import tarfile
import tempfile


def normalized_mode(path: pathlib.Path, *, is_dir: bool) -> int:
    if is_dir:
        return 0o755
    return 0o755 if os.access(path, os.X_OK) else 0o644


def safe_members(root: pathlib.Path) -> list[tuple[pathlib.Path, str, bool]]:
    members: list[tuple[pathlib.Path, str, bool]] = [(root, root.name, True)]
    for current, directories, files in os.walk(root, topdown=True, followlinks=False):
        directories.sort()
        files.sort()
        current_path = pathlib.Path(current)
        for name in directories + files:
            path = current_path / name
            relative = path.relative_to(root).as_posix()
            metadata = path.lstat()
            mode = metadata.st_mode
            if stat.S_ISLNK(mode):
                raise ValueError(f"release archive member is a symlink: {relative}")
            if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
                raise ValueError(f"release archive member is not a regular file: {relative}")
            if stat.S_ISREG(mode) and metadata.st_nlink != 1:
                raise ValueError(f"release archive member has multiple links: {relative}")
            members.append((path, f"{root.name}/{relative}", stat.S_ISDIR(mode)))
    return members


def package(root: pathlib.Path, output: pathlib.Path, mtime: int) -> None:
    if not root.is_dir() or root.is_symlink():
        raise ValueError(f"release root is not a real directory: {root}")
    if mtime < 0:
        raise ValueError("release archive mtime must be nonnegative")
    resolved_output = output.resolve(strict=False)
    resolved_root = root.resolve(strict=True)
    if resolved_output == resolved_root or resolved_output.is_relative_to(resolved_root):
        raise ValueError("release archive output must be outside the release root")
    members = safe_members(root)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="wb", dir=output.parent, prefix=f".{output.name}.", delete=False
    ) as temporary:
        temporary_path = pathlib.Path(temporary.name)
        with gzip.GzipFile(filename="", mode="wb", fileobj=temporary, mtime=0) as compressed:
            with tarfile.open(
                mode="w", format=tarfile.PAX_FORMAT, fileobj=compressed
            ) as archive:
                for path, name, is_dir in members:
                    info = tarfile.TarInfo(name=name)
                    info.mode = normalized_mode(path, is_dir=is_dir)
                    info.mtime = mtime
                    info.uid = 0
                    info.gid = 0
                    info.uname = ""
                    info.gname = ""
                    if is_dir:
                        info.type = tarfile.DIRTYPE
                        info.size = 0
                        archive.addfile(info)
                    else:
                        info.size = path.stat().st_size
                        with path.open("rb") as source:
                            archive.addfile(info, source)
        os.replace(temporary_path, output)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--mtime", type=int, required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    arguments = parse_args(argv)
    try:
        package(arguments.root, arguments.output, arguments.mtime)
    except (OSError, ValueError) as error:
        print(error, file=__import__("sys").stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
