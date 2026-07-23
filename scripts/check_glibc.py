#!/usr/bin/env python3
"""Reject ELF binaries that require a newer glibc than the release baseline."""

from __future__ import annotations

import argparse
import pathlib
import re
import subprocess


GLIBC_VERSION = re.compile(r"\bGLIBC_(\d+)\.(\d+)(?:\.(\d+))?\b")


def parse_version(value: str) -> tuple[int, ...]:
    parts = value.split(".")
    if len(parts) < 2 or any(not part.isdigit() for part in parts):
        raise ValueError(f"invalid glibc version {value!r}")
    return tuple(int(part) for part in parts)


def required_versions(version_info: str) -> set[tuple[int, ...]]:
    return {
        tuple(int(part) for part in match.groups() if part is not None)
        for match in GLIBC_VERSION.finditer(version_info)
    }


def check_binary(path: pathlib.Path, ceiling: tuple[int, ...]) -> None:
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"binary is missing or not a regular file: {path}")
    try:
        result = subprocess.run(
            ["readelf", "--version-info", "--wide", "--", str(path)],
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as error:
        raise ValueError("readelf is required to validate glibc compatibility") from error
    except subprocess.CalledProcessError as error:
        stderr = error.stderr.strip() if error.stderr else "unknown readelf error"
        raise ValueError(f"could not inspect {path}: {stderr}") from error

    versions = required_versions(result.stdout)
    if versions and max(versions) > ceiling:
        required = ".".join(str(part) for part in max(versions))
        maximum = ".".join(str(part) for part in ceiling)
        raise ValueError(f"{path} requires GLIBC_{required}, newer than GLIBC_{maximum}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-version", required=True)
    parser.add_argument("binary", nargs="+", type=pathlib.Path)
    args = parser.parse_args()

    try:
        ceiling = parse_version(args.max_version)
        for binary in args.binary:
            check_binary(binary, ceiling)
    except ValueError as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
