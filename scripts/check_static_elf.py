#!/usr/bin/env python3
"""Validate a statically linked ELF release binary for the expected machine."""

from __future__ import annotations

import argparse
import pathlib
import re
import subprocess


MACHINES = {
    "x86_64": "Advanced Micro Devices X86-64",
    "aarch64": "AArch64",
}
GLIBC_SYMBOL_VERSION = re.compile(r"\bGLIBC_[A-Za-z0-9_.]+")


def validate_readelf(
    architecture: str,
    file_header: str,
    program_headers: str,
    dynamic_section: str,
    version_info: str,
) -> None:
    expected = MACHINES.get(architecture)
    if expected is None:
        raise ValueError(f"unsupported ELF architecture {architecture!r}")
    machine = next(
        (
            line.split(":", 1)[1].strip()
            for line in file_header.splitlines()
            if line.lstrip().startswith("Machine:")
        ),
        None,
    )
    if machine != expected:
        raise ValueError(
            f"ELF machine is {machine or 'missing'}, expected {expected}"
        )
    if any(line.split()[:1] == ["INTERP"] for line in program_headers.splitlines()):
        raise ValueError("ELF has a program interpreter and is not static")
    if "(NEEDED)" in dynamic_section:
        raise ValueError("ELF has dynamic shared-library dependencies")
    if GLIBC_SYMBOL_VERSION.search(version_info):
        raise ValueError("ELF contains a glibc symbol-version requirement")


def readelf(path: pathlib.Path, *arguments: str) -> str:
    try:
        result = subprocess.run(
            ["readelf", *arguments, "--wide", "--", str(path)],
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as error:
        raise ValueError("readelf is required to validate static ELF binaries") from error
    except subprocess.CalledProcessError as error:
        stderr = error.stderr.strip() if error.stderr else "unknown readelf error"
        raise ValueError(f"could not inspect {path}: {stderr}") from error
    return result.stdout


def check_binary(path: pathlib.Path, architecture: str) -> None:
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"binary is missing or not a regular file: {path}")
    validate_readelf(
        architecture,
        readelf(path, "--file-header"),
        readelf(path, "--program-headers"),
        readelf(path, "--dynamic"),
        readelf(path, "--version-info"),
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--architecture", choices=sorted(MACHINES), required=True)
    parser.add_argument("binary", nargs="+", type=pathlib.Path)
    args = parser.parse_args()

    try:
        for binary in args.binary:
            check_binary(binary, args.architecture)
    except ValueError as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
