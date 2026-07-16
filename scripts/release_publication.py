#!/usr/bin/env python3
"""Authenticate the exact asset contract of an Astrid release candidate."""

from __future__ import annotations

import argparse
import hashlib
import stat
import sys
from pathlib import Path

import release_manifest


FIXED_PAYLOADS = ("BLAKE3SUMS.txt", "SHA256SUMS.txt")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def validate_release_assets(
    directory: Path,
    *,
    version: str,
    source_commit: str,
    contracts_commit: str,
) -> list[str]:
    require(directory.is_dir() and not directory.is_symlink(), "release assets must be a directory")
    entries = list(directory.iterdir())
    invalid = sorted(
        path.name
        for path in entries
        if path.is_symlink() or not stat.S_ISREG(path.lstat().st_mode)
    )
    require(not invalid, f"release assets contain non-regular entries: {invalid}")
    empty = sorted(path.name for path in entries if path.stat().st_size == 0)
    require(not empty, f"release assets contain empty files: {empty}")

    metadata_name = f"astrid-{version}-release.toml"
    metadata_path = directory / metadata_name
    metadata = release_manifest.load_manifest(metadata_path)
    release_manifest.validate_manifest(
        metadata,
        directory,
        verify_artifacts=True,
        require_bundles=True,
    )
    require(metadata["version"] == version, "release manifest version does not match the tag")
    require(metadata["tag"] == f"v{version}", "release manifest tag does not match the tag")
    require(
        metadata["source-commit"] == source_commit,
        "release manifest source commit does not match the tag commit",
    )
    require(
        metadata["contracts"]["commit"] == contracts_commit,
        "release manifest contracts commit does not match the tagged submodule",
    )

    archives = {target["asset"] for target in metadata["targets"]}
    payloads = archives | set(FIXED_PAYLOADS) | {metadata_name}
    expected = payloads | {f"{name}.sigstore.json" for name in payloads}
    actual = {path.name for path in entries}
    require(
        actual == expected,
        f"release asset set differs; missing={sorted(expected - actual)}, "
        f"unexpected={sorted(actual - expected)}",
    )

    release_manifest.validate_checksum_manifest(
        metadata, directory / "BLAKE3SUMS.txt", "blake3"
    )
    release_manifest.validate_checksum_manifest(
        metadata, directory / "SHA256SUMS.txt", "sha256"
    )
    for target in metadata["targets"]:
        archive = directory / target["asset"]
        require(
            sha256_file(archive) == target["sha256"],
            f"SHA-256 mismatch for {archive.name}",
        )
        require(
            release_manifest.blake3_file(archive) == target["blake3"],
            f"BLAKE3 mismatch for {archive.name}",
        )
    return sorted(payloads)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    root.add_argument("--artifacts", type=Path, required=True)
    root.add_argument("--version", required=True)
    root.add_argument("--source-commit", required=True)
    root.add_argument("--contracts-commit", required=True)
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    for payload in validate_release_assets(
        args.artifacts,
        version=args.version,
        source_commit=args.source_commit,
        contracts_commit=args.contracts_commit,
    ):
        print(payload)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (KeyError, OSError, ValueError) as error:
        print(f"release publication: {error}", file=sys.stderr)
        raise SystemExit(1)
