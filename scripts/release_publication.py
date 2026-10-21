#!/usr/bin/env python3
"""Authenticate the exact asset contract of an Astrid release candidate."""

from __future__ import annotations

import argparse
import hashlib
import stat
import sys
from pathlib import Path

import release_manifest
import musl_release_manifest


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

    windows_assets = {
        release_manifest.expected_asset(version, target)
        for target in release_manifest.WINDOWS_TARGETS
    }
    windows_markers = {
        f"astrid-{version}-windows-release.toml",
        *windows_assets,
    }
    windows_markers |= {f"{name}.sigstore.json" for name in windows_markers}
    checksum_assets = set(
        release_manifest.read_checksums(
            directory / "BLAKE3SUMS.txt", "BLAKE3"
        )
    ) | set(
        release_manifest.read_checksums(
            directory / "SHA256SUMS.txt", "SHA-256"
        )
    )
    entry_names = {path.name for path in entries}
    forbidden_windows = sorted((entry_names | checksum_assets) & windows_markers)
    require(
        not forbidden_windows,
        f"stable publication rejects Windows release assets: {forbidden_windows}",
    )

    archives = {target["asset"] for target in metadata["targets"]}
    payloads = archives | set(FIXED_PAYLOADS) | {metadata_name}
    extension_contracts = (
        (musl_release_manifest, release_manifest.MUSL_TARGETS),
    )
    extension_metadata = []
    for module, extension_targets in extension_contracts:
        extension_name = module.metadata_name(version)
        extension_archives = {
            release_manifest.expected_asset(version, target)
            for target in extension_targets
        }
        markers = {extension_name, *extension_archives}
        markers |= {f"{name}.sigstore.json" for name in markers}
        if not ((entry_names & markers) or (checksum_assets & extension_archives)):
            continue
        extension_path = directory / extension_name
        extension = module.load_manifest(extension_path)
        module.validate_manifest(
            extension,
            legacy_manifest=metadata,
            legacy_manifest_blake3=release_manifest.blake3_file(metadata_path),
            artifacts=directory,
            verify_artifacts=True,
            require_bundles=True,
        )
        extension_metadata.append(extension)
        payloads |= extension_archives | {extension_name}

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
    targets = list(metadata["targets"])
    if extension_metadata:
        for extension in extension_metadata:
            targets.extend(extension["targets"])
        for algorithm, checksum_name in (
            ("blake3", "BLAKE3SUMS.txt"),
            ("sha256", "SHA256SUMS.txt"),
        ):
            checksums = release_manifest.read_checksums(
                directory / checksum_name,
                "BLAKE3" if algorithm == "blake3" else "SHA-256",
            )
            expected_checksums = {
                target["asset"]: target[algorithm] for target in targets
            }
            require(
                checksums == expected_checksums,
                f"{checksum_name} does not match the combined authenticated release metadata",
            )
    for target in targets:
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
