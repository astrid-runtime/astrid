#!/usr/bin/env python3
"""Generate and validate Astrid's immutable Linux musl metadata extension."""

from __future__ import annotations

import argparse
import hashlib
import pathlib
import sys
import tomllib
from typing import Any

import release_manifest


KIND = "astrid-release-musl-extension"
ROOT_KEYS = {
    "schema-version",
    "kind",
    "product",
    "repository",
    "version",
    "tag",
    "source-commit",
    "release-workflow-identity",
    "legacy-release",
    "targets",
}
LEGACY_RELEASE_KEYS = {"metadata-asset", "metadata-blake3"}


def fail(message: str) -> "NoReturn":
    raise ValueError(message)


def metadata_name(version: str) -> str:
    return f"astrid-{version}-musl-release.toml"


def legacy_metadata_name(version: str) -> str:
    return f"astrid-{version}-release.toml"


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def build_manifest(
    artifacts: pathlib.Path,
    legacy_manifest_path: pathlib.Path,
) -> dict[str, Any]:
    legacy = release_manifest.load_manifest(legacy_manifest_path)
    release_manifest.validate_manifest(legacy)
    version = legacy["version"]
    expected_legacy_name = legacy_metadata_name(version)
    if legacy_manifest_path.name != expected_legacy_name:
        fail(f"legacy release manifest must be named {expected_legacy_name}")

    blake3 = release_manifest.read_checksums(
        artifacts / "BLAKE3SUMS.txt", "BLAKE3"
    )
    sha256 = release_manifest.read_checksums(
        artifacts / "SHA256SUMS.txt", "SHA-256"
    )
    release_manifest.validate_release_checksum_names(
        blake3, version, "BLAKE3SUMS.txt"
    )
    release_manifest.validate_release_checksum_names(
        sha256, version, "SHA256SUMS.txt"
    )
    expected_all = {
        release_manifest.expected_asset(version, target)
        for target in (*release_manifest.TARGETS, *release_manifest.MUSL_TARGETS)
    }
    if set(blake3) != expected_all or set(sha256) != expected_all:
        fail("musl metadata requires checksums for exactly all six release archives")

    targets = []
    for target in release_manifest.MUSL_TARGETS:
        asset = release_manifest.expected_asset(version, target)
        path = artifacts / asset
        if not path.is_file() or path.is_symlink():
            fail(f"musl release archive is missing or not a regular file: {asset}")
        targets.append(
            {
                "triple": target,
                "asset": asset,
                "size": path.stat().st_size,
                "blake3": blake3[asset],
                "sha256": sha256[asset],
                "sigstore-bundle": f"{asset}.sigstore.json",
            }
        )

    return {
        "schema-version": 1,
        "kind": KIND,
        "product": legacy["product"],
        "repository": legacy["repository"],
        "version": version,
        "tag": legacy["tag"],
        "source-commit": legacy["source-commit"],
        "release-workflow-identity": legacy["release-workflow-identity"],
        "legacy-release": {
            "metadata-asset": expected_legacy_name,
            "metadata-blake3": release_manifest.blake3_file(legacy_manifest_path),
        },
        "targets": targets,
    }


def validate_manifest(
    data: dict[str, Any],
    *,
    legacy_manifest: dict[str, Any] | None = None,
    legacy_manifest_blake3: str | None = None,
    artifacts: pathlib.Path | None = None,
    verify_artifacts: bool = False,
    require_bundles: bool = False,
) -> None:
    missing = ROOT_KEYS - set(data)
    unknown = set(data) - ROOT_KEYS
    if missing or unknown:
        fail(
            f"musl manifest root keys differ: missing={sorted(missing)}, "
            f"unknown={sorted(unknown)}"
        )
    if (
        type(data["schema-version"]) is not int
        or data["schema-version"] != 1
        or data["kind"] != KIND
        or data["product"] != release_manifest.PRODUCT
        or data["repository"] != release_manifest.REPOSITORY
    ):
        fail("musl manifest identity is invalid")
    for key in (
        "kind",
        "product",
        "repository",
        "tag",
        "source-commit",
        "release-workflow-identity",
    ):
        if not isinstance(data[key], str):
            fail(f"musl manifest {key} must be a string")
    version = release_manifest.canonical_version(data["version"])
    if data["tag"] != f"v{version}":
        fail("musl manifest tag does not match its version")
    if (
        not isinstance(data["source-commit"], str)
        or release_manifest.COMMIT.fullmatch(data["source-commit"]) is None
    ):
        fail("musl manifest source commit is invalid")
    nightly_commit = release_manifest.nightly_source_commit(version)
    if "-nightly." in version and nightly_commit is None:
        fail("nightly musl manifest version is malformed")
    if nightly_commit is not None and nightly_commit != data["source-commit"]:
        fail("nightly musl manifest version does not embed its source commit")
    expected_identity = (
        f"https://github.com/{release_manifest.REPOSITORY}/.github/workflows/"
        f"release.yml@refs/tags/v{version}"
    )
    if data["release-workflow-identity"] != expected_identity:
        fail("musl manifest release workflow identity is invalid")

    legacy = data["legacy-release"]
    if not isinstance(legacy, dict) or set(legacy) != LEGACY_RELEASE_KEYS:
        fail("musl manifest legacy-release table differs from schema")
    if legacy.get("metadata-asset") != legacy_metadata_name(version):
        fail("musl manifest legacy metadata asset is invalid")
    if (
        not isinstance(legacy.get("metadata-blake3"), str)
        or release_manifest.HEX_64.fullmatch(legacy["metadata-blake3"]) is None
    ):
        fail("musl manifest legacy metadata BLAKE3 is invalid")

    targets = data["targets"]
    if not isinstance(targets, list) or len(targets) != len(
        release_manifest.MUSL_TARGETS
    ):
        fail("musl manifest must contain exactly two target entries")
    seen: set[str] = set()
    for entry in targets:
        if not isinstance(entry, dict) or set(entry) != release_manifest.TARGET_KEYS:
            fail("musl target entry keys differ from schema")
        target = entry["triple"]
        if (
            not isinstance(target, str)
            or target not in release_manifest.MUSL_TARGETS
            or target in seen
        ):
            fail("musl manifest target set is invalid")
        seen.add(target)
        asset = release_manifest.expected_asset(version, target)
        if (
            entry["asset"] != asset
            or entry["sigstore-bundle"] != f"{asset}.sigstore.json"
        ):
            fail(f"musl manifest asset identity is invalid for {target}")
        if (
            type(entry["size"]) is not int
            or entry["size"] <= 0
        ):
            fail(f"musl manifest asset size is invalid for {target}")
        for key in ("blake3", "sha256"):
            value = entry[key]
            if (
                not isinstance(value, str)
                or release_manifest.HEX_64.fullmatch(value) is None
            ):
                fail(f"musl manifest {key} digest is invalid for {target}")
        if artifacts is not None:
            path = artifacts / asset
            if (
                not path.is_file()
                or path.is_symlink()
                or path.stat().st_size != entry["size"]
            ):
                fail(f"musl manifest size does not match local archive for {target}")
            if verify_artifacts:
                if sha256_file(path) != entry["sha256"]:
                    fail(f"musl manifest SHA-256 does not match local archive for {target}")
                if release_manifest.blake3_file(path) != entry["blake3"]:
                    fail(f"musl manifest BLAKE3 does not match local archive for {target}")
            if require_bundles:
                bundle = artifacts / entry["sigstore-bundle"]
                if not bundle.is_file() or bundle.is_symlink():
                    fail(f"musl manifest Sigstore bundle is missing for {target}")
    if seen != set(release_manifest.MUSL_TARGETS):
        fail("musl manifest target set is incomplete")

    if legacy_manifest is not None:
        release_manifest.validate_manifest(legacy_manifest)
        for key in (
            "product",
            "repository",
            "version",
            "tag",
            "source-commit",
            "release-workflow-identity",
        ):
            if data[key] != legacy_manifest[key]:
                fail(f"musl manifest {key} differs from the legacy release")
        if (
            legacy_manifest_blake3 is None
            or legacy["metadata-blake3"] != legacy_manifest_blake3
        ):
            fail("musl manifest does not bind the authenticated legacy release")


def render_manifest(data: dict[str, Any]) -> str:
    validate_manifest(data)
    quote = release_manifest.toml_string
    lines = [
        f"schema-version = {data['schema-version']}",
        f"kind = {quote(data['kind'])}",
        f"product = {quote(data['product'])}",
        f"repository = {quote(data['repository'])}",
        f"version = {quote(data['version'])}",
        f"tag = {quote(data['tag'])}",
        f"source-commit = {quote(data['source-commit'])}",
        f"release-workflow-identity = {quote(data['release-workflow-identity'])}",
        "",
        "[legacy-release]",
        f"metadata-asset = {quote(data['legacy-release']['metadata-asset'])}",
        f"metadata-blake3 = {quote(data['legacy-release']['metadata-blake3'])}",
    ]
    for target in data["targets"]:
        lines.extend(
            [
                "",
                "[[targets]]",
                f"triple = {quote(target['triple'])}",
                f"asset = {quote(target['asset'])}",
                f"size = {target['size']}",
                f"blake3 = {quote(target['blake3'])}",
                f"sha256 = {quote(target['sha256'])}",
                f"sigstore-bundle = {quote(target['sigstore-bundle'])}",
            ]
        )
    return "\n".join(lines) + "\n"


def load_manifest(path: pathlib.Path) -> dict[str, Any]:
    try:
        with path.open("rb") as source:
            data = tomllib.load(source)
    except (OSError, tomllib.TOMLDecodeError) as error:
        fail(f"could not parse {path}: {error}")
    if not isinstance(data, dict):
        fail("musl manifest root must be a TOML table")
    return data


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    generate = commands.add_parser("generate")
    generate.add_argument("--artifacts", type=pathlib.Path, required=True)
    generate.add_argument("--legacy-manifest", type=pathlib.Path, required=True)
    generate.add_argument("--output", type=pathlib.Path, required=True)
    validate = commands.add_parser("validate")
    validate.add_argument("manifest", type=pathlib.Path)
    validate.add_argument("--legacy-manifest", type=pathlib.Path, required=True)
    validate.add_argument("--artifacts", type=pathlib.Path)
    validate.add_argument("--verify-artifacts", action="store_true")
    validate.add_argument("--require-bundles", action="store_true")
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.command == "generate":
        data = build_manifest(args.artifacts, args.legacy_manifest)
        args.output.write_text(render_manifest(data), encoding="utf-8")
        return 0

    if (args.verify_artifacts or args.require_bundles) and args.artifacts is None:
        fail("--verify-artifacts and --require-bundles require --artifacts")
    legacy = release_manifest.load_manifest(args.legacy_manifest)
    legacy_blake3 = release_manifest.blake3_file(args.legacy_manifest)
    validate_manifest(
        load_manifest(args.manifest),
        legacy_manifest=legacy,
        legacy_manifest_blake3=legacy_blake3,
        artifacts=args.artifacts,
        verify_artifacts=args.verify_artifacts,
        require_bundles=args.require_bundles,
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(error, file=sys.stderr)
        raise SystemExit(1)
