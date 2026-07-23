#!/usr/bin/env python3
"""Generate and validate Astrid's immutable signed release manifest."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import pathlib
import re
import subprocess
import sys
import tomllib


PRODUCT = "astrid-runtime"
REPOSITORY = "astrid-runtime/astrid"
CONTRACTS_REPOSITORY = "astrid-runtime/wit"
TARGETS = (
    "aarch64-apple-darwin",
    "aarch64-unknown-linux-gnu",
    "x86_64-apple-darwin",
    "x86_64-unknown-linux-gnu",
)
MUSL_TARGETS = (
    "aarch64-unknown-linux-musl",
    "x86_64-unknown-linux-musl",
)
ROOT_KEYS = {
    "schema-version",
    "kind",
    "product",
    "repository",
    "version",
    "tag",
    "source-commit",
    "release-workflow-identity",
    "contracts",
    "targets",
}
TARGET_KEYS = {
    "triple",
    "asset",
    "size",
    "blake3",
    "sha256",
    "sigstore-bundle",
}
SEMVER = re.compile(
    r"(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)"
    r"(?:-(?:"
    r"(?:0|[1-9][0-9]*)|"
    r"(?:[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
    r")(?:\.(?:(?:0|[1-9][0-9]*)|(?:[0-9]*[A-Za-z-][0-9A-Za-z-]*)))*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)
NIGHTLY = re.compile(
    r"(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)-nightly\."
    r"[0-9]{8}\.g(?P<commit>[0-9a-f]{40})"
)
HEX_64 = re.compile(r"[0-9a-f]{64}")
COMMIT = re.compile(r"[0-9a-f]{40}")


def fail(message: str) -> "NoReturn":
    raise ValueError(message)


def canonical_version(value: object) -> str:
    if not isinstance(value, str):
        fail("version must be a string")
    if SEMVER.fullmatch(value) is None:
        fail(f"version must be canonical SemVer, got {value!r}")
    return value


def nightly_source_commit(version: str) -> str | None:
    match = NIGHTLY.fullmatch(version)
    if match is None:
        return None
    date = version.rsplit("-nightly.", 1)[1].split(".g", 1)[0]
    try:
        dt.datetime.strptime(date, "%Y%m%d")
    except ValueError:
        return None
    return match.group("commit")


def read_checksums(path: pathlib.Path, label: str) -> dict[str, str]:
    entries: dict[str, str] = {}
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        parts = raw.split("  ")
        if len(parts) != 2 or HEX_64.fullmatch(parts[0]) is None:
            fail(f"{path}:{number}: malformed {label} checksum entry")
        asset = parts[1]
        if not asset or pathlib.PurePosixPath(asset).name != asset or any(ch.isspace() for ch in asset):
            fail(f"{path}:{number}: unsafe asset name {asset!r}")
        if asset in entries:
            fail(f"{path}:{number}: duplicate checksum for {asset}")
        entries[asset] = parts[0]
    return entries


def expected_asset(version: str, target: str) -> str:
    return f"astrid-{version}-{target}.tar.gz"


def validate_release_checksum_names(entries: dict[str, str], version: str, label: str) -> None:
    """Keep the legacy four-target manifest compatible with combined checksums."""
    legacy = {expected_asset(version, target) for target in TARGETS}
    combined = legacy | {expected_asset(version, target) for target in MUSL_TARGETS}
    if set(entries) not in (legacy, combined):
        fail(
            f"{label} must contain exactly the four legacy release archives, "
            "optionally plus the two supported musl archives"
        )


def blake3_file(path: pathlib.Path) -> str:
    try:
        result = subprocess.run(
            ["b3sum", "--", str(path)],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        fail(f"could not compute BLAKE3 for {path.name}: {error}")
    digest = result.stdout.split(maxsplit=1)[0] if result.stdout else ""
    if HEX_64.fullmatch(digest) is None:
        fail(f"b3sum returned a malformed digest for {path.name}")
    return digest


def build_manifest(
    artifacts: pathlib.Path,
    version: str,
    tag: str,
    source_commit: str,
    contracts_commit: str,
) -> dict[str, object]:
    version = canonical_version(version)
    if tag != f"v{version}":
        fail(f"tag must be v{version}, got {tag!r}")
    if COMMIT.fullmatch(source_commit) is None:
        fail("source commit must be 40 lowercase hexadecimal characters")
    nightly_commit = nightly_source_commit(version)
    if "-nightly." in version and nightly_commit is None:
        fail("nightly version is malformed")
    if nightly_commit is not None and nightly_commit != source_commit:
        fail("nightly version must embed its source commit")
    if COMMIT.fullmatch(contracts_commit) is None:
        fail("contracts commit must be 40 lowercase hexadecimal characters")

    blake3 = read_checksums(artifacts / "BLAKE3SUMS.txt", "BLAKE3")
    sha256 = read_checksums(artifacts / "SHA256SUMS.txt", "SHA-256")
    validate_release_checksum_names(blake3, version, "BLAKE3SUMS.txt")
    validate_release_checksum_names(sha256, version, "SHA256SUMS.txt")

    targets: list[dict[str, object]] = []
    for target in TARGETS:
        asset = expected_asset(version, target)
        path = artifacts / asset
        if not path.is_file() or path.is_symlink():
            fail(f"release archive is missing or not a regular file: {asset}")
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
        "kind": "astrid-release",
        "product": PRODUCT,
        "repository": REPOSITORY,
        "version": version,
        "tag": tag,
        "source-commit": source_commit,
        "release-workflow-identity": (
            f"https://github.com/{REPOSITORY}/.github/workflows/release.yml@refs/tags/{tag}"
        ),
        "contracts": {
            "repository": CONTRACTS_REPOSITORY,
            "commit": contracts_commit,
        },
        "targets": targets,
    }


def validate_manifest(
    data: dict[str, object],
    artifacts: pathlib.Path | None = None,
    *,
    verify_artifacts: bool = False,
    require_bundles: bool = False,
) -> None:
    unknown = set(data) - ROOT_KEYS
    missing = ROOT_KEYS - set(data)
    if unknown or missing:
        fail(f"manifest root keys differ: missing={sorted(missing)}, unknown={sorted(unknown)}")
    if (
        type(data["schema-version"]) is not int
        or data["schema-version"] != 1
        or data["kind"] != "astrid-release"
        or data["product"] != PRODUCT
        or data["repository"] != REPOSITORY
    ):
        fail("manifest identity is invalid")
    for key in ("kind", "product", "repository", "tag", "source-commit", "release-workflow-identity"):
        if not isinstance(data[key], str):
            fail(f"manifest {key} must be a string")
    version = canonical_version(data["version"])
    tag = data["tag"]
    if tag != f"v{version}":
        fail("manifest tag does not match its version")
    source_commit = data["source-commit"]
    if COMMIT.fullmatch(source_commit) is None:
        fail("manifest source commit is invalid")
    nightly_commit = nightly_source_commit(version)
    if "-nightly." in version and nightly_commit is None:
        fail("nightly manifest version is malformed")
    if nightly_commit is not None and nightly_commit != source_commit:
        fail("nightly manifest version does not embed its source commit")
    expected_identity = (
        f"https://github.com/{REPOSITORY}/.github/workflows/release.yml@refs/tags/{tag}"
    )
    if data["release-workflow-identity"] != expected_identity:
        fail("manifest release workflow identity is invalid")
    contracts = data["contracts"]
    if not isinstance(contracts, dict) or set(contracts) != {"repository", "commit"}:
        fail("manifest contracts table differs from schema")
    if contracts["repository"] != CONTRACTS_REPOSITORY:
        fail("manifest contracts repository is invalid")
    if not isinstance(contracts["commit"], str) or COMMIT.fullmatch(contracts["commit"]) is None:
        fail("manifest contracts commit is invalid")

    target_entries = data["targets"]
    if not isinstance(target_entries, list) or len(target_entries) != len(TARGETS):
        fail("manifest must contain exactly four target entries")
    seen: set[str] = set()
    for entry in target_entries:
        if not isinstance(entry, dict) or set(entry) != TARGET_KEYS:
            fail("target entry keys differ from schema")
        target = entry["triple"]
        if not isinstance(target, str) or target not in TARGETS or target in seen:
            fail("manifest target set is invalid")
        seen.add(target)
        asset = expected_asset(version, target)
        if not isinstance(entry["asset"], str) or not isinstance(entry["sigstore-bundle"], str):
            fail(f"manifest asset identity must be a string for {target}")
        if entry["asset"] != asset or entry["sigstore-bundle"] != f"{asset}.sigstore.json":
            fail(f"manifest asset identity is invalid for {target}")
        if not isinstance(entry["size"], int) or isinstance(entry["size"], bool) or entry["size"] <= 0:
            fail(f"manifest asset size is invalid for {target}")
        for key in ("blake3", "sha256"):
            value = entry[key]
            if not isinstance(value, str) or HEX_64.fullmatch(value) is None:
                fail(f"manifest {key} digest is invalid for {target}")
        if artifacts is not None:
            path = artifacts / asset
            if not path.is_file() or path.is_symlink() or path.stat().st_size != entry["size"]:
                fail(f"manifest size does not match local archive for {target}")
            if verify_artifacts:
                sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
                if sha256 != entry["sha256"]:
                    fail(f"manifest SHA-256 does not match local archive for {target}")
                if blake3_file(path) != entry["blake3"]:
                    fail(f"manifest BLAKE3 does not match local archive for {target}")
            if require_bundles:
                bundle = artifacts / entry["sigstore-bundle"]
                if not bundle.is_file() or bundle.is_symlink():
                    fail(f"manifest Sigstore bundle is missing for {target}")
    if seen != set(TARGETS):
        fail("manifest target set is incomplete")


def validate_checksum_manifest(
    manifest: dict[str, object],
    checksum_path: pathlib.Path,
    algorithm: str,
) -> None:
    validate_manifest(manifest)
    if algorithm not in {"blake3", "sha256"}:
        fail("checksum algorithm must be blake3 or sha256")
    label = "BLAKE3" if algorithm == "blake3" else "SHA-256"
    actual = read_checksums(checksum_path, label)
    expected = {
        target["asset"]: target[algorithm]
        for target in manifest["targets"]
    }
    validate_release_checksum_names(actual, manifest["version"], checksum_path.name)
    if {asset: actual[asset] for asset in expected} != expected:
        fail(f"{checksum_path.name} does not match the authenticated release manifest")


def toml_string(value: object) -> str:
    text = str(value)
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def render_manifest(data: dict[str, object]) -> str:
    validate_manifest(data)
    lines = [
        f"schema-version = {data['schema-version']}",
        f"kind = {toml_string(data['kind'])}",
        f"product = {toml_string(data['product'])}",
        f"repository = {toml_string(data['repository'])}",
        f"version = {toml_string(data['version'])}",
        f"tag = {toml_string(data['tag'])}",
        f"source-commit = {toml_string(data['source-commit'])}",
        f"release-workflow-identity = {toml_string(data['release-workflow-identity'])}",
        "",
        "[contracts]",
        f"repository = {toml_string(data['contracts']['repository'])}",
        f"commit = {toml_string(data['contracts']['commit'])}",
    ]
    for target in data["targets"]:
        lines.extend(
            [
                "",
                "[[targets]]",
                f"triple = {toml_string(target['triple'])}",
                f"asset = {toml_string(target['asset'])}",
                f"size = {target['size']}",
                f"blake3 = {toml_string(target['blake3'])}",
                f"sha256 = {toml_string(target['sha256'])}",
                f"sigstore-bundle = {toml_string(target['sigstore-bundle'])}",
            ]
        )
    return "\n".join(lines) + "\n"


def load_manifest(path: pathlib.Path) -> dict[str, object]:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        fail(f"could not parse {path}: {error}")
    if not isinstance(data, dict):
        fail("manifest root must be a TOML table")
    return data


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    generate = subparsers.add_parser("generate")
    generate.add_argument("--artifacts", type=pathlib.Path, required=True)
    generate.add_argument("--version", required=True)
    generate.add_argument("--tag", required=True)
    generate.add_argument("--source-commit", required=True)
    generate.add_argument("--contracts-commit", required=True)
    generate.add_argument("--output", type=pathlib.Path, required=True)
    validate = subparsers.add_parser("validate")
    validate.add_argument("manifest", type=pathlib.Path)
    validate.add_argument("--artifacts", type=pathlib.Path)
    validate.add_argument("--verify-artifacts", action="store_true")
    validate.add_argument("--require-bundles", action="store_true")
    validate_checksums = subparsers.add_parser("validate-checksums")
    validate_checksums.add_argument("manifest", type=pathlib.Path)
    validate_checksums.add_argument("checksums", type=pathlib.Path)
    validate_checksums.add_argument("--algorithm", choices=("blake3", "sha256"), required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        if args.command == "generate":
            manifest = build_manifest(
                args.artifacts,
                args.version,
                args.tag,
                args.source_commit,
                args.contracts_commit,
            )
            args.output.write_text(render_manifest(manifest), encoding="utf-8")
        elif args.command == "validate":
            if (args.verify_artifacts or args.require_bundles) and args.artifacts is None:
                fail("--verify-artifacts and --require-bundles require --artifacts")
            validate_manifest(
                load_manifest(args.manifest),
                args.artifacts,
                verify_artifacts=args.verify_artifacts,
                require_bundles=args.require_bundles,
            )
        else:
            validate_checksum_manifest(
                load_manifest(args.manifest),
                args.checksums,
                args.algorithm,
            )
    except (OSError, ValueError) as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
