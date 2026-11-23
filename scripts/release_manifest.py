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
WINDOWS_TARGETS = ("x86_64-pc-windows-msvc",)
EXTENSION_TARGETS = MUSL_TARGETS
PARKED_WINDOWS_TARGETS = WINDOWS_TARGETS
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


def is_release_candidate(version: str) -> bool:
    return re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)-rc\.[1-9][0-9]*", version) is not None


def validate_channel_version(channel: str, version: str) -> None:
    canonical_version(version)
    if channel == "nightly":
        if nightly_source_commit(version) is None:
            fail("nightly channel must point to an exact nightly prerelease")
    elif channel not in ("stable", "dev"):
        fail("unknown release channel")
    elif "-" in version or "+" in version:
        if channel != "dev" or not is_release_candidate(version):
            fail("stable and dev require canonical releases; only dev permits X.Y.Z-rc.N")


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


def workspace_package_version(root: pathlib.Path) -> str:
    cargo = root / "Cargo.toml"
    try:
        data = tomllib.loads(cargo.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        fail(f"could not parse {cargo}: {error}")
    try:
        value = data["workspace"]["package"]["version"]
    except (KeyError, TypeError) as error:
        fail(f"workspace package version missing in {cargo}: {error}")
    if not isinstance(value, str):
        fail("workspace package version must be a string")
    return canonical_version(value)


def windows_release_markers(version: str) -> set[str]:
    assets = {expected_asset(version, target) for target in WINDOWS_TARGETS}
    markers = {f"astrid-{version}-windows-release.toml", *assets}
    markers |= {f"{name}.sigstore.json" for name in markers}
    return markers


def forbidden_windows_release_names(
    entry_names: set[str], checksum_assets: set[str], version: str
) -> list[str]:
    return sorted((entry_names | checksum_assets) & windows_release_markers(version))


def is_windows_release_metadata_name(name: str) -> bool:
    """Match the old release.yml compgen: astrid-*-windows-release.toml*."""
    return re.fullmatch(r"astrid-.*-windows-release\.toml.*", name) is not None


def reject_windows_release_artifacts(artifacts: pathlib.Path) -> None:
    """Fail closed if Windows archives or metadata appear in a stable candidate.

    Mirrors the release workflow preflight: path globs plus checksum substring.
    The windows-release.toml* glob rejects any version and any suffix
    (including .toml.sigstore.json), matching ``compgen -G ...toml*``.
    """
    if not artifacts.is_dir() or artifacts.is_symlink():
        fail("release artifacts must be a directory")
    names = {path.name for path in artifacts.iterdir()}
    if any("x86_64-pc-windows-msvc" in name for name in names) or any(
        is_windows_release_metadata_name(name) for name in names
    ):
        fail("stable release rejects Windows archives and Windows metadata")
    for checksum_name in ("BLAKE3SUMS.txt", "SHA256SUMS.txt"):
        path = artifacts / checksum_name
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as error:
            fail(f"could not read {path}: {error}")
        if "x86_64-pc-windows-msvc" in text:
            fail("stable release rejects Windows archives and Windows metadata")


def materialize(
    *,
    tag: str,
    artifacts: pathlib.Path,
    source_commit: str,
    contracts_commit: str,
    github_env: pathlib.Path,
    root: pathlib.Path,
) -> str:
    """Generate and validate fixed + musl manifests; append release env exports.

    Imports musl_release_manifest inside the function to avoid an import cycle:
    musl_release_manifest imports this module at load time.
    """
    if not tag.startswith("v"):
        fail(f"tag must start with v, got {tag!r}")
    version = tag[1:]
    cargo_version = workspace_package_version(root)
    if version != cargo_version:
        fail(f"tag version {version} does not match workspace package version {cargo_version}")
    reject_windows_release_artifacts(artifacts)

    manifest = build_manifest(artifacts, version, tag, source_commit, contracts_commit)
    output = artifacts / f"astrid-{version}-release.toml"
    output.write_text(render_manifest(manifest), encoding="utf-8")
    validate_manifest(load_manifest(output), artifacts, verify_artifacts=True)

    import musl_release_manifest  # scoped: musl module imports release_manifest

    musl_output = artifacts / f"astrid-{version}-musl-release.toml"
    musl_data = musl_release_manifest.build_manifest(artifacts, output)
    musl_output.write_text(musl_release_manifest.render_manifest(musl_data), encoding="utf-8")
    musl_release_manifest.validate_manifest(
        musl_release_manifest.load_manifest(musl_output),
        legacy_manifest=load_manifest(output),
        legacy_manifest_blake3=blake3_file(output),
        artifacts=artifacts,
        verify_artifacts=True,
    )

    with github_env.open("a", encoding="utf-8") as env_file:
        env_file.write(f"VERSION={version}\n")
        env_file.write(f"SOURCE_COMMIT={source_commit}\n")
        env_file.write(f"CONTRACTS_COMMIT={contracts_commit}\n")
    return version



def validate_release_checksum_names(entries: dict[str, str], version: str, label: str) -> None:
    """Keep fixed and musl manifests compatible with parked combined checksums."""
    legacy = {expected_asset(version, target) for target in TARGETS}
    musl = legacy | {expected_asset(version, target) for target in EXTENSION_TARGETS}
    parked = musl | {expected_asset(version, target) for target in PARKED_WINDOWS_TARGETS}
    if set(entries) not in (legacy, musl, parked):
        fail(
            f"{label} must contain exactly the four fixed release archives, "
            "optionally plus both musl extension archives, or the parked "
            "seven-archive Windows shape"
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
    materialize_cmd = subparsers.add_parser("materialize")
    materialize_cmd.add_argument("--tag", required=True)
    materialize_cmd.add_argument("--artifacts", type=pathlib.Path, required=True)
    materialize_cmd.add_argument("--source-commit", required=True)
    materialize_cmd.add_argument("--contracts-commit", required=True)
    materialize_cmd.add_argument("--github-env", type=pathlib.Path, required=True)
    materialize_cmd.add_argument("--root", type=pathlib.Path, default=pathlib.Path("."))
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
        elif args.command == "validate-checksums":
            validate_checksum_manifest(
                load_manifest(args.manifest),
                args.checksums,
                args.algorithm,
            )
        elif args.command == "materialize":
            materialize(
                tag=args.tag,
                artifacts=args.artifacts,
                source_commit=args.source_commit,
                contracts_commit=args.contracts_commit,
                github_env=args.github_env,
                root=args.root,
            )
        else:
            fail(f"unsupported command: {args.command}")
    except (OSError, ValueError) as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
