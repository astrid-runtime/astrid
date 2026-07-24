#!/usr/bin/env python3
"""Authenticate and stage an exact Astrid Linux release archive for OCI."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request

import release_manifest


REPOSITORY = "astrid-runtime/astrid"
TARGET = "x86_64-unknown-linux-gnu"
SUPPORTED_TARGETS = (
    TARGET,
    "aarch64-unknown-linux-gnu",
)
ISSUER = "https://token.actions.githubusercontent.com"
COMMIT = re.compile(r"[0-9a-f]{40}")
SAFE_DOWNLOAD_HOSTS = {
    "github.com",
    "release-assets.githubusercontent.com",
    "objects.githubusercontent.com",
}
MAX_API_BYTES = 5 * 1024 * 1024
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_EVIDENCE_BYTES = 5 * 1024 * 1024
REQUIRED_BINARIES = ("astrid", "astrid-daemon", "astrid-build", "astrid-emit")
ALLOWED_RELEASE_FILES = {
    *REQUIRED_BINARIES,
    "LICENSE-APACHE",
    "LICENSE-MIT",
    "README.md",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def bounded_read(response: object, limit: int) -> bytes:
    declared = response.headers.get("Content-Length")
    if declared is not None:
        try:
            declared_size = int(declared)
        except ValueError as error:
            raise ValueError("HTTP response has malformed Content-Length") from error
        require(0 <= declared_size <= limit, "HTTP response exceeds size limit")
    data = response.read(limit + 1)
    require(len(data) <= limit, "HTTP response exceeds size limit")
    return data


def request(url: str, *, token: str | None, accept: str) -> urllib.request.Request:
    headers = {
        "Accept": accept,
        "User-Agent": "astrid-oci-release/1",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return urllib.request.Request(url, headers=headers)


def url_origin(url: str) -> tuple[str, str, int | None]:
    parsed = urllib.parse.urlparse(url)
    return parsed.scheme, parsed.hostname or "", parsed.port


class SafeAssetRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Allow only HTTPS release hosts and never forward credentials cross-origin."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: object,
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> urllib.request.Request | None:
        redirected = urllib.parse.urlparse(newurl)
        require(
            redirected.scheme == "https" and redirected.hostname in SAFE_DOWNLOAD_HOSTS,
            "release asset redirected to an untrusted host",
        )
        redirected_request = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected_request is not None and url_origin(req.full_url) != url_origin(newurl):
            redirected_request.remove_header("Authorization")
            redirected_request.remove_header("Proxy-Authorization")
        return redirected_request


def fetch_release(version: str, token: str | None) -> dict[str, object]:
    tag = f"v{version}"
    url = f"https://api.github.com/repos/{REPOSITORY}/releases/tags/{tag}"
    with urllib.request.urlopen(
        request(url, token=token, accept="application/vnd.github+json"),
        timeout=30,
    ) as response:
        payload = bounded_read(response, MAX_API_BYTES)
    try:
        release = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("GitHub release response is not valid JSON") from error
    require(isinstance(release, dict), "GitHub release response must be an object")
    validate_release(release, version)
    return release


def validate_release(release: dict[str, object], version: str) -> None:
    require(release.get("tag_name") == f"v{version}", "GitHub release tag is not exact")
    require(release.get("draft") is False, "GitHub release is a draft")
    require(release.get("immutable") is True, "GitHub immutable releases are not enabled")
    assets = release.get("assets")
    require(isinstance(assets, list), "GitHub release assets must be a list")
    names: list[str] = []
    for asset in assets:
        require(isinstance(asset, dict), "GitHub release asset must be an object")
        name = asset.get("name")
        require(
            isinstance(name, str)
            and pathlib.PurePosixPath(name).name == name
            and not any(character.isspace() for character in name),
            "GitHub release asset has an unsafe name",
        )
        names.append(name)
        require(asset.get("state") == "uploaded", f"release asset is not uploaded: {name}")
        size = asset.get("size")
        require(
            isinstance(size, int) and not isinstance(size, bool) and size > 0,
            f"release asset has invalid size: {name}",
        )
    require(len(names) == len(set(names)), "GitHub release contains duplicate asset names")


def asset_map(release: dict[str, object]) -> dict[str, dict[str, object]]:
    return {asset["name"]: asset for asset in release["assets"]}


def download_asset(
    asset: dict[str, object],
    destination: pathlib.Path,
    *,
    token: str | None,
    max_bytes: int,
) -> None:
    name = asset["name"]
    url = asset.get("browser_download_url")
    size = asset["size"]
    digest = asset.get("digest")
    require(isinstance(url, str), f"release asset has no download URL: {name}")
    parsed = urllib.parse.urlparse(url)
    require(
        parsed.scheme == "https"
        and parsed.hostname == "github.com"
        and parsed.path
        == f"/{REPOSITORY}/releases/download/"
        f"{urllib.parse.quote('v' + destination.parent.name, safe='')}/{name}",
        f"release asset has unexpected download URL: {name}",
    )
    require(size <= max_bytes, f"release asset exceeds size limit: {name}")
    require(
        isinstance(digest, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is not None,
        f"release asset has no canonical SHA-256 digest: {name}",
    )

    opener = urllib.request.build_opener(SafeAssetRedirectHandler())
    with opener.open(request(url, token=token, accept="application/octet-stream"), timeout=60) as response:
        final = urllib.parse.urlparse(response.geturl())
        require(
            final.scheme == "https" and final.hostname in SAFE_DOWNLOAD_HOSTS,
            f"release asset redirected to an untrusted host: {name}",
        )
        declared = response.headers.get("Content-Length")
        if declared is not None:
            try:
                declared_size = int(declared)
            except ValueError as error:
                raise ValueError(f"asset has malformed Content-Length: {name}") from error
            require(declared_size == size, f"asset Content-Length differs from GitHub metadata: {name}")
        digest_state = hashlib.sha256()
        written = 0
        with destination.open("xb") as output:
            while chunk := response.read(1024 * 1024):
                written += len(chunk)
                require(written <= size and written <= max_bytes, f"asset exceeds declared size: {name}")
                digest_state.update(chunk)
                output.write(chunk)
    require(written == size, f"asset size differs from GitHub metadata: {name}")
    require(f"sha256:{digest_state.hexdigest()}" == digest, f"asset SHA-256 differs from GitHub metadata: {name}")


def verify_sigstore(payload: pathlib.Path, bundle: pathlib.Path, *, identity: str) -> None:
    try:
        subprocess.run(
            [
                "cosign",
                "verify-blob",
                "--bundle",
                str(bundle),
                "--certificate-identity",
                identity,
                "--certificate-oidc-issuer",
                ISSUER,
                "--use-signed-timestamps",
                str(payload),
            ],
            check=True,
        )
    except FileNotFoundError as error:
        raise ValueError("cosign is required to authenticate Astrid release assets") from error
    except subprocess.CalledProcessError as error:
        raise ValueError(f"Sigstore verification failed for {payload.name}") from error


def find_target(
    manifest: dict[str, object],
    version: str,
    source_commit: str,
    *,
    target: str = TARGET,
) -> dict[str, object]:
    release_manifest.validate_manifest(manifest)
    require(manifest["version"] == version, "release manifest version differs from requested version")
    require(manifest["tag"] == f"v{version}", "release manifest tag differs from requested version")
    require(
        manifest["source-commit"] == source_commit,
        "release manifest source commit differs from requested commit",
    )
    require(target in SUPPORTED_TARGETS, f"unsupported OCI release target: {target}")
    matches = [entry for entry in manifest["targets"] if entry["triple"] == target]
    require(len(matches) == 1, f"release manifest has no unique {target} target")
    return matches[0]


def verify_archive_structure(
    path: pathlib.Path,
    version: str,
    *,
    target: str = TARGET,
) -> None:
    require(target in SUPPORTED_TARGETS, f"unsupported OCI release target: {target}")
    expected_root = f"astrid-{version}-{target}"
    seen: set[str] = set()
    try:
        with tarfile.open(path, mode="r:gz") as archive:
            members = archive.getmembers()
    except (OSError, tarfile.TarError) as error:
        raise ValueError("release archive is not a valid gzip-compressed tar") from error
    require(1 <= len(members) <= 16, "release archive has an unexpected member count")
    for member in members:
        # GNU tar records an explicitly archived directory as `root/`, while
        # Python-created fixtures commonly spell the same member as `root`.
        # Normalize exactly one directory marker before applying the canonical
        # root and duplicate checks; `root//` remains invalid.
        canonical_name = (
            member.name[:-1] if member.isdir() and member.name.endswith("/") else member.name
        )
        pure = pathlib.PurePosixPath(canonical_name)
        require(
            not pure.is_absolute() and ".." not in pure.parts and pure.parts,
            f"release archive has unsafe path: {member.name}",
        )
        require(canonical_name not in seen, f"release archive has duplicate path: {member.name}")
        seen.add(canonical_name)
        require(member.mode & 0o7000 == 0, f"release archive has special permission bits: {member.name}")
        if canonical_name == expected_root:
            require(member.isdir(), "release archive root is not a directory")
            continue
        require(
            len(pure.parts) == 2 and pure.parts[0] == expected_root,
            f"release archive escapes its canonical root: {member.name}",
        )
        require(member.isreg(), f"release archive contains a non-regular member: {member.name}")
        require(pure.parts[1] in ALLOWED_RELEASE_FILES, f"release archive has unexpected file: {member.name}")
        require(member.size > 0, f"release archive has empty file: {member.name}")
    for binary in REQUIRED_BINARIES:
        name = f"{expected_root}/{binary}"
        require(name in seen, f"release archive is missing required binary: {binary}")
        member = next(candidate for candidate in members if candidate.name == name)
        require(member.mode & 0o111 != 0, f"release archive binary is not executable: {binary}")


def require_asset(
    assets: dict[str, dict[str, object]],
    name: str,
) -> dict[str, object]:
    require(name in assets, f"GitHub release is missing asset: {name}")
    return assets[name]


def stage_release(
    version: str,
    source_commit: str,
    output: pathlib.Path,
    *,
    token: str | None,
    target: str = TARGET,
) -> None:
    version = release_manifest.canonical_version(version)
    require(COMMIT.fullmatch(source_commit) is not None, "source commit must be 40 lowercase hexadecimal characters")
    require(target in SUPPORTED_TARGETS, f"unsupported OCI release target: {target}")
    require(
        not output.exists() or (output.is_dir() and not output.is_symlink() and not any(output.iterdir())),
        "output directory must be absent or empty",
    )
    output.mkdir(parents=True, exist_ok=True)

    release = fetch_release(version, token)
    assets = asset_map(release)
    manifest_name = f"astrid-{version}-release.toml"
    manifest_bundle_name = f"{manifest_name}.sigstore.json"
    identity = (
        f"https://github.com/{REPOSITORY}/.github/workflows/release.yml@refs/tags/v{version}"
    )

    with tempfile.TemporaryDirectory(prefix="astrid-oci-release-") as temporary:
        staging = pathlib.Path(temporary) / version
        staging.mkdir()
        manifest_path = staging / manifest_name
        manifest_bundle = staging / manifest_bundle_name
        download_asset(
            require_asset(assets, manifest_name),
            manifest_path,
            token=token,
            max_bytes=MAX_EVIDENCE_BYTES,
        )
        download_asset(
            require_asset(assets, manifest_bundle_name),
            manifest_bundle,
            token=token,
            max_bytes=MAX_EVIDENCE_BYTES,
        )
        verify_sigstore(manifest_path, manifest_bundle, identity=identity)

        manifest = release_manifest.load_manifest(manifest_path)
        target_entry = find_target(
            manifest,
            version,
            source_commit,
            target=target,
        )
        archive_name = target_entry["asset"]
        archive_bundle_name = target_entry["sigstore-bundle"]
        archive_asset = require_asset(assets, archive_name)
        require(
            archive_asset["size"] == target_entry["size"],
            "archive size differs between GitHub and signed release manifest",
        )
        require(
            archive_asset["digest"] == f"sha256:{target_entry['sha256']}",
            "archive SHA-256 differs between GitHub and signed release manifest",
        )

        archive_path = staging / archive_name
        archive_bundle = staging / archive_bundle_name
        download_asset(
            archive_asset,
            archive_path,
            token=token,
            max_bytes=MAX_ARCHIVE_BYTES,
        )
        download_asset(
            require_asset(assets, archive_bundle_name),
            archive_bundle,
            token=token,
            max_bytes=MAX_EVIDENCE_BYTES,
        )
        verify_sigstore(archive_path, archive_bundle, identity=identity)
        require(
            sha256_file(archive_path) == target_entry["sha256"],
            "archive SHA-256 differs from signed manifest",
        )
        require(
            release_manifest.blake3_file(archive_path) == target_entry["blake3"],
            "archive BLAKE3 differs from signed manifest",
        )
        verify_archive_structure(archive_path, version, target=target)

        manifest_sha256 = sha256_file(manifest_path)
        receipt = {
            "schema-version": 1,
            "repository": REPOSITORY,
            "version": version,
            "tag": f"v{version}",
            "source-commit": source_commit,
            "target": target,
            "archive": archive_name,
            "archive-size": target_entry["size"],
            "archive-sha256": target_entry["sha256"],
            "archive-blake3": target_entry["blake3"],
            "release-manifest": manifest_name,
            "release-manifest-sha256": manifest_sha256,
            "release-workflow-identity": identity,
            "certificate-oidc-issuer": ISSUER,
        }
        shutil.copyfile(archive_path, output / "astrid-release.tar.gz")
        (output / "release-receipt.json").write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    fetch = subparsers.add_parser("fetch")
    fetch.add_argument("--version", required=True)
    fetch.add_argument("--source-commit", required=True)
    fetch.add_argument(
        "--target",
        choices=SUPPORTED_TARGETS,
        default=TARGET,
        help=f"release target triple (default: {TARGET})",
    )
    fetch.add_argument("--output", type=pathlib.Path, required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.command == "fetch":
        stage_release(
            args.version,
            args.source_commit,
            args.output,
            token=os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN"),
            target=args.target,
        )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (KeyError, OSError, ValueError, urllib.error.URLError) as error:
        print(f"oci release: {error}", file=sys.stderr)
        raise SystemExit(1)
