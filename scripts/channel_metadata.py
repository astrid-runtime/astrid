#!/usr/bin/env python3
"""Render and validate Astrid's signed release-channel pointers."""

from __future__ import annotations

import argparse
import datetime as dt
import pathlib
import re
import subprocess
import sys
import tomllib
from typing import Any

import release_manifest


PRODUCT = "astrid-runtime"
REPOSITORY = "astrid-runtime/astrid"
CHANNELS = ("stable", "dev", "nightly")
MAX_GENERATION = (1 << 63) - 1
MAX_LIFETIMES = {
    "stable": dt.timedelta(days=30),
    "dev": dt.timedelta(days=7),
    "nightly": dt.timedelta(days=2),
}
MAX_FUTURE_SKEW = dt.timedelta(minutes=5)
CHANNEL_ROOT_KEYS = {
    "schema-version",
    "kind",
    "product",
    "repository",
    "channel",
    "generation",
    "published-at",
    "expires-at",
    "release",
    "targets",
}
RELEASE_KEYS = {
    "version",
    "tag",
    "source-commit",
    "metadata-asset",
    "metadata-blake3",
    "release-workflow-identity",
}


def fail(message: str) -> "NoReturn":
    raise ValueError(message)


def exact_table(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{label} must be a TOML table")
    missing = keys - set(value)
    unknown = set(value) - keys
    if missing or unknown:
        fail(f"{label} keys differ: missing={sorted(missing)}, unknown={sorted(unknown)}")
    return value


def string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or "\n" in value or "\r" in value:
        fail(f"{label} must be a non-empty, single-line string")
    return value


def timestamp(value: Any, label: str) -> dt.datetime:
    text = string(value, label)
    if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", text) is None:
        fail(f"{label} must use canonical UTC RFC3339 seconds")
    try:
        return dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as error:
        fail(f"{label} is not a real timestamp: {error}")


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
    if release_manifest.HEX_64.fullmatch(digest) is None:
        fail(f"b3sum returned a malformed digest for {path.name}")
    return digest


def build_channel(
    manifest_path: pathlib.Path,
    channel: str,
    generation: int,
    published_at: str,
    expires_at: str,
) -> dict[str, Any]:
    manifest = release_manifest.load_manifest(manifest_path)
    release_manifest.validate_manifest(manifest)
    if channel not in CHANNELS:
        fail("channel must be stable, dev, or nightly")
    if type(generation) is not int or not 1 <= generation <= MAX_GENERATION:
        fail("channel generation must be an integer from 1 through 2^63-1")
    published = timestamp(published_at, "channel published-at")
    expires = timestamp(expires_at, "channel expires-at")
    if expires <= published:
        fail("channel expires-at must be after published-at")
    if expires - published > MAX_LIFETIMES[channel]:
        fail("channel lifetime exceeds the maximum for its channel")

    return {
        "schema-version": 1,
        "kind": "astrid-channel",
        "product": PRODUCT,
        "repository": REPOSITORY,
        "channel": channel,
        "generation": generation,
        "published-at": published_at,
        "expires-at": expires_at,
        "release": {
            "version": manifest["version"],
            "tag": manifest["tag"],
            "source-commit": manifest["source-commit"],
            "metadata-asset": f"astrid-{manifest['version']}-release.toml",
            "metadata-blake3": blake3_file(manifest_path),
            "release-workflow-identity": manifest["release-workflow-identity"],
        },
        "targets": manifest["targets"],
    }


def validate_channel(
    data: dict[str, Any],
    *,
    expected_channel: str | None = None,
    minimum_generation: int | None = None,
    now: dt.datetime | None = None,
) -> None:
    exact_table(data, CHANNEL_ROOT_KEYS, "channel root")
    if type(data["schema-version"]) is not int or data["schema-version"] != 1:
        fail("channel schema-version must be integer 1")
    for key in ("kind", "product", "repository", "channel", "published-at", "expires-at"):
        string(data[key], f"channel {key}")
    if (
        data["kind"] != "astrid-channel"
        or data["product"] != PRODUCT
        or data["repository"] != REPOSITORY
    ):
        fail("channel identity is invalid")
    channel = data["channel"]
    if channel not in CHANNELS:
        fail("channel must be stable, dev, or nightly")
    if expected_channel is not None and channel != expected_channel:
        fail(f"channel names {channel}, expected {expected_channel}")

    generation = data["generation"]
    if type(generation) is not int or not 1 <= generation <= MAX_GENERATION:
        fail("channel generation must be an integer from 1 through 2^63-1")
    if minimum_generation is not None and generation < minimum_generation:
        fail("channel generation is older than the accepted generation")
    published = timestamp(data["published-at"], "channel published-at")
    expires = timestamp(data["expires-at"], "channel expires-at")
    if expires <= published:
        fail("channel expires-at must be after published-at")
    if expires - published > MAX_LIFETIMES[channel]:
        fail("channel lifetime exceeds the maximum for its channel")
    if now is not None:
        if now.tzinfo is None:
            fail("validation time must be timezone-aware")
        if now > expires:
            fail("channel metadata has expired")
        if published > now + MAX_FUTURE_SKEW:
            fail("channel published-at is unreasonably far in the future")

    release = exact_table(data["release"], RELEASE_KEYS, "channel release")
    for key in RELEASE_KEYS:
        string(release[key], f"channel release {key}")
    version = release_manifest.canonical_version(release["version"])
    nightly = release_manifest.nightly_source_commit(version) is not None
    if channel == "nightly":
        if not nightly:
            fail("nightly channel must point to an exact nightly prerelease")
    elif nightly or "-" in version or "+" in version:
        fail("stable and dev channels must point to canonical releases")
    tag = release["tag"]
    if tag != f"v{version}":
        fail("channel release tag does not match its version")
    if release_manifest.COMMIT.fullmatch(release["source-commit"]) is None:
        fail("channel release source commit is invalid")
    if nightly and release_manifest.nightly_source_commit(version) != release["source-commit"]:
        fail("nightly channel version does not embed its source commit")
    if release["metadata-asset"] != f"astrid-{version}-release.toml":
        fail("channel release metadata asset is not canonical")
    if release_manifest.HEX_64.fullmatch(release["metadata-blake3"]) is None:
        fail("channel release metadata BLAKE3 is invalid")
    expected_identity = (
        f"https://github.com/{REPOSITORY}/.github/workflows/release.yml@refs/tags/{tag}"
    )
    if release["release-workflow-identity"] != expected_identity:
        fail("channel release workflow identity is invalid")

    targets = data["targets"]
    if not isinstance(targets, list) or len(targets) != len(release_manifest.TARGETS):
        fail("channel must contain exactly four target entries")
    manifest_shape = {
        "schema-version": 1,
        "kind": "astrid-release",
        "product": PRODUCT,
        "repository": REPOSITORY,
        "version": version,
        "tag": tag,
        "source-commit": release["source-commit"],
        "release-workflow-identity": release["release-workflow-identity"],
        "contracts": {
            "repository": release_manifest.CONTRACTS_REPOSITORY,
            "commit": "0" * 40,
        },
        "targets": targets,
    }
    release_manifest.validate_manifest(manifest_shape)


def validate_channel_manifest(
    data: dict[str, Any],
    manifest: dict[str, Any],
    manifest_blake3: str,
    *,
    expected_channel: str | None = None,
    expected_generation: int | None = None,
    minimum_generation: int | None = None,
    now: dt.datetime | None = None,
) -> None:
    validate_channel(
        data,
        expected_channel=expected_channel,
        minimum_generation=minimum_generation,
        now=now,
    )
    release_manifest.validate_manifest(manifest)
    if expected_generation is not None and data["generation"] != expected_generation:
        fail(f"channel generation must equal {expected_generation}")
    expected_release = {
        "version": manifest["version"],
        "tag": manifest["tag"],
        "source-commit": manifest["source-commit"],
        "metadata-asset": f"astrid-{manifest['version']}-release.toml",
        "metadata-blake3": manifest_blake3,
        "release-workflow-identity": manifest["release-workflow-identity"],
    }
    if data["release"] != expected_release:
        fail("channel does not identify the authenticated release manifest exactly")
    if data["targets"] != manifest["targets"]:
        fail("channel targets do not match the authenticated release manifest")


def enforce_continuity(candidate: dict[str, Any], previous: dict[str, Any] | None) -> None:
    """Reject rollback and same-generation equivocation for one channel."""
    validate_channel(candidate)
    if previous is None:
        return
    validate_channel(previous, expected_channel=candidate["channel"])
    candidate_generation = candidate["generation"]
    previous_generation = previous["generation"]
    if candidate_generation < previous_generation:
        fail("channel generation rollback rejected")
    if candidate_generation == previous_generation and candidate != previous:
        fail("channel same-generation equivocation rejected")


def quote(value: Any) -> str:
    text = str(value)
    if re.fullmatch(r'[^"\\\r\n]*', text) is None:
        fail("channel strings must not require TOML escaping")
    return f'"{text}"'


def render_channel(data: dict[str, Any]) -> str:
    validate_channel(data)
    release = data["release"]
    lines = [
        f"schema-version = {data['schema-version']}",
        f"kind = {quote(data['kind'])}",
        f"product = {quote(data['product'])}",
        f"repository = {quote(data['repository'])}",
        f"channel = {quote(data['channel'])}",
        f"generation = {data['generation']}",
        f"published-at = {quote(data['published-at'])}",
        f"expires-at = {quote(data['expires-at'])}",
        "",
        "[release]",
    ]
    for key in (
        "version",
        "tag",
        "source-commit",
        "metadata-asset",
        "metadata-blake3",
        "release-workflow-identity",
    ):
        lines.append(f"{key} = {quote(release[key])}")
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


def load(path: pathlib.Path) -> dict[str, Any]:
    try:
        with path.open("rb") as file:
            data = tomllib.load(file)
    except (OSError, tomllib.TOMLDecodeError) as error:
        fail(f"could not parse {path}: {error}")
    if not isinstance(data, dict):
        fail("channel root must be a TOML table")
    return data


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)

    render = commands.add_parser("render")
    render.add_argument("--release-manifest", type=pathlib.Path, required=True)
    render.add_argument("--channel", choices=CHANNELS, required=True)
    render.add_argument("--generation", type=int, required=True)
    render.add_argument("--published-at", required=True)
    render.add_argument("--expires-at", required=True)
    render.add_argument("--output", type=pathlib.Path, required=True)

    validate = commands.add_parser("validate")
    validate.add_argument("channel", type=pathlib.Path)
    validate.add_argument("--expected-channel", choices=CHANNELS)
    validate.add_argument("--minimum-generation", type=int)
    validate.add_argument("--generation", type=int)
    validate.add_argument("--now")
    validate.add_argument("--previous", type=pathlib.Path)
    validate.add_argument("--release-manifest", type=pathlib.Path)
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(sys.argv[1:] if argv is None else argv)
    try:
        if args.command == "render":
            data = build_channel(
                args.release_manifest,
                args.channel,
                args.generation,
                args.published_at,
                args.expires_at,
            )
            args.output.write_text(render_channel(data), encoding="utf-8")
        else:
            now = timestamp(args.now, "--now") if args.now else None
            candidate = load(args.channel)
            if args.release_manifest is None:
                validate_channel(
                    candidate,
                    expected_channel=args.expected_channel,
                    minimum_generation=args.minimum_generation,
                    now=now,
                )
                if args.generation is not None and candidate["generation"] != args.generation:
                    fail(f"channel generation must equal {args.generation}")
            else:
                validate_channel_manifest(
                    candidate,
                    release_manifest.load_manifest(args.release_manifest),
                    blake3_file(args.release_manifest),
                    expected_channel=args.expected_channel,
                    expected_generation=args.generation,
                    minimum_generation=args.minimum_generation,
                    now=now,
                )
            enforce_continuity(candidate, load(args.previous) if args.previous else None)
    except (OSError, ValueError) as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
