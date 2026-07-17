#!/usr/bin/env python3
"""Derive and stage deterministic Astrid nightly versions."""

from __future__ import annotations

import argparse
import datetime as dt
import re
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SEMVER = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)")
NIGHTLY = re.compile(
    rf"(?P<base>{SEMVER.pattern})-nightly\.(?P<date>[0-9]{{8}})\.g(?P<commit>[0-9a-f]{{40}})"
)
COMMIT = re.compile(r"[0-9a-f]{40}")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def load(path: Path) -> dict[str, object]:
    require(path.is_file() and not path.is_symlink(), f"{path} must be a regular file")
    with path.open("rb") as file:
        return tomllib.load(file)


def source_version(root: Path) -> str:
    value = load(root / "Cargo.toml")["workspace"]["package"]["version"]
    require(isinstance(value, str) and SEMVER.fullmatch(value) is not None, "workspace source version must be canonical SemVer")
    return value


def base_version(root: Path) -> str:
    metadata = load(root / "release/nightly.toml")
    require(set(metadata) == {"schema-version", "base-version"}, "nightly train metadata keys are invalid")
    require(metadata["schema-version"] == 1, "nightly train schema-version must be integer 1")
    value = metadata["base-version"]
    require(isinstance(value, str) and SEMVER.fullmatch(value) is not None, "nightly base-version must be canonical SemVer")
    current = tuple(int(part) for part in source_version(root).split("."))
    base = tuple(int(part) for part in value.split("."))
    require(base > current, "nightly base-version must be newer than the workspace source version")
    return value


def real_date(value: str) -> None:
    require(re.fullmatch(r"[0-9]{8}", value) is not None, "nightly date must be YYYYMMDD")
    try:
        dt.datetime.strptime(value, "%Y%m%d")
    except ValueError as error:
        raise ValueError(f"nightly date is invalid: {error}") from error


def derive(base: str, date: str, source_commit: str) -> str:
    require(SEMVER.fullmatch(base) is not None, "nightly base must be canonical SemVer")
    real_date(date)
    require(COMMIT.fullmatch(source_commit) is not None, "source commit must be 40 lowercase hexadecimal characters")
    return f"{base}-nightly.{date}.g{source_commit}"


def validate_dispatch_date(date: str, created_at: str) -> None:
    real_date(date)
    try:
        created = dt.datetime.fromisoformat(created_at.replace("Z", "+00:00")).date()
    except ValueError as error:
        raise ValueError(f"release dispatch timestamp is invalid: {error}") from error
    nightly = dt.datetime.strptime(date, "%Y%m%d").date()
    require(
        (created - nightly).days in (0, 1),
        "nightly date must match the release dispatch date",
    )


def workspace_package_names(root: Path, current: str) -> set[str]:
    names: set[str] = set()
    for manifest in sorted((root / "crates").glob("*/Cargo.toml")):
        package = load(manifest).get("package")
        if not isinstance(package, dict):
            continue
        name = package.get("name")
        version = package.get("version")
        if isinstance(version, dict) and version.get("workspace") is True:
            version = current
        if (
            isinstance(name, str)
            and (name == "astrid" or name.startswith("astrid-"))
            and version == current
        ):
            names.add(name)
    require(names, "no Astrid workspace packages inherit the source version")
    return names


def stage(root: Path, version: str) -> None:
    match = NIGHTLY.fullmatch(version)
    require(match is not None, "nightly version must be X.Y.Z-nightly.YYYYMMDD.g<40 hex>")
    base = base_version(root)
    require(match.group("base") == base, "nightly version must derive from release/nightly.toml")
    real_date(match.group("date"))
    current = source_version(root)

    cargo_path = root / "Cargo.toml"
    cargo = cargo_path.read_text(encoding="utf-8")
    workspace_pattern = re.compile(rf'(?m)^(version = "){re.escape(current)}("\s*)$')
    workspace_matches = list(workspace_pattern.finditer(cargo))
    require(len(workspace_matches) == 1, "workspace package version must occur exactly once")
    cargo = workspace_pattern.sub(rf'\g<1>{version}\g<2>', cargo, count=1)

    dependency_pattern = re.compile(
        rf'(?m)^(astrid-[a-z0-9-]+\s*=\s*\{{[^\r\n]*\bpath\s*=\s*"[^"]+"[^\r\n]*\bversion\s*=\s*"){re.escape(current)}("[^\r\n]*\}}\s*)$'
    )
    dependencies = list(dependency_pattern.finditer(cargo))
    require(dependencies, "workspace Astrid path dependencies must carry the source version")
    cargo = dependency_pattern.sub(rf'\g<1>{version}\g<2>', cargo)

    names = workspace_package_names(root, current)
    lock_path = root / "Cargo.lock"
    lock = lock_path.read_text(encoding="utf-8")
    blocks = re.split(r"(?=^\[\[package\]\]\s*$)", lock, flags=re.MULTILINE)
    changed: set[str] = set()
    for index, block in enumerate(blocks):
        name_match = re.search(r'(?m)^name = "([^"]+)"$', block)
        version_match = re.search(r'(?m)^version = "([^"]+)"$', block)
        has_source = re.search(r'(?m)^source = "', block) is not None
        if (
            name_match is None
            or version_match is None
            or has_source
            or name_match.group(1) not in names
            or version_match.group(1) != current
        ):
            continue
        name = name_match.group(1)
        require(name not in changed, f"Cargo.lock contains duplicate source-less package {name}")
        blocks[index] = re.sub(
            rf'(?m)^(version = "){re.escape(current)}("\s*)$',
            rf'\g<1>{version}\g<2>',
            block,
            count=1,
        )
        changed.add(name)
    missing = names - changed
    require(not missing, f"Cargo.lock is missing source-less workspace packages: {', '.join(sorted(missing))}")

    cargo_path.write_text(cargo, encoding="utf-8")
    lock_path.write_text("".join(blocks), encoding="utf-8")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    derive_command = commands.add_parser("derive")
    derive_command.add_argument("--root", type=Path, default=ROOT)
    derive_command.add_argument("--date", required=True)
    derive_command.add_argument("--source-commit", required=True)
    stage_command = commands.add_parser("stage")
    stage_command.add_argument("--root", type=Path, default=ROOT)
    stage_command.add_argument("--version", required=True)
    dispatch_command = commands.add_parser("validate-dispatch")
    dispatch_command.add_argument("--date", required=True)
    dispatch_command.add_argument("--created-at", required=True)
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.command == "derive":
        print(derive(base_version(args.root), args.date, args.source_commit))
    elif args.command == "stage":
        stage(args.root, args.version)
    else:
        validate_dispatch_date(args.date, args.created_at)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (KeyError, OSError, TypeError, ValueError, tomllib.TOMLDecodeError) as error:
        print(f"nightly version: {error}", file=sys.stderr)
        raise SystemExit(1)
