#!/usr/bin/env python3
"""Verify checked-out first-party capsule commands are represented in E2E inventory."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import sys


DEFAULT_CAPSULES = (
    "astrid-capsule-cli "
    "astrid-capsule-registry "
    "astrid-capsule-session "
    "astrid-capsule-identity "
    "astrid-capsule-prompt-builder "
    "astrid-capsule-react "
    "astrid-capsule-openai-compat"
)


def selected_capsules() -> list[str]:
    raw = os.environ.get("ASTRID_E2E_CORE_CAPSULES", DEFAULT_CAPSULES)
    return [part for part in raw.split() if part]


def capsule_package_and_commands(manifest_path: Path) -> tuple[str, set[str]]:
    package_name: str | None = None
    commands: set[str] = set()
    in_package = False
    in_command = False
    for raw_line in manifest_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if line == "[package]":
            in_package = True
            in_command = False
            continue
        if line.startswith("["):
            in_package = False
            in_command = line == "[[command]]"
            continue
        key, sep, value = line.partition("=")
        if sep != "=":
            continue
        value = value.strip().strip('"')
        if in_package and key.strip() == "name":
            package_name = value
        elif in_command and key.strip() == "name":
            commands.add(value)
    if not package_name:
        raise SystemExit(f"{manifest_path} is missing package.name")
    return package_name, commands


def discovered_commands(capsules_dir: Path) -> set[str]:
    commands: set[str] = set()
    missing: list[str] = []
    for capsule_dir_name in selected_capsules():
        manifest_path = capsules_dir / capsule_dir_name / "Capsule.toml"
        if not manifest_path.exists():
            missing.append(str(manifest_path))
            continue
        package_name, names = capsule_package_and_commands(manifest_path)
        commands.update(f"{package_name} {name}" for name in names)
    if missing:
        raise SystemExit("missing first-party capsule manifests:\n" + "\n".join(missing))
    return commands


def inventoried_commands(core_dir: Path) -> set[str]:
    text = (core_dir / "e2e" / "first-party-capsule-scenarios.toml").read_text(
        encoding="utf-8"
    )
    found = set(re.findall(r'^\[capsule_commands\."([^"]+)"\]', text, re.MULTILINE))
    if not found:
        raise SystemExit("first-party-capsule-scenarios.toml is missing [capsule_commands]")
    return found


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--capsules-dir",
        type=Path,
        default=Path(os.environ.get("ASTRID_E2E_CAPSULES_DIR", "../capsules")),
    )
    args = parser.parse_args()

    core_dir = Path(__file__).resolve().parents[2]
    actual = discovered_commands(args.capsules_dir)
    manifest = inventoried_commands(core_dir)
    missing = sorted(actual - manifest)
    if missing:
        print("first-party capsule commands missing from e2e inventory:", file=sys.stderr)
        for command in missing:
            print(f"  - {command}", file=sys.stderr)
        return 1
    print(f"checked {len(actual)} first-party capsule commands")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
