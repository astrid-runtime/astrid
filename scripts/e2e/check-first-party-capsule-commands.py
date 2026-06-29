#!/usr/bin/env python3
"""Verify checked-out first-party capsule commands are represented in E2E inventory."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import sys
import tempfile

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11 fallback.
    import tomli as tomllib  # type: ignore[no-redef]


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
    data = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    package = data.get("package", {})
    package_name = package.get("name") if isinstance(package, dict) else None
    if not isinstance(package_name, str) or not package_name:
        raise SystemExit(f"{manifest_path} is missing package.name")

    commands: set[str] = set()
    command_entries = data.get("command", [])
    if not isinstance(command_entries, list):
        raise SystemExit(f"{manifest_path} has invalid [[command]] shape")
    for command in command_entries:
        if not isinstance(command, dict):
            raise SystemExit(f"{manifest_path} has invalid [[command]] entry")
        name = command.get("name")
        if isinstance(name, str) and name:
            commands.add(name)
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


def run_self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        manifest_path = Path(tmp) / "Capsule.toml"
        manifest_path.write_text(
            '''
            [package]
            description = "literal # is not a comment"
            name = "astrid-capsule-hash"
            version = "1.0.0"

            [[command]]
            description = """
            multiline # content is still TOML string data
            """
            name = "run-hash"

            [[command]]
            name = "inspect"
            ''',
            encoding="utf-8",
        )
        package, commands = capsule_package_and_commands(manifest_path)
    assert package == "astrid-capsule-hash", package
    assert commands == {"run-hash", "inspect"}, commands
    print("self-test passed")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--capsules-dir",
        type=Path,
        default=Path(os.environ.get("ASTRID_E2E_CAPSULES_DIR", "../capsules")),
    )
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        return run_self_test()

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
