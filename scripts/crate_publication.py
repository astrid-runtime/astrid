#!/usr/bin/env python3
"""Plan a complete dependency-ordered crates.io publication for Astrid."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import release_manifest


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def publication_order(metadata: object, version: str) -> list[str]:
    version = release_manifest.canonical_version(version)
    require(isinstance(metadata, dict), "Cargo metadata must be an object")
    packages = metadata.get("packages")
    members = metadata.get("workspace_members")
    require(isinstance(packages, list), "Cargo metadata packages must be an array")
    require(isinstance(members, list), "Cargo metadata workspace_members must be an array")
    member_ids = set(members)

    publishable: dict[str, dict[str, object]] = {}
    for package in packages:
        require(isinstance(package, dict), "Cargo package metadata must be an object")
        if package.get("id") not in member_ids or package.get("source") is not None:
            continue
        publish = package.get("publish")
        if publish == []:
            continue
        name = package.get("name")
        require(isinstance(name, str) and name, "workspace package name is invalid")
        require(name not in publishable, f"duplicate publishable workspace package: {name}")
        require(package.get("version") == version, f"{name} is not version {version}")
        dependencies = package.get("dependencies")
        require(isinstance(dependencies, list), f"{name} dependencies must be an array")
        publishable[name] = package
    require(publishable, "workspace has no publishable packages")

    prerequisites: dict[str, set[str]] = {name: set() for name in publishable}
    for name, package in publishable.items():
        for dependency in package["dependencies"]:
            require(isinstance(dependency, dict), f"{name} dependency metadata is invalid")
            target = dependency.get("name")
            if target not in publishable:
                continue
            require(
                dependency.get("req") == f"^{version}",
                f"{name} must pin workspace dependency {target} to ^{version}",
            )
            kind = dependency.get("kind")
            require(kind in {None, "normal", "build", "dev"}, f"{name} dependency kind is invalid")
            if kind != "dev":
                prerequisites[name].add(target)

    order: list[str] = []
    remaining = {name: set(values) for name, values in prerequisites.items()}
    while remaining:
        ready = sorted(name for name, values in remaining.items() if not values)
        require(ready, f"publishable workspace dependency cycle: {sorted(remaining)}")
        for name in ready:
            order.append(name)
            del remaining[name]
        for values in remaining.values():
            values.difference_update(ready)
    return order


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args(argv)
    metadata = json.loads(args.metadata.read_text(encoding="utf-8"))
    for package in publication_order(metadata, args.version):
        print(package)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        print(f"crate publication: {error}", file=sys.stderr)
        raise SystemExit(1)
