#!/usr/bin/env python3
"""Render an exact Cargo.lock version inventory between release revisions."""

import argparse
from collections import defaultdict
import subprocess
import tomllib


def packages(revision):
    raw = subprocess.check_output(["git", "show", f"{revision}:Cargo.lock"])
    result = defaultdict(set)
    for package in tomllib.loads(raw.decode())["package"]:
        result[package["name"]].add(package["version"])
    return result


def render(base, head):
    before, after = packages(base), packages(head)
    lines = ["# Release dependency version inventory", "",
             f"Baseline: `{base}`. Candidate: `{head}`.", "",
             "Generated from Cargo.lock. Includes direct, transitive, workspace,",
             "test, and platform-specific packages; inclusion is not a claim that",
             "every package ships in every binary. Multiple versions are listed.", ""]
    for title, names in (
        ("Updated", sorted(n for n in before.keys() & after.keys() if before[n] != after[n])),
        ("Added", sorted(after.keys() - before.keys())),
        ("Removed", sorted(before.keys() - after.keys())),
    ):
        lines += [f"## {title} ({len(names)})", "", "| Package | Previous | Candidate |",
                  "| --- | --- | --- |"]
        for name in names:
            old = ", ".join(sorted(before.get(name, ()))) or "—"
            new = ", ".join(sorted(after.get(name, ()))) or "—"
            lines.append(f"| `{name}` | {old} | {new} |")
        lines.append("")
    lines += ["Unchanged version sets are omitted. Source/checksum changes with unchanged",
              "versions remain visible in the linked repository comparison, not this version inventory."]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", default="HEAD")
    args = parser.parse_args()
    print(render(args.base, args.head), end="")
