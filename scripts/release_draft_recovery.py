#!/usr/bin/env python3
"""Plan a write-once recovery of an interrupted GitHub release draft."""

from __future__ import annotations

import argparse
import filecmp
import stat
import sys
from pathlib import Path


BUNDLE_SUFFIX = ".sigstore.json"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def regular_entries(directory: Path, *, label: str) -> dict[str, Path]:
    require(
        directory.is_dir() and not directory.is_symlink(),
        f"{label} must be a directory",
    )
    entries = {path.name: path for path in directory.iterdir()}
    invalid = sorted(
        name
        for name, path in entries.items()
        if path.is_symlink() or not stat.S_ISREG(path.lstat().st_mode)
    )
    require(not invalid, f"{label} contains non-regular entries: {invalid}")
    empty = sorted(name for name, path in entries.items() if path.stat().st_size == 0)
    require(not empty, f"{label} contains empty files: {empty}")
    return entries


def load_payloads(path: Path) -> list[str]:
    payloads = [line.strip() for line in path.read_text().splitlines() if line.strip()]
    require(payloads, "release payload list must not be empty")
    require(
        len(payloads) == len(set(payloads)),
        "release payload list contains duplicates",
    )
    invalid = sorted(
        name
        for name in payloads
        if Path(name).name != name or name in {".", ".."} or name.endswith(BUNDLE_SUFFIX)
    )
    require(not invalid, f"release payload list contains invalid names: {invalid}")
    return payloads


def plan_recovery(
    candidate: Path,
    existing: Path,
    payloads: list[str],
) -> tuple[list[str], list[str]]:
    candidate_entries = regular_entries(candidate, label="release candidate")
    existing_entries = regular_entries(existing, label="existing draft assets")
    expected = set(payloads) | {f"{name}{BUNDLE_SUFFIX}" for name in payloads}
    actual_candidate = set(candidate_entries)
    require(
        actual_candidate == expected,
        "release candidate asset set differs; "
        f"missing={sorted(expected - actual_candidate)}, "
        f"unexpected={sorted(actual_candidate - expected)}",
    )
    unexpected = sorted(set(existing_entries) - expected)
    require(not unexpected, f"existing draft contains unexpected assets: {unexpected}")

    for payload in sorted(set(existing_entries) & set(payloads)):
        require(
            filecmp.cmp(
                candidate_entries[payload],
                existing_entries[payload],
                shallow=False,
            ),
            f"existing draft payload differs from the release candidate: {payload}",
        )

    missing = sorted(expected - set(existing_entries))
    existing_bundles = sorted(set(existing_entries) - set(payloads))
    return missing, existing_bundles


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    root.add_argument("--candidate", type=Path, required=True)
    root.add_argument("--existing", type=Path, required=True)
    root.add_argument("--payloads", type=Path, required=True)
    root.add_argument("--missing-output", type=Path, required=True)
    root.add_argument("--existing-bundles-output", type=Path, required=True)
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    missing, existing_bundles = plan_recovery(
        args.candidate,
        args.existing,
        load_payloads(args.payloads),
    )
    args.missing_output.write_text("".join(f"{name}\n" for name in missing))
    args.existing_bundles_output.write_text(
        "".join(f"{name}\n" for name in existing_bundles)
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(f"release draft recovery: {error}", file=sys.stderr)
        raise SystemExit(1)
