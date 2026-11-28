#!/usr/bin/env python3
"""Check that deliberate defects fail the pinned Verus entry point.

Every defect is an exact edit applied to a scratch copy of the verifier's
inputs. A defect that still verifies shows that the proof does not constrain
what it claims. The unmodified copy must verify with zero errors first. A
defect counts as rejected only when the verifier reports an error in the
edited file or the named consumer of a weakened contract, so a defect that fails to parse is reported as a failure.

This checks only the defects listed here and establishes no other property.
A weaker statement that is still true is not a defect, unless a proof listed
here derives its conclusion from the stronger one.
"""

import argparse
import os.path
from collections.abc import Callable
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
if __package__:
    from . import verification_cases as cases
else:
    import verification_cases as cases

AUTHORITY, ENTRY, INPUTS, MODEL = cases.AUTHORITY, cases.ENTRY, cases.INPUTS, cases.MODEL
replace_once, edit_function = cases.replace_once, cases.edit_function
item = cases.item
contradict_function = cases.contradict_function
consumer_defects = cases.consumer_defects

RESULT = re.compile(r"verification results:: (\d+) verified, (\d+) errors")
LOCATION = re.compile(r"^error[^\n]*\n\s+--> (\S+):\d+:\d+", re.MULTILINE)


def verified_counts(output: str) -> tuple[int, int] | None:
    """Read the verifier's counts, or None when it reported no result."""
    found = RESULT.search(output)
    if found is None:
        return None
    return int(found.group(1)), int(found.group(2))


def error_in(output: str, relative: Path) -> bool:
    """Report whether the verifier located an error in `relative`."""
    return any(Path(os.path.normpath(location)) == relative for location in LOCATION.findall(output))


def defects() -> list[tuple[str, Path, Callable[[str], str]]]:
    vacuity = [
        (f"false assertion in the body of {item}", MODEL, lambda text, item=item: contradict_function(text, item))
        for item in cases.PROOF_ITEMS
    ]
    return [
        *cases.dispatch.defects(), *cases.mounts.defects(), *cases.storage.defects(),
        *cases.authority.defects(), *vacuity,
    ]


def verify(verus: str, tree: Path) -> tuple[int, str]:
    result = subprocess.run(
        [
            verus,
            "--edition=2024",
            "--crate-type=lib",
            "--no-cheating",
            ENTRY.as_posix(),
        ],
        cwd=tree,
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode, result.stdout + result.stderr


def copy_inputs(source: Path, tree: Path) -> None:
    for relative in INPUTS:
        (tree / relative).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / relative, tree / relative)


def check_defect(verus: str, base: Path, name: str, relative: Path, defect, expected_error: Path | None = None) -> bool:
    """Apply one defect to a scratch copy and report whether it was rejected."""
    tree = base / "defect"
    copy_inputs(base, tree)
    source = tree / relative
    try:
        source.write_text(defect(source.read_text()))
    except ValueError as error:
        print(f"FAIL: {name}: {error}")
        return False
    _, output = verify(verus, tree)
    counts = verified_counts(output)
    if counts is None:
        print(f"FAIL: {name}: verifier did not produce verification counts")
        print(output[-2000:])
        return False
    if counts[1] == 0:
        print(f"FAIL: {name}: the verifier reported no error")
        return False
    location = expected_error or relative
    if not error_in(output, location):
        print(f"FAIL: {name}: no error in {location}")
        return False
    print(f"PASS: {name}: rejected")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--verus", default="verus", help="path to the pinned verifier")
    parser.add_argument("--shard-index", type=int, default=0, help="zero-based shard index")
    parser.add_argument("--shard-count", type=int, default=1, help="number of disjoint shards")
    args = parser.parse_args()
    checks = [(*check, None) for check in defects()] + list(consumer_defects())
    if not 0 <= args.shard_index < args.shard_count <= len(checks):
        parser.error("require 0 <= shard-index < shard-count <= number of checks")
    total = len(checks)
    checks = checks[args.shard_index::args.shard_count]
    print(f"Shard {args.shard_index + 1}/{args.shard_count}: {len(checks)} of {total} checks")
    with tempfile.TemporaryDirectory(prefix="astrid-verification-defects-") as scratch:
        base = Path(scratch)
        copy_inputs(ROOT, base)
        code, output = verify(args.verus, base)
        counts = verified_counts(output)
        if code != 0 or counts is None or counts[1] != 0:
            print("FAIL: the unmodified sources must verify with zero errors")
            print(output[-2000:])
            return 1
        print("PASS: unmodified sources verify with zero errors")
        passed = sum(
            check_defect(args.verus, base, *check) for check in checks
        )
    print(f"{passed} of {len(checks)} defects rejected")
    return 0 if passed == len(checks) else 1


if __name__ == "__main__":
    sys.exit(main())
