#!/usr/bin/env python3
"""Check that deliberate defects fail the pinned Verus entry point.

Every defect is an exact edit applied to a scratch copy of the verifier's
inputs. A defect that still verifies shows that the proof does not constrain
what it claims. The unmodified copy must verify with zero errors first. This
checks only the defects listed here and establishes no other property.
"""

import argparse
from collections.abc import Callable
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
ENTRY = Path("verification/hosted_authority.rs")
MODEL = Path("verification/hosted_authority_model.rs")
AUTHORITY = Path("crates/astrid-capabilities/src/store/authority.rs")
INPUTS = [
    ENTRY,
    MODEL,
    AUTHORITY,
    Path("crates/astrid-capsule-types/src/fuel_ledger/arithmetic.rs"),
    Path("crates/astrid-capsule/src/engine/wasm/principal_tracker/state.rs"),
    Path("crates/astrid-core/src/capability_grammar/matcher.rs"),
]
PROOF_ITEMS = [
    "theorem_acknowledged_revocation_denies_admission",
    "theorem_single_use_grant_admits_one_consumption",
    "theorem_acknowledged_consumption_denies_admission",
    "theorem_unacknowledged_revocation_fences_until_recovery",
    "witness_unacknowledged_revocation_reopens_at_recovery",
    "theorem_retirement_admits_no_operation",
    "witness_earlier_resume_does_not_reopen_retirement",
    "theorem_committed_fuel_is_budget_plus_charged_excess",
    "theorem_committed_fuel_stays_within_budget",
    "witness_charged_excess_is_the_only_overshoot",
]


def replace_once(text: str, old: str, new: str) -> str:
    """Replace the one occurrence of `old` in `text`."""
    if text.count(old) != 1:
        raise ValueError(f"expected one occurrence of {old!r}, found {text.count(old)}")
    return text.replace(old, new, 1)


def edit_function(text: str, function: str, old: str, new: str) -> str:
    """Replace the one occurrence of `old` in a top-level proof item.

    The scope starts at the signature, so it includes the requires and
    ensures clauses, and ends at the closing brace of the body.
    """
    start = text.index(f"fn {function}(")
    closing = text.index("\n}\n", start) + 1
    item = text[start:closing]
    return text[:start] + replace_once(item, old, new) + text[closing:]


def contradict_function(text: str, function: str) -> str:
    """Put a false assertion first in the body of a proof item."""
    signature = text.index(f"proof fn {function}(")
    opening = text.index("{\n", signature) + 2
    return text[:opening] + "    assert(false);\n" + text[opening:]


def storage_condition_removed(text: str) -> str:
    line = "        recovery_observes_acknowledged_markers(events),\n"
    return edit_function(
        text, "theorem_acknowledged_revocation_denies_admission", line, ""
    )


def defects() -> list[tuple[str, Path, Callable[[str], str]]]:
    """Each defect names the claim it would falsify."""
    vacuity = [
        (f"vacuity: {item}", MODEL, lambda text, item=item: contradict_function(text, item))
        for item in PROOF_ITEMS
    ]
    return [
        (
            "admit ignores revocation for reusable tokens",
            AUTHORITY,
            lambda text: replace_once(
                text,
                "if self.revoked {\n            Admission::Revoked",
                "if self.revoked && single_use {\n            Admission::Revoked",
            ),
        ),
        (
            "recover_markers drops its last marker",
            AUTHORITY,
            lambda text: replace_once(text, "status.restore(*last);", "let _ = last;"),
        ),
        (
            "apply_revocation records consumption",
            MODEL,
            lambda text: edit_function(
                text, "apply_revocation", "status.record_revocation();", "status.record_consumption();"
            ),
        ),
        ("revocation theorem stated without the storage condition", MODEL, storage_condition_removed),
        (
            "recovery ignores durable markers",
            MODEL,
            lambda text: edit_function(
                text,
                "grant_step",
                "revoked: markers.contains(Marker::Revoked),",
                "revoked: false,",
            ),
        ),
        (
            "retirement proof ignores resumes after the retirement",
            MODEL,
            lambda text: edit_function(
                text, "retired_until_resume", "no_resume_between(events, i, k),", "true,"
            ),
        ),
        (
            "single-use proof loses the consumption lemma",
            MODEL,
            lambda text: edit_function(
                text,
                "theorem_single_use_grant_admits_one_consumption",
                "acknowledged_consumption_closes(events, first);",
                "",
            ),
        ),
        (
            "settlement releases more than it promised",
            MODEL,
            lambda text: edit_function(
                text,
                "fuel_transition_is_admitted",
                "FuelEvent::Settle { released, .. } => released as int <= state.reserved,",
                "FuelEvent::Settle { .. } => true,",
            ),
        ),
        (
            "settlement hides the fuel charged beyond its promise",
            MODEL,
            lambda text: edit_function(
                text,
                "fuel_step",
                "+ if actual as int > released as int { actual as int - released as int } else { 0 },",
                "+ 0,",
            ),
        ),
        *vacuity,
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


def copy_inputs(tree: Path) -> None:
    for relative in INPUTS:
        (tree / relative).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, tree / relative)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--verus", default="verus", help="path to the pinned verifier")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="astrid-verification-defects-") as scratch:
        base = Path(scratch)
        copy_inputs(base)
        code, output = verify(args.verus, base)
        if code != 0 or "0 errors" not in output:
            print("FAIL: the unmodified sources must verify with zero errors")
            print(output[-2000:])
            return 1
        print("PASS: unmodified sources verify with zero errors")
        failures = 0
        for index, (name, relative, defect) in enumerate(defects()):
            tree = base / f"defect-{index}"
            copy_inputs(tree)
            source = tree / relative
            try:
                source.write_text(defect(source.read_text()))
            except ValueError as error:
                print(f"FAIL: {name}: {error}")
                failures += 1
                continue
            code, _ = verify(args.verus, tree)
            if code == 0:
                print(f"FAIL: {name}: still verifies")
                failures += 1
            else:
                print(f"PASS: {name}: rejected")
    print(f"{len(defects()) - failures} of {len(defects())} defects rejected")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
