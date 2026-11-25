#!/usr/bin/env python3
"""Check that deliberate defects fail the pinned Verus entry point.

Every defect is an exact edit applied to a scratch copy of the verifier's
inputs. A defect that still verifies shows that the proof does not constrain
what it claims. The unmodified copy must verify with zero errors first. A
defect counts as rejected only when the verifier reports an error in the
edited file, so a defect that fails to parse is reported as a failure.

This checks only the defects listed here and establishes no other property.
A weaker statement that is still true is not a defect, unless a proof listed
here derives its conclusion from the stronger one.
"""

import argparse
from collections.abc import Callable
from pathlib import Path
import re
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
    "theorem_acknowledged_revocation_keeps_grant_revoked",
    "acknowledged_revocation_denies_reusable_admission",
    "theorem_single_use_grant_admits_one_consumption",
    "theorem_acknowledged_consumption_keeps_grant_used",
    "acknowledged_consumption_survives_a_later_revocation",
    "theorem_revocation_keeps_grant_revoked_until_recovery",
    "revocation_denies_reusable_admission_until_recovery",
    "witness_unacknowledged_revocation_reopens_at_recovery",
    "theorem_retirement_admits_no_operation",
    "retirement_closes_after_an_earlier_resume",
    "witness_earlier_resume_does_not_reopen_retirement",
    "theorem_committed_fuel_is_budget_plus_charged_excess",
    "theorem_committed_fuel_stays_within_budget",
    "witness_charged_excess_is_the_only_overshoot",
]
RESULT = re.compile(r"verification results:: (\d+) verified, (\d+) errors")
LOCATION = re.compile(r"^error[^\n]*\n\s+--> (\S+):\d+:\d+", re.MULTILINE)


def replace_once(text: str, old: str, new: str) -> str:
    """Replace the one occurrence of `old` in `text`."""
    if text.count(old) != 1:
        raise ValueError(f"expected one occurrence of {old!r}, found {text.count(old)}")
    return text.replace(old, new, 1)


def item(text: str, function: str) -> tuple[int, int]:
    """Locate a top-level proof item, from its signature to its closing brace.

    The scope includes the requires and ensures clauses.
    """
    start = text.index(f"fn {function}(")
    closing = text.index("\n}\n", start) + 1
    return start, closing


def edit_function(text: str, function: str, old: str, new: str) -> str:
    """Replace the one occurrence of `old` in a top-level proof item."""
    start, closing = item(text, function)
    item_text = text[start:closing]
    return text[:start] + replace_once(item_text, old, new) + text[closing:]


def contradict_function(text: str, function: str) -> str:
    """Put a false assertion first in the body of a proof item."""
    signature = text.index(f"proof fn {function}(")
    opening = text.index("{\n", signature) + 2
    return text[:opening] + "    assert(false);\n" + text[opening:]


def verified_counts(output: str) -> tuple[int, int] | None:
    """Read the verifier's counts, or None when it reported no result."""
    found = RESULT.search(output)
    if found is None:
        return None
    return int(found.group(1)), int(found.group(2))


def error_in(output: str, relative: Path) -> bool:
    """Report whether the verifier located an error in `relative`."""
    return any(Path(location).name == relative.name for location in LOCATION.findall(output))


def defects() -> list[tuple[str, Path, Callable[[str], str]]]:
    """Each defect names the claim it would falsify."""
    storage = "recovery_observes_acknowledged_markers"
    vacuity = [
        (f"false assertion in the body of {item}", MODEL, lambda text, item=item: contradict_function(text, item))
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
            "recovery forgets an acknowledged revocation",
            MODEL,
            lambda text: edit_function(
                text,
                storage,
                "(revocation_acknowledged_before(events, i) ==> markers.contains(Marker::Revoked))",
                "true",
            ),
        ),
        (
            "recovery forgets an acknowledged consumption",
            MODEL,
            lambda text: edit_function(
                text,
                storage,
                "(consumption_acknowledged_before(events, i) ==> markers.contains(Marker::Consumed))",
                "true",
            ),
        ),
        (
            "a revoke keeps the grant's prior state",
            MODEL,
            lambda text: edit_function(
                text,
                "grant_step",
                "GrantEvent::Revoke { .. } => GrantState { revoked: true, used: state.used },",
                "GrantEvent::Revoke { .. } => state,",
            ),
        ),
        (
            "recovery ignores revoked markers",
            MODEL,
            lambda text: edit_function(
                text,
                "grant_step",
                "revoked: markers.contains(Marker::Revoked),",
                "revoked: false,",
            ),
        ),
        (
            "recovery ignores consumed markers",
            MODEL,
            lambda text: edit_function(
                text,
                "grant_step",
                "used: markers.contains(Marker::Consumed),",
                "used: false,",
            ),
        ),
        (
            "revocation theorem stated without the storage condition",
            MODEL,
            lambda text: edit_function(
                text,
                "theorem_acknowledged_revocation_keeps_grant_revoked",
                "        recovery_observes_acknowledged_markers(events),\n",
                "",
            ),
        ),
        (
            "acknowledged revocation theorem reports only single-use denial",
            MODEL,
            lambda text: edit_function(
                text,
                "theorem_acknowledged_revocation_keeps_grant_revoked",
                "        forall|j: int| i <= j <= events.len()"
                " ==> (#[trigger] grant_run(events, j)).revoked,\n",
                "        forall|j: int| i <= j <= events.len()"
                " ==> !grant_admits(#[trigger] grant_run(events, j), true),\n",
            ),
        ),
        (
            "recovery-fence theorem reports only single-use denial",
            MODEL,
            lambda text: edit_function(
                text,
                "theorem_revocation_keeps_grant_revoked_until_recovery",
                "            ==> (grant_run(events, k)).revoked,",
                "            ==> !grant_admits(grant_run(events, k), true),",
            ),
        ),
        (
            "consumption theorem reports only single-use denial",
            MODEL,
            lambda text: edit_function(
                text,
                "theorem_acknowledged_consumption_keeps_grant_used",
                "        forall|j: int| i <= j <= events.len() ==> (#[trigger] grant_run(events, j)).used,\n",
                "        forall|j: int| i <= j <= events.len()"
                " ==> !grant_admits(#[trigger] grant_run(events, j), true),\n",
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
            "retirement theorem counts a resume before the retirement",
            MODEL,
            lambda text: edit_function(
                text,
                "theorem_retirement_admits_no_operation",
                "            && #[trigger] no_resume_between(events, i, k)\n"
                "            ==> !operation_admits(operation_run(events, k)),",
                "            && !(events.take(k).contains(OperationEvent::Resume))\n"
                "                ==> !operation_admits(operation_run(events, k)),",
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
            "a reservation is admitted without fitting",
            MODEL,
            lambda text: edit_function(
                text,
                "fuel_transition_is_admitted",
                "FuelEvent::Reserve { requested } => fuel_admits(state, requested as int, limit),",
                "FuelEvent::Reserve { .. } => true,",
            ),
        ),
        (
            "a settlement releases more than it promised",
            MODEL,
            lambda text: edit_function(
                text,
                "fuel_transition_is_admitted",
                "FuelEvent::Settle { released, .. } => released as int <= state.reserved,",
                "FuelEvent::Settle { .. } => true,",
            ),
        ),
        (
            "a settlement hides the fuel charged beyond its promise",
            MODEL,
            lambda text: edit_function(
                text,
                "fuel_step",
                "+ if actual as int > released as int { actual as int - released as int } else { 0 },",
                "+ 0,",
            ),
        ),
        (
            "budget corollary stated without its no-excess condition",
            MODEL,
            lambda text: edit_function(
                text,
                "theorem_committed_fuel_stays_within_budget",
                "        forall|m: int| 0 <= m < events.len()"
                " ==> #[trigger] settlement_charges_within_promise(events, m),\n",
                "",
            ),
        ),
        (
            "apply_revocation records consumption",
            MODEL,
            lambda text: edit_function(
                text, "apply_revocation", "status.record_revocation();", "status.record_consumption();"
            ),
        ),
        (
            "apply_consumption records a revocation",
            MODEL,
            lambda text: edit_function(
                text,
                "apply_consumption",
                "status.confirm_consumption(won)",
                "{ status.record_revocation(); false }",
            ),
        ),
        (
            "store_admission allows everything",
            MODEL,
            lambda text: edit_function(
                text,
                "store_admission",
                "matches!(status.admit(single_use), Admission::Allowed)",
                "true",
            ),
        ),
        (
            "apply_recovery ignores the markers",
            MODEL,
            lambda text: edit_function(
                text,
                "apply_recovery",
                "TokenStatus::recover_markers(markers)",
                "TokenStatus::recover(false, false)",
            ),
        ),
        (
            "apply_operation skips finish",
            MODEL,
            lambda text: edit_function(
                text,
                "apply_operation",
                "OperationEvent::Finish => {\n            state.finish();\n            false\n        },",
                "OperationEvent::Finish => false,",
            ),
        ),
        (
            "fuel_reservation_fits confuses the request with the limit",
            MODEL,
            lambda text: edit_function(
                text,
                "fuel_reservation_fits",
                "crate::arithmetic::reservation_fits(spent, reserved, requested, limit)",
                "crate::arithmetic::reservation_fits(spent, reserved, limit, requested)",
            ),
        ),
        (
            "fuel_settlement confuses the release with the charge",
            MODEL,
            lambda text: edit_function(
                text,
                "fuel_settlement",
                "crate::arithmetic::settle_amounts(spent, reserved, released, actual)",
                "crate::arithmetic::settle_amounts(spent, reserved, actual, released)",
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


def check_defect(verus: str, base: Path, name: str, relative: Path, defect) -> bool:
    """Apply one defect to a scratch copy and report whether it was rejected."""
    tree = base / "defect"
    copy_inputs(tree)
    source = tree / relative
    try:
        source.write_text(defect(source.read_text()))
    except ValueError as error:
        print(f"FAIL: {name}: {error}")
        return False
    _, output = verify(verus, tree)
    counts = verified_counts(output)
    if counts is None or counts[1] == 0:
        print(f"FAIL: {name}: the verifier reported no error")
        return False
    if not error_in(output, relative):
        print(f"FAIL: {name}: no error in {relative}")
        return False
    print(f"PASS: {name}: rejected")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--verus", default="verus", help="path to the pinned verifier")
    args = parser.parse_args()
    checks = defects()
    with tempfile.TemporaryDirectory(prefix="astrid-verification-defects-") as scratch:
        base = Path(scratch)
        copy_inputs(base)
        code, output = verify(args.verus, base)
        counts = verified_counts(output)
        if code != 0 or counts is None or counts[1] != 0:
            print("FAIL: the unmodified sources must verify with zero errors")
            print(output[-2000:])
            return 1
        print("PASS: unmodified sources verify with zero errors")
        passed = sum(
            check_defect(args.verus, base, name, relative, defect)
            for name, relative, defect in checks
        )
    print(f"{passed} of {len(checks)} defects rejected")
    return 0 if passed == len(checks) else 1


if __name__ == "__main__":
    sys.exit(main())
