"""Implementation mutations for authority verification."""

from pathlib import Path

from .common import (
    AUTHORITY,
    MODEL,
    edit_function,
    replace_once,
)


def defects():
    storage = "recovery_observes_acknowledged_markers"
    return [
        (
            "restart enumerates revoked markers twice and drops consumption",
            AUTHORITY,
            lambda text: replace_once(text, "[Self::Revoked, Self::Consumed]", "[Self::Revoked, Self::Revoked]"),
        ),
        (
            "revoked tokens are written to the used marker namespace",
            AUTHORITY,
            lambda text: replace_once(text, 'Self::Revoked => "caps:revoked", Self::Consumed => "caps:used"', 'Self::Revoked => "caps:used", Self::Consumed => "caps:used"'),
        ),
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
            "recover_markers skips a recorded marker",
            AUTHORITY,
            lambda text: replace_once(text, "status.restore(markers[i]);", "let _ = markers[i];"),
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
            "consumption theorem omits the index itself",
            MODEL,
            lambda text: edit_function(
                text,
                "theorem_acknowledged_consumption_keeps_grant_used",
                "        forall|j: int| i <= j <= events.len() ==> (#[trigger] grant_run(events, j)).used,\n",
                "        forall|j: int| i < j <= events.len() ==> (#[trigger] grant_run(events, j)).used,\n",
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
    ]


def live_token_consumers():
    for label, clause in [
        ("marker namespace", 'address.0@ == "caps:revoked"@'),
        ("marker identity", "*address.1 == *id"),
        ("prior consumption", "final(authority)@[*id].used() == (old(authority)@.contains_key(*id) && old(authority)@[*id].used())"),
        ("live refusal", "final(authority)@[*id].revoked()"),
        ("peer isolation", "final(authority)@ == old(authority)@.insert(*id, final(authority)@[*id])"),
    ]:
        yield (
            f"token revocation fence loses {label}", AUTHORITY,
            lambda s, clause=clause: replace_once(s, clause, "true"), MODEL,
        )
    for label, clause in [
        ("CAS address", "*out.1 == self.target()"),
        ("admission", "admitted == (won && !revoked && !used)"),
        ("live consumption", "final(authority)@[id].used()"),
        ("prior revocation", "final(authority)@[id].revoked() == revoked"),
        ("peer isolation", "final(authority)@ == old(authority)@.insert(id,final(authority)@[id])"),
    ]:
        yield (
            f"single-use completion loses {label}", AUTHORITY,
            lambda s, clause=clause: replace_once(s, clause, "true"), MODEL,
        )


def marker_batch_consumers():
    for label, path, clause, weaker in [
        ("canonical encoding", "crates/astrid-capabilities/src/store/marker_key.rs", "ensures a == b,", "ensures true,"),
        ("physical source", "verification/hosted_key_projection.rs",
         "keys.deep_view().get(namespace@ + seq![0u8] + #[trigger] logical@[i]@) == Some(true)",
         "#[trigger] logical@[i]@.len() >= 0"),
    ]:
        yield (
            f"marker image recovery loses {label}", Path(path),
            lambda s, a=clause, b=weaker: replace_once(s, a, b),
            Path("verification/hosted_token_recovery.rs"),
        )
    for label, clause, weaker in [
        ("complete enumeration", "Ok(()) => ids.len() == keys.len()", "Ok(()) => ids.len() <= keys.len()"),
        ("decoded identity", "&& decoded(keys@,ids,decode) && match out", "&& match out"),
        ("failed row", "&& decode.ensures((&keys@[ids.len() as int],),Err(e))", ""),
        ("namespace membership", "#[trigger] has(after,id,tag) ==",
         "#[trigger] has(after,id,tag) ==>"),
    ]:
        yield (
            f"token marker batch loses {label}", Path("crates/astrid-capabilities/src/store/marker_batch.rs"),
            lambda s, clause=clause, weaker=weaker: replace_once(s, clause, weaker),
            Path("verification/hosted_token_recovery.rs"),
        )
