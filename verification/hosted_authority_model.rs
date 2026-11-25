//! Abstract model of hosted authority and the theorems checked for it.
//!
//! This is the specification side of the hosted security contract. A trace
//! follows one grant, the operations of one principal, or the fuel charged to
//! one principal, through the transitions that change what it may do. The
//! `apply_*` and `fuel_*` functions call the production function the fuel
//! limiter, the capability store or the invocation tracker calls, to decide
//! admission, to record a transition or to compute a settlement. The theorems
//! constrain every trace of those calls. Whatever the model cannot see, it
//! states as a condition on the trace.

use vstd::prelude::*;

use crate::principal_invocation_state::PrincipalInvocation;
use crate::token_authority::{Admission, Marker, TokenStatus};

verus! {

/// One transition of a grant's authority.
enum GrantEvent {
    /// Close live admission before the durable write. `completed` reports
    /// that the write completed.
    Revoke { completed: bool },
    /// Record single-use consumption. `won` reports a durable
    /// insert-if-absent win.
    Consume { won: bool },
    /// Replace live admission with the durable markers read at startup.
    Restart { markers: Seq<Marker> },
}

/// Live admission state of one grant.
struct GrantState {
    revoked: bool,
    used: bool,
}

/// One transition of a principal's operation admission.
enum OperationEvent {
    /// Request admission for one operation.
    Begin,
    /// Finish an admitted operation.
    Finish,
    /// Close admission to new operations while admitted ones drain.
    Retire,
    /// Reopen admission.
    Resume,
}

/// Live operation admission state of one principal.
struct OperationState {
    retired: bool,
    active: int,
}

closed spec fn grant_initial() -> GrantState {
    GrantState { revoked: false, used: false }
}

closed spec fn operation_initial() -> OperationState {
    OperationState { retired: false, active: 0 }
}

/// Admission under the grant is open while it is neither revoked nor, for a
/// single-use grant, consumed.
closed spec fn grant_admits(state: GrantState, single_use: bool) -> bool {
    !state.revoked && (!single_use || !state.used)
}

/// Admission under the principal is open while it is not retired.
closed spec fn operation_admits(state: OperationState) -> bool {
    !state.retired
}

/// The transition relation for one grant. Recovery denies exactly the
/// markers it reads.
closed spec fn grant_step(state: GrantState, event: GrantEvent) -> GrantState {
    match event {
        GrantEvent::Revoke { .. } => GrantState { revoked: true, used: state.used },
        GrantEvent::Consume { .. } => GrantState { revoked: state.revoked, used: true },
        GrantEvent::Restart { markers } => GrantState {
            revoked: markers.contains(Marker::Revoked),
            used: markers.contains(Marker::Consumed),
        },
    }
}

/// The transition relation for one principal. A denied begin changes nothing.
closed spec fn operation_step(state: OperationState, event: OperationEvent) -> OperationState {
    match event {
        OperationEvent::Begin => OperationState {
            retired: state.retired,
            active: if state.retired { state.active } else { state.active + 1 },
        },
        OperationEvent::Finish => OperationState {
            retired: state.retired,
            active: if state.active == 0 { 0 } else { state.active - 1 },
        },
        OperationEvent::Retire => OperationState { retired: true, active: state.active },
        OperationEvent::Resume => OperationState { retired: false, active: state.active },
    }
}

/// State of the grant after the first `k` transitions of a trace.
spec fn grant_run(events: Seq<GrantEvent>, k: int) -> GrantState
    recommends 0 <= k <= events.len(),
    decreases k,
{
    if k <= 0 {
        grant_initial()
    } else {
        grant_step(grant_run(events, k - 1), events[k - 1])
    }
}

/// State of the principal after the first `k` transitions of a trace.
spec fn operation_run(events: Seq<OperationEvent>, k: int) -> OperationState
    recommends 0 <= k <= events.len(),
    decreases k,
{
    if k <= 0 {
        operation_initial()
    } else {
        operation_step(operation_run(events, k - 1), events[k - 1])
    }
}

/// A durable revocation of the grant completed among the first `k` transitions.
closed spec fn revocation_acknowledged_before(events: Seq<GrantEvent>, k: int) -> bool {
    events.take(k).contains(GrantEvent::Revoke { completed: true })
}

/// A durable consumption of the grant completed among the first `k` transitions.
closed spec fn consumption_acknowledged_before(events: Seq<GrantEvent>, k: int) -> bool {
    events.take(k).contains(GrantEvent::Consume { won: true })
}

/// The storage adapter's obligation: recovery reads every marker whose write
/// completed earlier. Durable markers are only ever added.
closed spec fn recovery_observes_acknowledged_markers(events: Seq<GrantEvent>) -> bool {
    forall|i: int| 0 <= i < events.len() && #[trigger] events[i] is Restart ==> {
        let markers = events[i]->Restart_markers;
        (revocation_acknowledged_before(events, i) ==> markers.contains(Marker::Revoked))
            && (consumption_acknowledged_before(events, i) ==> markers.contains(Marker::Consumed))
    }
}

/// An acknowledged marker stays in every later prefix.
proof fn acknowledged_marker_stays_in_prefix<A>(events: Seq<A>, k: int, acknowledged: A)
    requires
        0 <= k < events.len(),
        events.take(k).contains(acknowledged),
    ensures events.take(k + 1).contains(acknowledged),
{
    vstd::seq_lib::lemma_seq_take_contains(events, k, acknowledged);
    vstd::seq_lib::lemma_seq_take_contains(events, k + 1, acknowledged);
}

/// Locate the transition that acknowledged a marker among the first `i`.
proof fn acknowledged_at<A>(events: Seq<A>, i: int, acknowledged: A) -> (index: int)
    requires
        0 <= i <= events.len(),
        events.take(i).contains(acknowledged),
    ensures
        0 <= index < i,
        events[index] == acknowledged,
{
    vstd::seq_lib::lemma_seq_take_len(events, i);
    vstd::seq_lib::lemma_seq_contains(events.take(i), acknowledged);
    let index = choose|m: int| 0 <= m < events.take(i).len() && events.take(i)[m] == acknowledged;
    vstd::seq_lib::lemma_seq_take_index(events, i, index);
    index
}

// ---- One grant ----

/// Once an acknowledged marker has closed the grant, no later transition
/// reopens it.
proof fn revoked_persists(events: Seq<GrantEvent>, k: int)
    requires
        0 <= k <= events.len(),
        grant_run(events, k).revoked,
        revocation_acknowledged_before(events, k),
        recovery_observes_acknowledged_markers(events),
    ensures
        forall|j: int| k <= j <= events.len() ==> (#[trigger] grant_run(events, j)).revoked,
    decreases events.len() - k,
{
    if k < events.len() {
        assert(grant_run(events, k + 1) == grant_step(grant_run(events, k), events[k]));
        match events[k] {
            GrantEvent::Restart { markers } => {
                assert(revocation_acknowledged_before(events, k));
                assert(markers.contains(Marker::Revoked));
            },
            GrantEvent::Revoke { .. } | GrantEvent::Consume { .. } => {},
        }
        acknowledged_marker_stays_in_prefix(events, k, GrantEvent::Revoke { completed: true });
        revoked_persists(events, k + 1);
    }
}

/// A completed revocation closes the grant from the next transition on.
proof fn acknowledged_revocation_closes(events: Seq<GrantEvent>, i: int)
    requires
        0 <= i < events.len(),
        events[i] is Revoke && events[i]->Revoke_completed,
        recovery_observes_acknowledged_markers(events),
    ensures
        forall|j: int| i < j <= events.len() ==> (#[trigger] grant_run(events, j)).revoked,
{
    assert(grant_run(events, i + 1) == grant_step(grant_run(events, i), events[i]));
    vstd::seq_lib::lemma_seq_take_contains(events, i + 1, GrantEvent::Revoke { completed: true });
    vstd::seq_lib::lemma_seq_take_index(events, i + 1, i);
    revoked_persists(events, i + 1);
}

/// An acknowledged revocation keeps the grant revoked for the rest of the
/// trace, across retries and restarts.
proof fn theorem_acknowledged_revocation_keeps_grant_revoked(events: Seq<GrantEvent>, i: int)
    requires
        0 <= i <= events.len(),
        revocation_acknowledged_before(events, i),
        recovery_observes_acknowledged_markers(events),
    ensures
        forall|j: int| i <= j <= events.len() ==> (#[trigger] grant_run(events, j)).revoked,
{
    let index = acknowledged_at(events, i, GrantEvent::Revoke { completed: true });
    acknowledged_revocation_closes(events, index);
}

/// The theorem closes admission for a reusable grant, which is denied only
/// by revocation.
proof fn acknowledged_revocation_denies_reusable_admission(events: Seq<GrantEvent>, i: int)
    requires
        0 <= i <= events.len(),
        revocation_acknowledged_before(events, i),
        recovery_observes_acknowledged_markers(events),
    ensures
        forall|j: int| i <= j <= events.len() ==> !grant_admits(#[trigger] grant_run(events, j), false),
{
    theorem_acknowledged_revocation_keeps_grant_revoked(events, i);
}

/// Once an acknowledged consumption has closed single-use admission, no later
/// transition reopens it.
proof fn used_persists(events: Seq<GrantEvent>, k: int)
    requires
        0 <= k <= events.len(),
        grant_run(events, k).used,
        consumption_acknowledged_before(events, k),
        recovery_observes_acknowledged_markers(events),
    ensures
        forall|j: int| k <= j <= events.len() ==> (#[trigger] grant_run(events, j)).used,
    decreases events.len() - k,
{
    if k < events.len() {
        assert(grant_run(events, k + 1) == grant_step(grant_run(events, k), events[k]));
        match events[k] {
            GrantEvent::Restart { markers } => {
                assert(consumption_acknowledged_before(events, k));
                assert(markers.contains(Marker::Consumed));
            },
            GrantEvent::Revoke { .. } | GrantEvent::Consume { .. } => {},
        }
        acknowledged_marker_stays_in_prefix(events, k, GrantEvent::Consume { won: true });
        used_persists(events, k + 1);
    }
}

/// A completed consumption closes single-use admission from the next
/// transition on.
proof fn acknowledged_consumption_closes(events: Seq<GrantEvent>, i: int)
    requires
        0 <= i < events.len(),
        events[i] is Consume && events[i]->Consume_won,
        recovery_observes_acknowledged_markers(events),
    ensures
        forall|j: int| i < j <= events.len() ==> (#[trigger] grant_run(events, j)).used,
{
    assert(grant_run(events, i + 1) == grant_step(grant_run(events, i), events[i]));
    vstd::seq_lib::lemma_seq_take_contains(events, i + 1, GrantEvent::Consume { won: true });
    vstd::seq_lib::lemma_seq_take_index(events, i + 1, i);
    used_persists(events, i + 1);
}

/// A consumption that the store admits at `events[k]`.
closed spec fn consumption_admitted(events: Seq<GrantEvent>, k: int) -> bool {
    0 <= k < events.len()
        && events[k] is Consume
        && events[k]->Consume_won
        && grant_admits(grant_run(events, k), true)
}

/// A single-use grant admits at most one consumption in a trace, across
/// retries and restarts.
proof fn theorem_single_use_grant_admits_one_consumption(events: Seq<GrantEvent>)
    requires recovery_observes_acknowledged_markers(events),
    ensures
        forall|first: int, second: int| consumption_admitted(events, first)
            && consumption_admitted(events, second) ==> first == second,
{
    assert forall|first: int, second: int| consumption_admitted(events, first)
        && consumption_admitted(events, second) implies first == second by {
        if first < second {
            acknowledged_consumption_closes(events, first);
        } else if second < first {
            acknowledged_consumption_closes(events, second);
        }
    };
}

/// An acknowledged consumption keeps the grant consumed for the rest of the
/// trace.
proof fn theorem_acknowledged_consumption_keeps_grant_used(events: Seq<GrantEvent>, i: int)
    requires
        0 <= i <= events.len(),
        consumption_acknowledged_before(events, i),
        recovery_observes_acknowledged_markers(events),
    ensures
        forall|j: int| i <= j <= events.len() ==> (#[trigger] grant_run(events, j)).used,
{
    let index = acknowledged_at(events, i, GrantEvent::Consume { won: true });
    acknowledged_consumption_closes(events, index);
}

/// A revoke after an acknowledged consumption leaves the grant used from the
/// revocation on and revoked right after it. That needs the consumed component
/// of the consumption theorem over its whole range, which single-use denial
/// alone does not state.
proof fn acknowledged_consumption_survives_a_later_revocation(
    events: Seq<GrantEvent>,
    i: int,
)
    requires
        0 <= i < events.len(),
        consumption_acknowledged_before(events, i),
        recovery_observes_acknowledged_markers(events),
        events[i] is Revoke,
    ensures
        forall|j: int| i <= j <= events.len() ==> (#[trigger] grant_run(events, j)).used,
        (grant_run(events, i + 1)).revoked,
{
    theorem_acknowledged_consumption_keeps_grant_used(events, i);
    assert(grant_run(events, i + 1) == grant_step(grant_run(events, i), events[i]));
}


/// No recovery transition occurs strictly between `i` and `k`.
closed spec fn no_recovery_between(events: Seq<GrantEvent>, i: int, k: int) -> bool {
    forall|m: int| i < m < k ==> !(#[trigger] events[m] is Restart)
}

/// A revocation keeps the grant closed until the next recovery.
proof fn revoked_until_recovery(events: Seq<GrantEvent>, i: int, k: int)
    requires
        0 <= i < k <= events.len(),
        events[i] is Revoke,
        no_recovery_between(events, i, k),
    ensures grant_run(events, k).revoked,
    decreases k - i,
{
    assert(grant_run(events, k) == grant_step(grant_run(events, k - 1), events[k - 1]));
    if i < k - 1 {
        revoked_until_recovery(events, i, k - 1);
    }
}

/// A revocation keeps the grant revoked until the next recovery, whether or
/// not its durable write completed.
proof fn theorem_revocation_keeps_grant_revoked_until_recovery(events: Seq<GrantEvent>, i: int)
    requires
        0 <= i < events.len(),
        events[i] is Revoke,
    ensures
        forall|k: int| i < k <= events.len() && #[trigger] no_recovery_between(events, i, k)
            ==> (grant_run(events, k)).revoked,
{
    assert forall|k: int| i < k <= events.len() && no_recovery_between(events, i, k)
        implies (#[trigger] grant_run(events, k)).revoked by {
        revoked_until_recovery(events, i, k);
    };
}

/// The theorem closes admission for a reusable grant until the next recovery.
proof fn revocation_denies_reusable_admission_until_recovery(
    events: Seq<GrantEvent>,
    i: int,
)
    requires
        0 <= i < events.len(),
        events[i] is Revoke,
    ensures
        forall|k: int| i < k <= events.len() && #[trigger] no_recovery_between(events, i, k)
            ==> !grant_admits(grant_run(events, k), false),
{
    theorem_revocation_keeps_grant_revoked_until_recovery(events, i);
}

/// A checked witness to the boundary of the restart guarantee: a recovery
/// that reads no marker for the grant reopens it. This is one trace and
/// states no general property.
proof fn witness_unacknowledged_revocation_reopens_at_recovery() {
    let recovered = seq![
        GrantEvent::Revoke { completed: false },
        GrantEvent::Restart { markers: Seq::empty() },
    ];
    assert(recovery_observes_acknowledged_markers(recovered));
    assert(!grant_admits(grant_run(recovered, 1), false));
    assert(grant_admits(grant_run(recovered, 2), false));
}

/// The model state of the grant as the store keeps it.
closed spec fn store_state(status: TokenStatus) -> GrantState {
    GrantState { revoked: status.revoked(), used: status.used() }
}

/// The store's revocation fence is the model's revoke transition.
fn apply_revocation(status: &mut TokenStatus, completed: bool)
    ensures
        store_state(*final(status))
            == grant_step(store_state(*old(status)), GrantEvent::Revoke { completed }),
{
    status.record_revocation();
}

/// The store's single-use consumption is the model's consume transition, and
/// the admission it reports is the model's.
fn apply_consumption(status: &mut TokenStatus, won: bool) -> (admitted: bool)
    ensures
        store_state(*final(status)) == grant_step(store_state(*old(status)), GrantEvent::Consume { won }),
        admitted == (won && grant_admits(store_state(*old(status)), true)),
{
    status.confirm_consumption(won)
}

/// The store's admission decision is the model's admission predicate.
fn store_admission(status: TokenStatus, single_use: bool) -> (allowed: bool)
    ensures allowed == grant_admits(store_state(status), single_use),
{
    matches!(status.admit(single_use), Admission::Allowed)
}

/// The store's startup recovery is the model's restart transition.
fn apply_recovery(markers: &[Marker]) -> (status: TokenStatus)
    ensures store_state(status) == grant_step(grant_initial(), GrantEvent::Restart { markers: markers@ }),
{
    proof {
        crate::token_authority::replay_keeps_markers(markers@);
    }
    TokenStatus::recover_markers(markers)
}

// ---- One principal ----

/// No resume transition occurs strictly between `i` and `k`.
closed spec fn no_resume_between(events: Seq<OperationEvent>, i: int, k: int) -> bool {
    forall|m: int| i < m < k ==> !(#[trigger] events[m] is Resume)
}

/// Once retirement has closed the principal, it stays closed until a resume.
proof fn retired_until_resume(events: Seq<OperationEvent>, i: int, k: int)
    requires
        0 <= i < k <= events.len(),
        events[i] is Retire,
        no_resume_between(events, i, k),
    ensures !operation_admits(operation_run(events, k)),
    decreases k - i,
{
    assert(operation_run(events, k) == operation_step(operation_run(events, k - 1), events[k - 1]));
    if i < k - 1 {
        retired_until_resume(events, i, k - 1);
    }
}

/// Retirement admits no operation until the principal is resumed. The
/// caller of the tracker resumes only once the kernel's retirement of the
/// principal has ended. Each engine instance has its own tracker.
proof fn theorem_retirement_admits_no_operation(events: Seq<OperationEvent>, i: int)
    requires
        0 <= i < events.len(),
        events[i] is Retire,
    ensures
        forall|k: int| i < k <= events.len()
            && #[trigger] no_resume_between(events, i, k)
            ==> !operation_admits(operation_run(events, k)),
{
    assert forall|k: int| i < k <= events.len()
        && no_resume_between(events, i, k)
        implies !operation_admits(#[trigger] operation_run(events, k)) by {
        retired_until_resume(events, i, k);
    };
}

/// The theorem covers an earlier resume. For an abstract trace with a
/// resume before the retirement and none after it, the final state admits
/// nothing.
proof fn retirement_closes_after_an_earlier_resume(events: Seq<OperationEvent>, i: int)
    requires
        2 < i < events.len() as int,
        events[2] is Resume,
        events[i] is Retire,
        no_resume_between(events, i, events.len() as int),
    ensures !operation_admits(operation_run(events, events.len() as int)),
{
    theorem_retirement_admits_no_operation(events, i);
}

/// A checked witness on a concrete trace: a resume before the retirement
/// does not reopen the principal after it, and the begin after the
/// retirement leaves the tracker in the same state.
proof fn witness_earlier_resume_does_not_reopen_retirement() {
    let trace = seq![
        OperationEvent::Begin,
        OperationEvent::Finish,
        OperationEvent::Resume,
        OperationEvent::Retire,
        OperationEvent::Begin,
    ];
    retirement_closes_after_an_earlier_resume(trace, 3);
    assert(operation_run(trace, 5) == operation_run(trace, 4));
}

/// The model state of the principal as the tracker keeps it.
closed spec fn tracker_state(state: &PrincipalInvocation) -> OperationState {
    OperationState { retired: state.is_retired(), active: state.active_count() as int }
}

/// The tracker's transitions are the model's, and the admission `begin`
/// reports is the model's below the machine bound on the active count.
fn apply_operation(state: &mut PrincipalInvocation, event: OperationEvent) -> (admitted: bool)
    ensures
        admitted
            == (event is Begin
                && operation_admits(tracker_state(old(state)))
                && old(state).active_count() < usize::MAX),
        (event is Begin && old(state).active_count() == usize::MAX)
            ==> tracker_state(final(state)) == tracker_state(old(state)),
        (event is Begin && old(state).active_count() < usize::MAX)
            || !(event is Begin)
            ==> tracker_state(final(state)) == operation_step(tracker_state(old(state)), event),
{
    match event {
        OperationEvent::Begin => state.begin(),
        OperationEvent::Finish => {
            state.finish();
            false
        },
        OperationEvent::Retire => {
            state.retire();
            false
        },
        OperationEvent::Resume => {
            state.resume();
            false
        },
    }
}

// ---- One fuel window ----

/// One transition of the fuel charged and promised to a principal under a
/// fixed budget, across its accounting windows.
enum FuelEvent {
    /// Promise the maximum fuel one invocation may consume.
    Reserve { requested: u64 },
    /// Release a promise and charge the fuel the invocation consumed. A
    /// metered call can consume more than it was promised before the meter
    /// traps, so the charge may exceed the promise.
    Settle { released: u64, actual: u64 },
    /// Start a new window. Charged fuel is dropped and promises are kept.
    Roll,
}

/// Charged and promised fuel over mathematical integers, and the fuel
/// settlements have charged beyond what they released.
struct FuelState {
    spent: int,
    reserved: int,
    excess: int,
}

closed spec fn fuel_initial() -> FuelState {
    FuelState { spent: 0, reserved: 0, excess: 0 }
}

/// A reservation fits when charged and promised fuel leave room for it.
closed spec fn fuel_admits(state: FuelState, requested: int, limit: u64) -> bool {
    state.spent + state.reserved + requested <= limit as int
}

/// The transition relation for one window.
closed spec fn fuel_step(state: FuelState, event: FuelEvent) -> FuelState {
    match event {
        FuelEvent::Reserve { requested } => FuelState {
            spent: state.spent,
            reserved: state.reserved + requested as int,
            excess: state.excess,
        },
        FuelEvent::Settle { released, actual } => FuelState {
            spent: if state.spent + actual as int > u64::MAX as int {
                u64::MAX as int
            } else {
                state.spent + actual as int
            },
            reserved: if released as int > state.reserved { 0 } else { state.reserved - released as int },
            excess: state.excess
                + if actual as int > released as int { actual as int - released as int } else { 0 },
        },
        FuelEvent::Roll => FuelState {
            spent: 0,
            reserved: state.reserved,
            excess: state.excess,
        },
    }
}

/// State of the window after the first `k` transitions of a trace.
spec fn fuel_run(events: Seq<FuelEvent>, k: int) -> FuelState
    recommends 0 <= k <= events.len(),
    decreases k,
{
    if k <= 0 {
        fuel_initial()
    } else {
        fuel_step(fuel_run(events, k - 1), events[k - 1])
    }
}

/// What production guarantees for one transition: a reservation fits, and a
/// settlement releases no more than it promised.
closed spec fn fuel_transition_is_admitted(events: Seq<FuelEvent>, k: int, limit: u64) -> bool {
    let state = fuel_run(events, k);
    match events[k] {
        FuelEvent::Reserve { requested } => fuel_admits(state, requested as int, limit),
        FuelEvent::Settle { released, .. } => released as int <= state.reserved,
        FuelEvent::Roll => true,
    }
}

/// The settlement at `events[k]` charges no more fuel than it released.
closed spec fn settlement_charges_within_promise(events: Seq<FuelEvent>, k: int) -> bool {
    match events[k] {
        FuelEvent::Settle { released, actual } => actual <= released,
        FuelEvent::Reserve { .. } | FuelEvent::Roll => true,
    }
}

proof fn committed_fuel_upto(events: Seq<FuelEvent>, limit: u64, k: int)
    requires
        0 <= k <= events.len(),
        forall|m: int| 0 <= m < events.len() ==> #[trigger] fuel_transition_is_admitted(events, m, limit),
    ensures
        0 <= fuel_run(events, k).excess,
        0 <= fuel_run(events, k).spent,
        fuel_run(events, k).spent + fuel_run(events, k).reserved
            <= limit as int + fuel_run(events, k).excess,
    decreases k,
{
    if k > 0 {
        committed_fuel_upto(events, limit, k - 1);
        assert(fuel_transition_is_admitted(events, k - 1, limit));
        let prior = fuel_run(events, k - 1);
        let next = fuel_run(events, k);
        assert(next == fuel_step(prior, events[k - 1]));
        match events[k - 1] {
            FuelEvent::Reserve { requested } => {
                assert(fuel_admits(prior, requested as int, limit));
                assert(next.spent + next.reserved == prior.spent + prior.reserved + requested as int);
                assert(next.excess == prior.excess);
                assert(next.spent == prior.spent);
            },
            FuelEvent::Settle { released, actual } => {
                assert(released as int <= prior.reserved);
                assert(next.reserved == prior.reserved - released as int);
                assert(next.excess
                    == prior.excess
                        + if actual as int > released as int { actual as int - released as int } else { 0 });
                if prior.spent + actual as int > u64::MAX as int {
                    assert(next.spent == u64::MAX as int);
                } else {
                    assert(next.spent == prior.spent + actual as int);
                }
            },
            FuelEvent::Roll => {
                assert(next.spent == 0);
                assert(next.reserved == prior.reserved);
                assert(next.excess == prior.excess);
            },
        }
    }
}

/// Charged and promised fuel never exceed the budget by more than the fuel
/// that settlements charged beyond what they released.
proof fn theorem_committed_fuel_is_budget_plus_charged_excess(events: Seq<FuelEvent>, limit: u64)
    requires
        forall|m: int| 0 <= m < events.len() ==> #[trigger] fuel_transition_is_admitted(events, m, limit),
    ensures
        forall|k: int| 0 <= k <= events.len() ==> #[trigger] fuel_run(events, k).spent
            + fuel_run(events, k).reserved
            <= limit as int + fuel_run(events, k).excess,
{
    assert forall|k: int| 0 <= k <= events.len() implies (#[trigger] fuel_run(events, k)).spent
        + fuel_run(events, k).reserved
        <= limit as int + fuel_run(events, k).excess by {
        committed_fuel_upto(events, limit, k);
    };
}

proof fn unexcessed_settlements_add_no_excess_upto(events: Seq<FuelEvent>, k: int)
    requires
        0 <= k <= events.len(),
        forall|m: int| 0 <= m < events.len() ==> #[trigger] settlement_charges_within_promise(events, m),
    ensures fuel_run(events, k).excess == 0,
    decreases k,
{
    if k > 0 {
        unexcessed_settlements_add_no_excess_upto(events, k - 1);
        assert(settlement_charges_within_promise(events, k - 1));
        match events[k - 1] {
            FuelEvent::Settle { released, actual } => {
                assert(actual <= released);
                assert(fuel_run(events, k).excess == fuel_run(events, k - 1).excess);
            },
            FuelEvent::Reserve { .. } | FuelEvent::Roll => {
                assert(fuel_run(events, k).excess == fuel_run(events, k - 1).excess);
            },
        }
    }
}

/// Charged and promised fuel never exceed the budget when no settlement
/// charges more than it released.
proof fn theorem_committed_fuel_stays_within_budget(events: Seq<FuelEvent>, limit: u64)
    requires
        forall|m: int| 0 <= m < events.len() ==> #[trigger] fuel_transition_is_admitted(events, m, limit),
        forall|m: int| 0 <= m < events.len() ==> #[trigger] settlement_charges_within_promise(events, m),
    ensures
        forall|k: int| 0 <= k <= events.len() ==> #[trigger] fuel_run(events, k).spent
            + fuel_run(events, k).reserved
            <= limit as int,
{
    theorem_committed_fuel_is_budget_plus_charged_excess(events, limit);
    assert forall|k: int| 0 <= k <= events.len() implies (#[trigger] fuel_run(events, k)).spent
        + fuel_run(events, k).reserved
        <= limit as int by {
        unexcessed_settlements_add_no_excess_upto(events, k);
    };
}

/// A checked witness that the bound is tight: a settlement charging fifty
/// beyond its promise leaves the window fifty over the budget, exactly the
/// excess charged.
proof fn witness_charged_excess_is_the_only_overshoot() {
    let trace = seq![
        FuelEvent::Reserve { requested: 100 },
        FuelEvent::Settle { released: 100, actual: 150 },
    ];
    let limit = 100u64;
    assert(fuel_transition_is_admitted(trace, 0, limit));
    assert(fuel_transition_is_admitted(trace, 1, limit));
    assert(fuel_run(trace, 2).spent + fuel_run(trace, 2).reserved == 150);
    assert(fuel_run(trace, 2).excess == 50);
}

/// The window the limiter's arithmetic reads. The excess is not an input of
/// that arithmetic.
closed spec fn arithmetic_state(spent: u64, reserved: u64) -> FuelState {
    FuelState { spent: spent as int, reserved: reserved as int, excess: 0 }
}

/// The limiter's reservation arithmetic decides the model's admission.
fn fuel_reservation_fits(spent: u64, reserved: u64, requested: u64, limit: u64) -> (fits: bool)
    ensures
        fits == fuel_admits(arithmetic_state(spent, reserved), requested as int, limit),
{
    crate::arithmetic::reservation_fits(spent, reserved, requested, limit)
}

/// The limiter's settlement arithmetic is the model's settle transition.
fn fuel_settlement(spent: u64, reserved: u64, released: u64, actual: u64) -> (next: (u64, u64))
    ensures
        next.0 as int
            == fuel_step(
                arithmetic_state(spent, reserved),
                FuelEvent::Settle { released, actual },
            ).spent,
        next.1 as int
            == fuel_step(
                arithmetic_state(spent, reserved),
                FuelEvent::Settle { released, actual },
            ).reserved,
{
    crate::arithmetic::settle_amounts(spent, reserved, released, actual)
}

}
