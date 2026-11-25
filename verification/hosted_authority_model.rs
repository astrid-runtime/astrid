//! Abstract model of hosted authority and the theorems checked for it.
//!
//! This is the specification side of the hosted security contract. A trace
//! follows one grant, the operations of one principal, or the fuel charged to
//! one principal, through the transitions that change what it may do. The
//! `apply_*` and `fuel_*` functions perform each transition with the
//! production function the ledger, the capability store or the invocation
//! tracker calls, so the theorems constrain every sequence those functions
//! can produce. Whatever the model cannot see, it states as a condition on
//! the trace.

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
        forall|j: int| k <= j <= events.len() ==> grant_run(events, j).revoked,
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
        forall|j: int| i < j <= events.len() ==> grant_run(events, j).revoked,
{
    assert(grant_run(events, i + 1) == grant_step(grant_run(events, i), events[i]));
    vstd::seq_lib::lemma_seq_take_contains(events, i + 1, GrantEvent::Revoke { completed: true });
    vstd::seq_lib::lemma_seq_take_index(events, i + 1, i);
    revoked_persists(events, i + 1);
}

/// An acknowledged revocation denies admission for the rest of the trace,
/// across retries and restarts.
proof fn theorem_acknowledged_revocation_denies_admission(events: Seq<GrantEvent>, i: int)
    requires
        0 <= i <= events.len(),
        revocation_acknowledged_before(events, i),
        recovery_observes_acknowledged_markers(events),
    ensures
        forall|j: int| i <= j <= events.len() ==> !grant_admits(grant_run(events, j), false),
        forall|j: int| i <= j <= events.len() ==> !grant_admits(grant_run(events, j), true),
{
    let index = acknowledged_at(events, i, GrantEvent::Revoke { completed: true });
    acknowledged_revocation_closes(events, index);
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
        forall|j: int| k <= j <= events.len() ==> grant_run(events, j).used,
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
        forall|j: int| i < j <= events.len() ==> grant_run(events, j).used,
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

/// A single-use grant is consumed at most once in a trace, across retries
/// and restarts.
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

/// An acknowledged consumption closes single-use admission for the rest of
/// the trace.
proof fn theorem_acknowledged_consumption_denies_admission(events: Seq<GrantEvent>, i: int)
    requires
        0 <= i <= events.len(),
        consumption_acknowledged_before(events, i),
        recovery_observes_acknowledged_markers(events),
    ensures
        forall|j: int| i <= j <= events.len() ==> !grant_admits(grant_run(events, j), true),
{
    let index = acknowledged_at(events, i, GrantEvent::Consume { won: true });
    acknowledged_consumption_closes(events, index);
}

/// A revocation whose durable write did not complete fences live admission
/// until recovery reads markers that lack it. This is the boundary of the
/// restart guarantee.
proof fn theorem_unacknowledged_revocation_ends_at_recovery() {
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

/// Once retirement has closed the principal, it stays closed until a resume.
proof fn retired_until_resume(events: Seq<OperationEvent>, i: int, k: int)
    requires
        0 <= i < k <= events.len(),
        events[i] is Retire,
        forall|m: int| i < m < k ==> !(events[m] is Resume),
    ensures !operation_admits(operation_run(events, k)),
    decreases k - i,
{
    assert(operation_run(events, k) == operation_step(operation_run(events, k - 1), events[k - 1]));
    if i < k - 1 {
        retired_until_resume(events, i, k - 1);
        assert(!(events[k - 1] is Resume));
    }
}

/// Retirement admits no operation until the principal is resumed. The
/// caller of the tracker resumes only once the kernel's retirement of the
/// principal has ended.
proof fn theorem_retirement_admits_no_operation(events: Seq<OperationEvent>, i: int)
    requires
        0 <= i < events.len(),
        events[i] is Retire,
    ensures
        forall|k: int| i < k <= events.len()
            && !(events.take(k).contains(OperationEvent::Resume))
            ==> !operation_admits(operation_run(events, k)),
{
    assert forall|k: int| i < k <= events.len()
        && !(events.take(k).contains(OperationEvent::Resume))
        implies !operation_admits(operation_run(events, k)) by {
        assert forall|m: int| i < m < k implies !(events[m] is Resume) by {
            vstd::seq_lib::lemma_seq_take_contains(events, k, OperationEvent::Resume);
            vstd::seq_lib::lemma_seq_take_index(events, k, m);
        };
        retired_until_resume(events, i, k);
    };
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
        admitted ==> operation_admits(tracker_state(old(state))),
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

/// One transition of the fuel charged and promised to a principal in one
/// accounting window.
enum FuelEvent {
    /// Promise the maximum fuel one invocation may consume.
    Reserve { requested: u64 },
    /// Release a promise and charge the fuel the invocation consumed.
    Settle { released: u64, actual: u64 },
}

/// Charged and promised fuel over mathematical integers.
struct FuelState {
    spent: int,
    reserved: int,
}

closed spec fn fuel_initial() -> FuelState {
    FuelState { spent: 0, reserved: 0 }
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
        },
        FuelEvent::Settle { released, actual } => FuelState {
            spent: if state.spent + actual as int > u64::MAX as int {
                u64::MAX as int
            } else {
                state.spent + actual as int
            },
            reserved: if released as int > state.reserved { 0 } else { state.reserved - released as int },
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

/// The limiter's obligations for one transition: a reservation fits, and a
/// settlement releases no more than it promised and charges no more than it
/// released.
closed spec fn fuel_transition_is_admitted(events: Seq<FuelEvent>, k: int, limit: u64) -> bool {
    let state = fuel_run(events, k);
    match events[k] {
        FuelEvent::Reserve { requested } => fuel_admits(state, requested as int, limit),
        FuelEvent::Settle { released, actual } => {
            released as int <= state.reserved && actual <= released
        },
    }
}

proof fn committed_fuel_within_budget_upto(events: Seq<FuelEvent>, limit: u64, k: int)
    requires
        0 <= k <= events.len(),
        forall|m: int| 0 <= m < events.len() ==> #[trigger] fuel_transition_is_admitted(events, m, limit),
    ensures
        fuel_run(events, k).spent + fuel_run(events, k).reserved <= limit as int,
    decreases k,
{
    if k > 0 {
        committed_fuel_within_budget_upto(events, limit, k - 1);
        assert(fuel_transition_is_admitted(events, k - 1, limit));
    }
}

/// Charged and promised fuel never exceed the budget through any sequence of
/// admitted reservations and admitted settlements.
proof fn theorem_committed_fuel_stays_within_budget(events: Seq<FuelEvent>, limit: u64)
    requires
        forall|m: int| 0 <= m < events.len() ==> #[trigger] fuel_transition_is_admitted(events, m, limit),
    ensures
        forall|k: int| 0 <= k <= events.len() ==> fuel_run(events, k).spent
            + fuel_run(events, k).reserved
            <= limit as int,
{
    assert forall|k: int| 0 <= k <= events.len() implies fuel_run(events, k).spent
        + fuel_run(events, k).reserved
        <= limit as int by {
        committed_fuel_within_budget_upto(events, limit, k);
    };
}

/// The limiter's reservation arithmetic is the model's admission predicate.
fn fuel_reservation_fits(spent: u64, reserved: u64, requested: u64, limit: u64) -> (fits: bool)
    ensures
        fits == fuel_admits(FuelState { spent: spent as int, reserved: reserved as int }, requested as int, limit),
{
    crate::arithmetic::reservation_fits(spent, reserved, requested, limit)
}

/// The limiter's settlement arithmetic is the model's settle transition.
fn fuel_settlement(spent: u64, reserved: u64, released: u64, actual: u64) -> (next: (u64, u64))
    ensures
        next.0 as int
            == fuel_step(
                FuelState { spent: spent as int, reserved: reserved as int },
                FuelEvent::Settle { released, actual },
            ).spent,
        next.1 as int
            == fuel_step(
                FuelState { spent: spent as int, reserved: reserved as int },
                FuelEvent::Settle { released, actual },
            ).reserved,
{
    crate::arithmetic::settle_amounts(spent, reserved, released, actual)
}

}
