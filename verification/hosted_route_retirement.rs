//! A caller may keep evidence of retirement across later publication attempts.
use crate::route_gate::{GateState, RETIRED, release};
use vstd::prelude::*;

verus! {
fn late_publication<T>(gate: &GateState, pending: T) -> (out: Option<T>)
    ensures out.is_none(),
{
    let Tracked(receipt) = gate.retire();
    gate.publish();
    let _again = gate.retire();
    gate.publish();
    let observed = gate.read(Tracked(Some(&receipt)));
    assert(observed == RETIRED);
    release(observed, pending)
}
}
