//! Arithmetic for the fuel ledger's serialized per-principal transitions.

use vstd::prelude::*;

verus! {

/// Test whether the complete reservation fits a bounded fuel window.
/// The caller handles unlimited budgets before calling this function.
pub(super) fn reservation_fits(spent: u64, reserved: u64, requested: u64, limit: u64) -> (fits: bool)
    ensures
        fits == (spent as int + reserved as int + requested as int <= limit as int),
{
    let Some(committed) = spent.checked_add(reserved) else {
        return false;
    };
    let Some(total) = committed.checked_add(requested) else {
        return false;
    };
    total <= limit
}

/// Release a reservation and charge observed fuel. Saturation preserves the
/// ledger's conservative behavior if the meter exceeds its reserved bound.
pub(super) fn settle_amounts(
    spent: u64,
    reserved: u64,
    released: u64,
    actual: u64,
) -> (next: (u64, u64))
    ensures
        next.0 as int == if spent as int + actual as int > u64::MAX as int {
            u64::MAX as int
        } else {
            spent as int + actual as int
        },
        next.1 as int == if released > reserved { 0 } else { reserved as int - released as int },
        released <= reserved && actual <= released ==>
            next.0 as int + next.1 as int <= spent as int + reserved as int,
{
    (spent.saturating_add(actual), reserved.saturating_sub(released))
}

}
