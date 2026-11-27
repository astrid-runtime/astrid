//! Proposed counter value for an atomic reservation at its observed occupancy.
use vstd::prelude::*;

verus! {
pub(super) fn reserve(count: usize, limit: usize) -> (next: Option<usize>)
    ensures if count < limit {
        next matches Some(n) && n as int == count as int + 1 && n <= limit
    } else { next.is_none() },
{
    if count < limit { Some(count + 1) } else { None }
}
}
