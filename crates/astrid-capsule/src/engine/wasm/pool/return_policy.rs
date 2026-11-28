//! Dispose of the same leased instance that passed through invocation cleanup.
use std::collections::HashMap;
use vstd::prelude::*;

verus! {
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Policy { Discard, ResetAndReuse, PreserveAndReuse }

/// Only a completed free-checkout return needs an occupancy scan.
pub(super) fn policy<V, F: FnOnce() -> bool>(healthy: bool, free: bool, responses: &HashMap<u64, V>, empty: F) -> (decision: Policy)
    requires vstd::std_specs::hash::hash_map_inv(responses),
        healthy && free && responses@.len() == 0 ==> empty.requires(()),
    ensures if !healthy { decision == Policy::Discard }
        else if !free { decision == Policy::PreserveAndReuse }
        else if responses@.len() != 0 { decision == Policy::Discard }
        else { exists|observed: bool| #[trigger] empty.ensures((), observed)
            && decision == (if observed { Policy::ResetAndReuse } else { Policy::Discard }) },
{
    if !healthy { Policy::Discard }
    else if !free { Policy::PreserveAndReuse }
    else if !responses.is_empty() { Policy::Discard }
    else if empty() { Policy::ResetAndReuse }
    else { Policy::Discard }
}

pub(super) enum Returned<T> { Retired(T), Warm(T) }

/// Retain the cleanup result in both variants so the native caller can only
/// enqueue the value returned by cleanup on the warm path.
pub(super) fn finish<T, F: FnOnce(T, bool) -> T>(decision: Policy, instance: T, clear: F)
    -> (returned: Returned<T>)
    requires clear.requires((instance, decision != Policy::PreserveAndReuse)),
    ensures match returned {
        Returned::Warm(clean) => decision != Policy::Discard
            && clear.ensures((instance, decision == Policy::ResetAndReuse), clean),
        Returned::Retired(clean) => decision == Policy::Discard && clear.ensures((instance, true), clean),
    },
{
    let reset = !matches!(decision, Policy::PreserveAndReuse);
    let clean = clear(instance, reset);
    match decision {
        Policy::Discard => Returned::Retired(clean),
        _ => Returned::Warm(clean),
    }
}

/// Rotate the host table and revoke all live HTTP response entries together.
pub(super) fn reset_resources<T, V, F: FnOnce() -> T>(
    table: &mut T, responses: &mut HashMap<u64, V>, reset: bool, fresh: F,
)
    requires vstd::std_specs::hash::hash_map_inv(old(responses)), reset ==> fresh.requires(()),
    ensures vstd::std_specs::hash::hash_map_inv(final(responses)),
        if reset {
            fresh.ensures((), *final(table)) && final(responses)@ == Map::empty()
        } else {
            *final(table) == *old(table) && final(responses)@ == old(responses)@
        },
{
    if reset {
        *table = fresh();
        responses.clear();
    }
}

}
