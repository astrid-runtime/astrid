//! Immutable owner selection for staged principal operations.

use vstd::prelude::*;

verus! {

pub(super) fn select(expected: Option<[u8; 32]>, observed: [u8; 32]) -> (owner: Option<[u8; 32]>)
    ensures
        owner.is_some() == (match expected { None => true, Some(uid) => uid@ == observed@ }),
        owner matches Some(uid) ==> uid@ == observed@ && (match expected { None => true, Some(pinned) => pinned@ == uid@ }),
{
    match expected {
        Some(uid) if uid.as_slice() != observed.as_slice() => None,
        Some(uid) => { assert(uid@ =~= observed@); Some(uid) },
        None => Some(observed),
    }
}

}
