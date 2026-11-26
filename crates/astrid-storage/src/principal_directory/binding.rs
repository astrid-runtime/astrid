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

pub(super) fn matches_pair(
    alias: &[u8], uid: &[u8; 32], forward: Option<&[u8; 32]>, reverse: Option<&[u8]>,
) -> (accepted: bool)
    ensures accepted == ((forward matches Some(f) && f@ == uid@)
        && (reverse matches Some(r) && r@ == alias@)),
{
    let (Some(f), Some(r)) = (forward, reverse) else { return false; };
    if f.as_slice() != uid.as_slice() || r != alias { return false; }
    assert(f@ =~= uid@);
    assert(r@ =~= alias@);
    true
}

}
