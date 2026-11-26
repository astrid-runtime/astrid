//! Select a durable owner for an admitted guest namespace.

use vstd::prelude::*;

verus! {

fn same_bytes(left: &[u8], right: &[u8]) -> (equal: bool)
    ensures equal == (left@ == right@),
{
    if left.len() != right.len() { return false; }
    let mut i = 0;
    while i < left.len()
        invariant
            left.len() == right.len(),
            i <= left.len(),
            forall|j: int| 0 <= j < i ==> #[trigger] left@[j] == right@[j],
        decreases left.len() - i,
    {
        if left[i] != right[i] { return false; }
        i = i.saturating_add(1);
    }
    assert(left@ =~= right@);
    true
}

/// A stale binding or a different namespace cannot select any owner.
pub(super) fn select(
    admitted: &[u8],
    requested: &[u8],
    pinned: [u8; 32],
    observed: [u8; 32],
) -> (owner: Option<[u8; 32]>)
    ensures
        owner.is_some() == (admitted@ == requested@ && pinned@ == observed@),
        owner matches Some(uid) ==> uid@ == pinned@ && uid@ == observed@,
{
    if same_bytes(admitted, requested) && same_bytes(pinned.as_slice(), observed.as_slice()) {
        Some(pinned)
    } else {
        None
    }
}

}
