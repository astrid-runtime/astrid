//! Check an admitted viewer against the instance's immutable owner, if any.

use vstd::prelude::*;

verus! {

pub(super) fn matches(owner: Option<&[u8; 32]>, viewer: &[u8; 32]) -> (accepted: bool)
    ensures accepted == (match owner { Some(uid) => uid@ == viewer@, None => true }),
{
    let Some(uid) = owner else { return true; };
    if uid.as_slice() != viewer.as_slice() { return false; }
    assert(uid@ =~= viewer@);
    true
}

}
