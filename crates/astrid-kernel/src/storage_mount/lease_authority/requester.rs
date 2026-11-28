//! Owner-local control of a live native mount lease.
use vstd::prelude::*;

verus! {

pub(crate) fn same_requester(issued: Option<[u8; 32]>, caller: Option<[u8; 32]>) -> (accepted: bool)
    ensures accepted == (issued matches Some(owner) && caller matches Some(uid) && uid@ == owner@),
{
    let (Some(owner), Some(uid)) = (issued, caller) else { return false; };
    if uid.as_slice() != owner.as_slice() { return false; }
    assert(uid@ =~= owner@);
    true
}

}
