//! Match a consent reply to the host-stamped request.

use vstd::prelude::*;

verus! {

pub(super) fn matches(principal: &[u8], owner: u128, stamped: Option<&[u8]>, stamped_owner: Option<u128>) -> (accept: bool)
    ensures accept == (stamped matches Some(bytes) && bytes@ == principal@ && stamped_owner == Some(owner)),
{
    let Some(bytes) = stamped else { return false; };
    if bytes != principal { return false; }
    assert(bytes@ =~= principal@);
    match stamped_owner { Some(actual) => actual == owner, None => false }
}

}
