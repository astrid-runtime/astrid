//! Owner check shared by hosted load, run-loop initialization and interception.
use vstd::prelude::*;

verus! {

pub(super) fn accepts(expected: Option<[u8; 32]>, observed: Option<[u8; 32]>) -> (admitted: bool)
    ensures admitted == match expected {
        None => true,
        Some(owner) => observed matches Some(uid) && uid@ == owner@,
    },
{
    match (expected, observed) {
        (None, _) => true,
        (Some(owner), Some(uid)) => {
            if uid.as_slice() != owner.as_slice() { return false; }
            assert(uid@ =~= owner@);
            true
        },
        (Some(_), None) => false,
    }
}

}
