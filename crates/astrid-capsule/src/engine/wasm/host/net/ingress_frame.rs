//! Select the authenticated connection identity for one completed read.

use vstd::prelude::*;

verus! {

pub(super) fn select<T>(uplink: bool, data: bool, binding: Option<T>) -> (stamp: Option<T>)
    ensures stamp == if uplink && data { binding } else { None },
{
    if uplink && data { binding } else { None }
}

}
