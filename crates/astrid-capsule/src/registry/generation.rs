//! Generation allocation under the capsule registry write lock.

use vstd::prelude::*;

verus! {

pub(super) fn reserve(next: &mut u64) -> (generation: Option<u64>)
    ensures
        generation.is_some() == (*old(next) < u64::MAX),
        generation matches Some(value) ==> value == *old(next) && *final(next) as int == value as int + 1,
        generation.is_none() ==> *final(next) == *old(next),
{
    let current = *next;
    let successor = current.checked_add(1)?;
    *next = successor;
    Some(current)
}

}
