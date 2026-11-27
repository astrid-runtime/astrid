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

/// Issue the selected runtime key together with the generation consumed for it.
pub(super) fn issue<K,R,F: FnOnce(K,u64) -> R>(next: &mut u64, key: K, make: F) -> (out: Option<R>)
    requires *old(next) < u64::MAX ==> make.requires((key,*old(next))),
    ensures out.is_some() == (*old(next) < u64::MAX),
        out matches Some(r) ==> make.ensures((key,*old(next)),r) && *final(next) as int == *old(next) as int + 1,
        out.is_none() ==> *final(next) == *old(next),
{
    let generation = reserve(next)?;
    Some(make(key,generation))
}

}
