//! Remove exactly one validated device registration while preserving the others.

use vstd::prelude::*;

verus! {

pub(super) closed spec fn observed<T, F: Fn(&T) -> &str>(
    identify: F, registration: T, requested: &str, matched: bool,
) -> bool {
    exists|k: &str| identify.ensures((&registration,), k) && (k@ == requested@) == matched
}

/// The key projection in the profile adapter reads the record's fingerprint.
pub(super) fn remove_unique<T, F: Fn(&T) -> &str>(
    registrations: &mut Vec<T>, requested: &str, identify: F,
) -> (removed: Option<T>)
    requires forall|r: &T| #[trigger] identify.requires((r,)),
    ensures
        match removed {
            Some(device) => exists|index: int| 0 <= index < old(registrations).len()
                && device == old(registrations)@[index]
                && final(registrations)@ == old(registrations)@.remove(index)
                && forall|j: int| 0 <= j < old(registrations).len() ==>
                    observed(identify, #[trigger] old(registrations)@[j], requested, j == index),
            None => final(registrations)@ == old(registrations)@
                && ((forall|j: int| 0 <= j < old(registrations).len() ==>
                    observed(identify, #[trigger] old(registrations)@[j], requested, false))
                    || exists|i: int, j: int| 0 <= i < j < old(registrations).len()
                        && observed(identify, old(registrations)@[i], requested, true)
                        && observed(identify, old(registrations)@[j], requested, true)),
        },
{
    let mut found: Option<usize> = None;
    let mut i = 0usize;
    while i < registrations.len()
        invariant
            registrations@ == old(registrations)@,
            i <= registrations.len(),
            found matches Some(n) ==> n < i,
            forall|r: &T| #[trigger] identify.requires((r,)),
            forall|j: int| 0 <= j < i ==> observed(identify, #[trigger] registrations@[j], requested, found == Some(j as usize)),
        decreases registrations.len() - i,
    {
        let k = identify(&registrations[i]);
        assert(observed(identify, registrations@[i as int], requested, k@ == requested@));
        if k == requested {
            if let Some(_previous) = found {
                assert(observed(identify, registrations@[_previous as int], requested, true));
                return None;
            }
            found = Some(i);
        }
        i = i.saturating_add(1);
    }
    let index = found?;
    Some(registrations.remove(index))
}

}
