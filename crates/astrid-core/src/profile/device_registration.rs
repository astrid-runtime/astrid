//! Resolve and remove device registrations by unique fingerprint.

use vstd::prelude::*;

verus! {

pub(super) closed spec fn observed<T, F: Fn(&T) -> &str>(
    identify: F, registration: T, requested: &str, matched: bool,
) -> bool {
    exists|k: &str| identify.ensures((&registration,), k) && (k@ == requested@) == matched
}

/// Return the unique matching index shared by live admission and revocation.
fn unique_index<T, F: Fn(&T) -> &str>(
    registrations: &[T], requested: &str, identify: F,
) -> (index: Option<usize>)
    requires forall|r: &T| #[trigger] identify.requires((r,)),
    ensures
        match index {
            Some(i) => i < registrations.len()
                && forall|j: int| 0 <= j < registrations.len() ==>
                    observed(identify, #[trigger] registrations@[j], requested, j == i),
            None => (forall|j: int| 0 <= j < registrations.len() ==>
                    observed(identify, #[trigger] registrations@[j], requested, false))
                || exists|i: int, j: int| 0 <= i < j < registrations.len()
                    && observed(identify, registrations@[i], requested, true)
                    && observed(identify, registrations@[j], requested, true),
        },
{
    let mut found: Option<usize> = None;
    let mut i = 0usize;
    while i < registrations.len()
        invariant
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
    found
}

pub(super) fn resolve_unique<'a, T, F: Fn(&T) -> &str>(
    registrations: &'a [T], requested: &str, identify: F,
) -> (selected: Option<&'a T>)
    requires forall|r: &T| #[trigger] identify.requires((r,)),
    ensures
        match selected {
            Some(device) => exists|i: int| 0 <= i < registrations.len()
                && *device == registrations@[i]
                && forall|j: int| 0 <= j < registrations.len() ==>
                    observed(identify, #[trigger] registrations@[j], requested, j == i),
            None => (forall|j: int| 0 <= j < registrations.len() ==>
                    observed(identify, #[trigger] registrations@[j], requested, false))
                || exists|i: int, j: int| 0 <= i < j < registrations.len()
                    && observed(identify, registrations@[i], requested, true)
                    && observed(identify, registrations@[j], requested, true),
        },
{
    let index = unique_index(registrations, requested, identify)?;
    Some(&registrations[index])
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
    let index = unique_index(registrations.as_slice(), requested, identify)?;
    Some(registrations.remove(index))
}

}
