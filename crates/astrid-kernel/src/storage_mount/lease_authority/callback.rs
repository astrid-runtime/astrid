//! Admission of a decoded operation on a private storage mount callback.
use vstd::prelude::*;

verus! {

pub(crate) fn live(revoked: bool, now: u64, expires: u64) -> (accepted: bool)
    ensures accepted == (!revoked && now <= expires),
{
    !revoked && now <= expires
}

pub(crate) enum Admission<T> { Stale, Unauthorized, Accepted(T) }

pub(crate) fn admit<T>(live: bool, authenticated: bool, operation: T) -> (outcome: Admission<T>)
    ensures
        (outcome is Stale) == !live,
        (outcome is Unauthorized) == (live && !authenticated),
        (outcome is Accepted) == (live && authenticated),
        outcome matches Admission::Accepted(actual) ==> actual == operation,
{
    if !live { Admission::Stale }
    else if !authenticated { Admission::Unauthorized }
    else { Admission::Accepted(operation) }
}

}
