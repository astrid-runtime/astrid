//! Admission of a decoded operation on a private storage mount callback.
use vstd::prelude::*;

verus! {

pub(crate) fn live(revoked: bool, now: u64, expires: u64) -> (accepted: bool)
    ensures accepted == (!revoked && now <= expires),
{
    !revoked && now <= expires
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum OperationClass { Read, Write, Sync }

impl OperationClass {
    pub(crate) fn permits(self, writable: bool) -> (accepted: bool)
        ensures accepted == (self != Self::Write || writable),
    {
        match self { Self::Read | Self::Sync => true, Self::Write => writable }
    }
    pub(crate) fn requires_serialization(self) -> (serialized: bool)
        ensures serialized == (self == Self::Write || self == Self::Sync),
    {
        match self { Self::Read => false, Self::Write | Self::Sync => true }
    }
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
