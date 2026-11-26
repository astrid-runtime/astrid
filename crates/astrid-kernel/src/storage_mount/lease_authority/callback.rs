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

/// One-use evidence for the effect executor. Only admission can construct it.
pub(crate) struct Admitted<L, O> {
    lease: L,
    operation: O,
    class: OperationClass,
}

impl<L, O> Admitted<L, O> {
    pub(crate) closed spec fn binding(self) -> (L, O, OperationClass) {
        (self.lease, self.operation, self.class)
    }

    pub(crate) fn into_effect(self) -> (effect: (L, O, OperationClass))
        ensures effect == self.binding(),
    {
        (self.lease, self.operation, self.class)
    }
}

pub(crate) enum Admission<L, O> { Stale, Unauthorized, ReadOnly, Accepted(Admitted<L, O>) }

pub(crate) fn admit<L, O>(
    lease: L, live: bool, authenticated: bool, writable: bool, operation: O, class: OperationClass,
) -> (outcome: Admission<L, O>)
    ensures
        (outcome is Stale) == !live,
        (outcome is Unauthorized) == (live && !authenticated),
        (outcome is ReadOnly) == (live && authenticated && class == OperationClass::Write && !writable),
        (outcome is Accepted) == (live && authenticated && (class != OperationClass::Write || writable)),
        outcome matches Admission::Accepted(actual) ==> actual.binding() == (lease, operation, class),
{
    if !live { Admission::Stale }
    else if !authenticated { Admission::Unauthorized }
    else if !class.permits(writable) { Admission::ReadOnly }
    else { Admission::Accepted(Admitted { lease, operation, class }) }
}

}
