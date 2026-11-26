//! Admission of a decoded operation on a private storage mount callback.
use vstd::prelude::*;
use astrid_core::storage_filesystem::StorageFilesystemOperationV1 as Operation;

verus! {

pub(crate) fn live(revoked: bool, now: u64, expires: u64) -> (accepted: bool)
    ensures accepted == (!revoked && now <= expires),
{
    !revoked && now <= expires
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum OperationClass { Read, Write, Sync }

pub(crate) open spec fn access_class(operation: Operation) -> OperationClass {
    match operation {
        Operation::Write { .. } | Operation::SetLength { .. } | Operation::Create { .. }
            | Operation::Remove { .. } | Operation::Rename { .. } => OperationClass::Write,
        Operation::VolumeInfo | Operation::Stat { .. } | Operation::ReadDirectory { .. }
            | Operation::Read { .. } => OperationClass::Read,
        Operation::Sync => OperationClass::Sync,
    }
}

fn operation_class(operation: &Operation) -> (class: OperationClass)
    ensures class == access_class(*operation),
{
    match operation {
        Operation::VolumeInfo | Operation::Stat { .. } | Operation::ReadDirectory { .. }
            | Operation::Read { .. } => OperationClass::Read,
        Operation::Write { .. }
        | Operation::SetLength { .. }
        | Operation::Create { .. }
        | Operation::Remove { .. }
        | Operation::Rename { .. } => OperationClass::Write,
        Operation::Sync => OperationClass::Sync,
    }
}

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

pub(crate) fn admit<L>(
    lease: L, live: bool, authenticated: bool, writable: bool, operation: Operation,
) -> (outcome: Admission<L, Operation>)
    ensures
        (outcome is Stale) == !live,
        (outcome is Unauthorized) == (live && !authenticated),
        (outcome is ReadOnly) == (live && authenticated && access_class(operation) == OperationClass::Write && !writable),
        (outcome is Accepted) == (live && authenticated && (access_class(operation) != OperationClass::Write || writable)),
        outcome matches Admission::Accepted(actual) ==> actual.binding() == (lease, operation, access_class(operation)),
{
    let class = operation_class(&operation);
    if !live { Admission::Stale }
    else if !authenticated { Admission::Unauthorized }
    else if !class.permits(writable) { Admission::ReadOnly }
    else { Admission::Accepted(Admitted { lease, operation, class }) }
}

}
