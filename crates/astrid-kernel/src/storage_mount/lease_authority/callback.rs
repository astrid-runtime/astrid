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
}

/// Immutable scope and backing selected when the lease is issued.
pub(crate) struct Issued<T, B> {
    pub(crate) scope: T,
    pub(crate) backing: B,
}

impl<T, B> Issued<T, B> {
    pub(crate) fn bind<L>(&self, lease: L) -> (bound: Destinations<L, &T, &B>)
        ensures bound.parts().0 == lease, *bound.parts().1 == self.scope, *bound.parts().2 == self.backing,
    {
        Destinations { lease, mount: &self.scope, backing: &self.backing }
    }
}

pub(crate) struct Destinations<L, T, H> {
    lease: L,
    mount: T,
    backing: H,
}

impl<L, T, H> Destinations<L, T, H> {
    pub(crate) closed spec fn parts(self) -> (L, T, H) {
        (self.lease, self.mount, self.backing)
    }
}

pub(crate) enum Effect<L, T, H> {
    Volume(L, T, H),
    Filesystem(L, T, H, Operation, OperationClass),
}

impl<L, T, H> Admitted<Destinations<L, T, H>, Operation> {
    pub(crate) fn into_effect(self) -> (effect: Effect<L, T, H>)
        ensures
            (effect is Volume) == (self.binding().1 is VolumeInfo),
            effect matches Effect::Volume(lease, scope, backing) ==> lease == self.binding().0.parts().0 &&
                scope == self.binding().0.parts().1 && backing == self.binding().0.parts().2,
            effect matches Effect::Filesystem(lease, target, home, op, class) ==>
                lease == self.binding().0.parts().0 && target == self.binding().0.parts().1 &&
                home == self.binding().0.parts().2 && op == self.binding().1 && class == self.binding().2,
    {
        let destinations = self.lease;
        match self.operation {
            Operation::VolumeInfo => Effect::Volume(destinations.lease, destinations.mount, destinations.backing),
            operation => Effect::Filesystem(destinations.lease, destinations.mount,
                destinations.backing, operation, self.class),
        }
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
