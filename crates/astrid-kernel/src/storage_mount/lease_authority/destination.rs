//! Select the system administration projection only for writes on the system root.
use super::callback::{OperationClass, operation_class};
use super::subtree::{BoundSubtree, Owner};
use astrid_core::storage_filesystem::StorageFilesystemOperationV1 as Operation;
use vstd::prelude::*;

verus! {

#[derive(Clone, Copy)]
pub(crate) enum Target<P, F, W> {
    OwnerRoot(Owner<P,F>),
    WorkspaceBranch(Owner<P,F>, W),
    Subtree(BoundSubtree<P,F>),
}

pub(crate) enum Backend<P, F, W> {
    SystemProjection,
    Filesystem(Target<P,F,W>),
}

impl<P, F, W> Target<P,F,W> {
    pub(crate) fn backend(self, operation: &Operation) -> (result: Backend<P,F,W>)
        ensures
            (result is SystemProjection) ==
                ((self matches Self::OwnerRoot(Owner::System)) && super::callback::access_class(*operation) == OperationClass::Write),
            result matches Backend::Filesystem(target) ==> target == self,
    {
        match (&self, operation_class(operation)) {
            (Self::OwnerRoot(Owner::System), OperationClass::Write) => Backend::SystemProjection,
            _ => Backend::Filesystem(self),
        }
    }
}

}
