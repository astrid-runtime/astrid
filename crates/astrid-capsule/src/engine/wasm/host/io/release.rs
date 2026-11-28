//! Adapt Wasmtime ownership, typed lookup and child edges to checked disposal.
use super::disposal::{Refusal, dispose};
use wasmtime::component::{Resource, ResourceTable, ResourceTableError};

pub(super) fn from_table<'a, H: 'static, R>(
    table: &'a mut ResourceTable,
    handle: Resource<H>,
    remove: impl FnOnce(&'a mut ResourceTable, Resource<H>) -> R,
) -> wasmtime::Result<R> {
    dispose(
        table,
        handle,
        Resource::owned,
        |table, handle| -> Result<bool, ResourceTableError> {
            table.get(handle)?;
            Ok(table.iter_children(handle)?.next().is_some())
        },
        remove,
    )
    .map_err(|reason| match reason {
        Refusal::Borrowed => wasmtime::format_err!("cannot drop a borrowed resource"),
        Refusal::Table(error) => wasmtime::Error::from(error),
        Refusal::HasChildren => ResourceTableError::HasChildren.into(),
    })
}
