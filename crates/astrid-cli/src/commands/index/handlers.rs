//! Thin command handlers used by dispatch.
//!
//! These functions intentionally accept command-independent argument structs;
//! clap parsing and output policy remain in the top-level CLI modules.

use super::{
    AddArgs, AddOutcome, IndexError, IndexListFormat, IndexStore, ListArgs, MetadataVerifier,
    RefreshTransport, RemoveArgs, RemoveOutcome, RootRotation, UpdateArgs, UpdateOutcome,
    UsageChecker,
};

/// Handle index add.
pub(crate) fn add_source(store: &IndexStore, args: AddArgs) -> Result<AddOutcome, IndexError> {
    store.add(args)
}

/// Handle index list.
pub(crate) fn list_sources(
    store: &IndexStore,
    format: IndexListFormat,
) -> Result<String, IndexError> {
    store.list(ListArgs { format })
}

/// Handle index remove.
pub(crate) fn remove_source<C: UsageChecker>(
    store: &IndexStore,
    args: RemoveArgs,
    usage: &C,
) -> Result<RemoveOutcome, IndexError> {
    store.remove(args, usage)
}

/// Handle index update.
pub(crate) fn update_source<T: RefreshTransport, V: MetadataVerifier>(
    store: &IndexStore,
    args: UpdateArgs,
    transport: &T,
    verifier: &V,
) -> Result<UpdateOutcome, IndexError> {
    store.update(args, transport, verifier)
}

/// Handle the explicit trust-root rotation path.
pub(crate) fn rotate_source_root<V: MetadataVerifier>(
    store: &IndexStore,
    rotation: RootRotation,
    verifier: &V,
) -> Result<super::IndexSource, IndexError> {
    store.rotate_root(rotation, verifier)
}
