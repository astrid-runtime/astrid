//! Publish the running projection, durably mark retirement, then remove host state.

use super::{
    AstridHome, ReceiptPhase, RuntimePrincipalStore, StorageResult, active,
    is_exactly_pack_open_staging_journal, legacy_projection_pack, publish_active_projection,
    retire_projection, scan, transition_retiring_projection, tree_error, tree_io_error,
    validate_retiring_host_subset, validate_surviving_projection,
};

/// Publish current running projection changes, then retire their host files.
pub(super) fn pack_and_retire_projection(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
) -> StorageResult<()> {
    pack_and_retire_projection_with_retirement(home, store, retire_projection)
}

fn pack_and_retire_projection_with_retirement(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
    retire: impl FnOnce(&AstridHome) -> StorageResult<()>,
) -> StorageResult<()> {
    if home
        .layout_version()
        .map_err(|error| tree_io_error(&error))?
        .as_deref()
        == Some(astrid_core::dirs::LEGACY_LAYOUT_VERSION)
    {
        return legacy_projection_pack(home, store);
    }
    if validate_surviving_projection(home.root(), home.root())? {
        let receipt = active::read(home, store)?;
        match receipt {
            Some(receipt) if receipt.phase() == ReceiptPhase::Active => {
                publish_active_projection(home, store)?;
            },
            Some(receipt) => {
                let scanned = scan(home.root())?;
                validate_retiring_host_subset(home, &receipt, &scanned)?;
            },
            None => {
                let scanned = scan(home.root())?;
                if !scanned.is_empty() && !is_exactly_pack_open_staging_journal(&scanned) {
                    let names = scanned
                        .iter()
                        .map(|entry| entry.name().as_str())
                        .collect::<Vec<_>>();
                    return Err(tree_error(
                        home.root(),
                        format!(
                            "active projection receipt is missing for surviving host projection: {names:?}"
                        ),
                    ));
                }
            },
        }
    }
    transition_retiring_projection(home, store)?;
    store.require_volume_binding(home)?;
    retire(home)?;
    active::clear(store, home).map(|_| ())
}

#[cfg(all(test, unix))]
#[path = "retirement_crash_tests.rs"]
mod tests;
