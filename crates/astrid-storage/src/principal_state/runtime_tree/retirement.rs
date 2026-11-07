//! Bind deletion to both the published inventory and the engine-owned volume.

use std::path::Path;

use astrid_core::dirs::AstridHome;

use super::{
    RuntimePrincipalStore, STAGING_JOURNAL_PROJECTION, active, content_name_from_relative,
    is_excluded, tree_error,
};
use crate::StorageResult;

enum Inventory {
    Current(Option<active::ActiveProjectionReceipt>),
    Legacy(Vec<crate::content::ContentEntry>),
}

impl Inventory {
    fn require_file(&self, home: &AstridHome, relative: &Path) -> StorageResult<()> {
        let source = home.root().join(relative);
        let name = content_name_from_relative(&source, home.root())?;
        if is_excluded(name.as_str()) {
            return Ok(());
        }
        let published = match self {
            Self::Current(Some(receipt)) => receipt.contains_inventory_name(name.as_str()),
            Self::Current(None) => name.as_str() == STAGING_JOURNAL_PROJECTION,
            Self::Legacy(entries) => entries
                .binary_search_by(|entry| entry.name().as_str().cmp(name.as_str()))
                .is_ok(),
        };
        if !published {
            return Err(tree_error(
                &source,
                "retiring projection contains unreceipted host file",
            ));
        }
        Ok(())
    }
}

pub(super) fn retire_current_projection(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
) -> StorageResult<()> {
    retire_current_with_hook(home, store, || Ok(()))
}

fn retire_current_with_hook(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
    before_prepare: impl FnOnce() -> StorageResult<()>,
) -> StorageResult<()> {
    let receipt = active::read(home, store)?;
    if let Some(receipt) = &receipt
        && receipt.phase() != super::ReceiptPhase::Retiring
    {
        return Err(tree_error(
            home.root(),
            "projection receipt is not RETIRING",
        ));
    }
    let inventory = Inventory::Current(receipt);
    retire(home, store, &inventory, before_prepare)
}

pub(super) fn retire_legacy_projection(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
) -> StorageResult<()> {
    // Legacy packing admits sources that current-layout restoration deliberately
    // omits, including the retired SQLite/COW paths. Validate their publication
    // against the complete durable catalog, not the current projection view.
    let mut entries = store
        .content()
        .list(&super::StateOwner::System)
        .map_err(|error| tree_error(home.root(), format!("list legacy retirement: {error}")))?;
    entries.sort_by(|left, right| left.name().as_str().cmp(right.name().as_str()));
    retire(home, store, &Inventory::Legacy(entries), || Ok(()))
}

fn retire(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
    inventory: &Inventory,
    before_prepare: impl FnOnce() -> StorageResult<()>,
) -> StorageResult<()> {
    #[cfg(unix)]
    {
        // Capture from the actual engine owner, before preflight can observe
        // a pathname replacement. This clone conveys identity, not a new open.
        let volume = store.retirement_volume_file(home)?;
        before_prepare()?;
        let prepared = astrid_core::dirs::PreparedProjectionRetirement::prepare(home.root())
            .map_err(|error| tree_error(home.root(), format!("prepare retirement: {error}")))?;
        for relative in prepared.regular_files() {
            inventory.require_file(home, relative)?;
        }
        prepared
            .retire(&volume)
            .map_err(|error| tree_error(home.root(), format!("retire projection: {error}")))?;
    }
    #[cfg(not(unix))]
    {
        store.require_volume_binding(home)?;
        before_prepare()?;
        for entry in super::scan(home.root())? {
            let relative = entry
                .source_path
                .strip_prefix(home.root())
                .map_err(|error| {
                    tree_error(home.root(), format!("validate retirement path: {error}"))
                })?;
            inventory.require_file(home, relative)?;
        }
        astrid_core::dirs::retire_projection_root(home.root())
            .map_err(|error| tree_error(home.root(), format!("retire projection: {error}")))?;
    }
    // Do not clear the durable receipt if the public binding changed during
    // deletion, including after the core survivor and root barrier checks.
    store.require_volume_binding(home)
}

#[cfg(all(test, unix))]
mod tests;
