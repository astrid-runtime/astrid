//! Bind deletion to both the published inventory and the engine-owned volume.

use std::path::Path;

use astrid_core::dirs::AstridHome;

use super::{
    RuntimePrincipalStore, STAGING_JOURNAL_PROJECTION, active, content_name_from_relative,
    is_excluded, tree_error,
};
use crate::StorageResult;

/// Publish a complete inventory only while every captured file still matches.
pub(super) fn transition_retiring_projection(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
) -> StorageResult<()> {
    transition_retiring_with_hook(home, store, || Ok(()))
}

fn transition_retiring_with_hook(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
    before_publish: impl FnOnce() -> StorageResult<()>,
) -> StorageResult<()> {
    let name = active::active_projection_name()?;
    let expected = store
        .content()
        .describe(&super::StateOwner::System, &name)
        .map_err(|error| tree_error(home.root(), format!("inspect retiring receipt: {error}")))?
        .map(crate::content::ContentDescriptor::file);
    let Some(receipt) = active::read(home, store)? else {
        return Ok(());
    };
    if receipt.phase() == super::ReceiptPhase::Retiring {
        return Ok(());
    }
    let entries = super::active_projection_entries(home, store)?;
    let expectation = crate::content::ContentBatchExpectation::exact(
        entries
            .iter()
            .map(|entry| (entry.name.clone(), Some(entry.file)))
            .chain([(name.clone(), expected)]),
    );
    let receipt = super::receipt_ingest(home, super::ReceiptPhase::Retiring, &entries, None)?;
    before_publish()?;
    store.replace_contiguous_files_with_expectation(
        super::StateOwner::System,
        [receipt],
        &[],
        None,
        Some(&expectation),
    )?;
    store
        .content()
        .flush()
        .map_err(|error| tree_error(home.root(), format!("flush retiring receipt: {error}")))
}

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
    #[cfg(any(unix, windows))]
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
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (home, store, inventory, before_prepare);
        return Err(tree_error(
            home.root(),
            "projection retirement requires unix or windows",
        ));
    }
    // Do not clear the durable receipt if the public binding changed during
    // deletion, including after the core survivor and root barrier checks.
    // With a real NTFS directory-structure flush barrier, existing active::clear
    // after this function (pack_and_retire_projection) remains the Unix-parity path.
    store.require_volume_binding(home)
}

#[cfg(all(test, unix))]
mod tests;

#[cfg(test)]
mod publication_tests;
