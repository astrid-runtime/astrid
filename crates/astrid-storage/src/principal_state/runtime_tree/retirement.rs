//! Bind deletion to both the published inventory and the engine-owned volume.

#[cfg(any(unix, windows))]
use std::collections::BTreeSet;
use std::path::Path;

use astrid_core::dirs::AstridHome;

use super::{
    RuntimePrincipalStore, STAGING_JOURNAL_PROJECTION, active, content_name_from_relative,
    is_excluded, tree_error,
};
use crate::StorageResult;
use crate::engine::PrincipalProjectionEngine;

mod publication;
pub(super) use publication::publish_retiring_projection;

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
    // No host payloads are rewritten on restoration's inventory-only path.
    // The shared empty-snapshot contract retains the complete durable catalog.
    publication::publish_with_hook(home, store, Vec::new(), before_publish)
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

#[cfg(test)]
pub(super) fn retire_current_projection(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
) -> StorageResult<()> {
    prepare_current_projection(home, store)?.retire()
}

pub(super) fn prepare_current_projection<'a>(
    home: &'a AstridHome,
    store: &'a RuntimePrincipalStore,
) -> StorageResult<PreparedRetirement<'a>> {
    prepare_current_with_hook(home, store, || Ok(()), None)
}

/// Restoration is volume-authoritative for retained siblings. Authenticate the
/// selected deletion sources while retaining the same complete namespace,
/// RETIRING receipt, owner-root, and actual volume capture checks.
pub(super) fn prepare_empty_projection<'a>(
    home: &'a AstridHome,
    store: &'a RuntimePrincipalStore,
    selected: &[std::path::PathBuf],
) -> StorageResult<PreparedRetirement<'a>> {
    prepare_current_with_hook(home, store, || Ok(()), Some(selected))
}

#[cfg(all(test, unix))]
fn retire_current_with_hook(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
    before_prepare: impl FnOnce() -> StorageResult<()>,
) -> StorageResult<()> {
    prepare_current_with_hook(home, store, before_prepare, None)?.retire()
}

fn prepare_current_with_hook<'a>(
    home: &'a AstridHome,
    store: &'a RuntimePrincipalStore,
    before_prepare: impl FnOnce() -> StorageResult<()>,
    selected: Option<&[std::path::PathBuf]>,
) -> StorageResult<PreparedRetirement<'a>> {
    let root = store
        .engine
        .current_root(&super::StateOwner::System)
        .map_err(|error| {
            tree_error(
                home.root(),
                format!("capture retirement validation root: {error}"),
            )
        })?;
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
    let prepared = prepare(home, store, &inventory, before_prepare, selected)?;
    if store
        .engine
        .current_root(&super::StateOwner::System)
        .map_err(|error| {
            tree_error(
                home.root(),
                format!("confirm retirement validation root: {error}"),
            )
        })?
        != root
    {
        return Err(tree_error(
            home.root(),
            "retirement catalog changed during source validation",
        ));
    }
    Ok(prepared)
}

#[cfg(any(unix, windows))]
fn is_selected_source(scopes: Option<&BTreeSet<&Path>>, relative: &Path) -> bool {
    scopes.is_none_or(|scopes| {
        relative
            .ancestors()
            .any(|ancestor| scopes.contains(ancestor))
    })
}

#[cfg(test)]
pub(super) fn after_final_publication(home: &AstridHome) -> StorageResult<()> {
    publication::tests::after_final_publication(home)
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
    prepare(home, store, &Inventory::Legacy(entries), || Ok(()), None)?.retire()
}

fn prepare<'a>(
    home: &'a AstridHome,
    store: &'a RuntimePrincipalStore,
    inventory: &Inventory,
    before_prepare: impl FnOnce() -> StorageResult<()>,
    selected: Option<&[std::path::PathBuf]>,
) -> StorageResult<PreparedRetirement<'a>> {
    #[cfg(any(unix, windows))]
    {
        // Capture from the actual engine owner, before preflight can observe
        // a pathname replacement. This clone conveys identity, not a new open.
        let volume = store.retirement_volume_file(home)?;
        before_prepare()?;
        let started = std::time::Instant::now();
        let prepared = match inventory {
            Inventory::Current(Some(receipt)) => {
                // Index this captured selection once. Scanning every UID scope
                // for every file makes bootstrap quadratic in the agent count.
                // Ancestors retain the same component-prefix admission rule.
                let selected_sources = selected.map(|scopes| {
                    scopes
                        .iter()
                        .map(|scope| scope.as_path())
                        .collect::<BTreeSet<_>>()
                });
                astrid_core::dirs::PreparedProjectionRetirement::prepare_checked(
                    home.root(),
                    |relative| {
                        source::should_check(relative)
                            && is_selected_source(selected_sources.as_ref(), relative)
                    },
                    |relative, source| {
                        inventory
                            .require_file(home, relative)
                            .and_then(|()| {
                                source::verify_file(home, store, receipt, source, relative)
                            })
                            .map_err(std::io::Error::other)
                    },
                )
            },
            _ => astrid_core::dirs::PreparedProjectionRetirement::prepare(home.root()),
        }
        .map_err(|error| tree_error(home.root(), format!("prepare retirement: {error}")))?;
        if !matches!(inventory, Inventory::Current(Some(_))) {
            for relative in prepared.regular_files() {
                inventory.require_file(home, relative)?;
            }
        }
        tracing::debug!(elapsed = ?started.elapsed(), "captured and validated projection retirement sources");
        Ok(PreparedRetirement {
            home,
            store,
            prepared,
            volume,
        })
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (home, store, inventory, before_prepare, selected);
        return Err(tree_error(
            home.root(),
            "projection retirement requires unix or windows",
        ));
    }
}

/// Complete preflight bound to the same engine volume and captured host entries.
/// Dropping this value performs no deletion and leaves RETIRING recovery intact.
pub(super) struct PreparedRetirement<'a> {
    home: &'a AstridHome,
    store: &'a RuntimePrincipalStore,
    #[cfg(any(unix, windows))]
    prepared: astrid_core::dirs::PreparedProjectionRetirement,
    #[cfg(any(unix, windows))]
    volume: std::fs::File,
}

impl PreparedRetirement<'_> {
    /// Reuse complete receipt/source capture and the same volume-bound plan.
    pub(super) fn retire_empty_subtrees(
        self,
        selected: &[std::path::PathBuf],
        authorize: impl FnMut(&Path, astrid_core::dirs::RetirementEntryKind) -> std::io::Result<()>,
    ) -> StorageResult<()> {
        #[cfg(any(unix, windows))]
        self.prepared
            .retire_empty_subtrees(&self.volume, selected, authorize)
            .map_err(|error| {
                tree_error(
                    self.home.root(),
                    format!("retire empty log projection: {error}"),
                )
            })?;
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (selected, authorize);
            return Err(tree_error(
                self.home.root(),
                "projection retirement requires unix or windows",
            ));
        }
        self.store.require_volume_binding(self.home)
    }

    pub(super) fn retire(self) -> StorageResult<()> {
        #[cfg(any(unix, windows))]
        {
            let started = std::time::Instant::now();
            self.prepared.retire(&self.volume).map_err(|error| {
                tree_error(self.home.root(), format!("retire projection: {error}"))
            })?;
            tracing::debug!(elapsed = ?started.elapsed(), "deleted and synchronized runtime projection");
        }
        // Keep the receipt if the public binding changed, including after the
        // core's final survivor and root durability checks.
        self.store.require_volume_binding(self.home)
    }
}

#[cfg(any(unix, windows))]
mod source;

#[cfg(all(test, unix))]
mod tests;

#[cfg(test)]
mod publication_tests;

#[cfg(all(test, any(unix, windows)))]
mod selection_tests;
