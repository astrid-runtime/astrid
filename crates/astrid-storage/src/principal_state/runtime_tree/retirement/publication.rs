//! Publish final payloads and complete deletion authority in one owner-root CAS.

use std::collections::BTreeSet;

use super::super::{
    ActiveProjectionEntry, AstridHome, ContiguousFileIngest, PackedProjectionIngest, ReceiptPhase,
    RuntimePrincipalStore, RuntimeTreeEntry, StateOwner, active, active_projection_entries,
    active_receipt::prepared_entries, is_exactly_pack_open_staging_journal, projection, tree_error,
    validate_retiring_host_subset,
};
use crate::StorageResult;
use crate::content::{ContentBatchPreconditions, ContentName, PrepareDerivedBatchContent};
use crate::engine::{PrincipalProjectionEngine, PrincipalProjectionError};

pub(in crate::principal_state::runtime_tree) fn publish_retiring_projection(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
    scanned: Vec<RuntimeTreeEntry>,
) -> StorageResult<()> {
    publish_with_hook(home, store, scanned, || Ok(()))
}

pub(super) fn publish_with_hook(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
    scanned: Vec<RuntimeTreeEntry>,
    before_publish: impl FnOnce() -> StorageResult<()>,
) -> StorageResult<()> {
    let started = std::time::Instant::now();
    // Capture the whole System generation before parsing the receipt or listing
    // retained names. A fresh-name addition must fail just like replacement;
    // per-name expectations cannot prove that the inventory is complete.
    let root = store
        .engine
        .current_root(&StateOwner::System)
        .map_err(|error| tree_error(home.root(), format!("capture retiring root: {error}")))?;
    let Some(receipt) = active::read(home, store)? else {
        return if scanned.is_empty() || is_exactly_pack_open_staging_journal(&scanned) {
            Ok(())
        } else {
            Err(tree_error(
                home.root(),
                "active projection receipt is missing for surviving host projection",
            ))
        };
    };
    if receipt.phase() == ReceiptPhase::Retiring {
        return validate_retiring_host_subset(home, &receipt, &scanned);
    }
    let surviving = scanned
        .iter()
        .map(|entry| entry.name.clone())
        .collect::<Vec<_>>();
    // An entirely absent projection can follow an interrupted cleanup. Preserve
    // the existing empty-host contract instead of inferring mass deletion.
    let mut removals = if scanned.is_empty() {
        Vec::new()
    } else {
        active::removals(&receipt, &surviving)?
    };
    removals.retain(|name| !projection::surviving_directory(home.root(), name.as_str()));
    let rewritten = surviving.iter().collect::<BTreeSet<_>>();
    let removed = removals.iter().collect::<BTreeSet<_>>();
    let complete = active_projection_entries(home, store)?;
    let root =
        root.ok_or_else(|| tree_error(home.root(), "active receipt has no principal root"))?;
    let retained = complete
        .iter()
        .filter(|entry| !rewritten.contains(&entry.name) && !removed.contains(&entry.name))
        .cloned()
        .collect::<Vec<_>>();
    let mut derived = RetiringReceiptDeriver {
        home,
        entries: scanned
            .iter()
            .map(|entry| (entry.name.clone(), entry.logical_bytes))
            .collect(),
        retained: &retained,
    };
    let ingests = scanned.into_iter().map(|entry| {
        PackedProjectionIngest::File(ContiguousFileIngest::new(
            entry.name,
            entry.source_path,
            entry.logical_bytes,
        ))
    });
    before_publish()?;
    store.replace_contiguous_files_with_expectation(
        StateOwner::System,
        ingests,
        &removals,
        Some(&mut derived),
        ContentBatchPreconditions {
            names: None,
            root: Some(root),
        },
    )?;
    #[cfg(test)]
    tests::before_flush(home)?;
    store
        .content()
        .flush()
        .map_err(|error| tree_error(home.root(), format!("flush retiring projection: {error}")))?;
    #[cfg(any(test, feature = "test-support"))]
    super::super::operation_counts::record_completed_publication();
    tracing::debug!(target: "astrid_storage::runtime_tree_publication", elapsed = ?started.elapsed(), phase = "retiring", "published and flushed runtime projection");
    Ok(())
}

struct RetiringReceiptDeriver<'a> {
    home: &'a AstridHome,
    entries: Vec<(ContentName, u64)>,
    retained: &'a [ActiveProjectionEntry],
}

impl PrepareDerivedBatchContent for RetiringReceiptDeriver<'_> {
    fn prepare(
        &mut self,
        prepared: &std::collections::BTreeMap<ContentName, crate::content::ContentDescriptor>,
    ) -> Result<(ContentName, Vec<u8>), crate::content::PrincipalContentError> {
        let mut entries = prepared_entries(&self.entries, prepared)?;
        // Unlike ACTIVE, RETIRING retains volume-only directories and files:
        // it describes complete durable authority, not host materialization.
        entries.extend(self.retained.iter().cloned());
        entries.sort_by(|left, right| left.name.cmp(&right.name));
        let bytes = active::encode(self.home, ReceiptPhase::Retiring, &entries, None)
            .map_err(|error| PrincipalProjectionError::Engine(error.to_string()))?;
        let name = active::active_projection_name()
            .map_err(|error| PrincipalProjectionError::Engine(error.to_string()))?;
        Ok((name, bytes))
    }
}

#[cfg(test)]
pub(super) mod tests;
