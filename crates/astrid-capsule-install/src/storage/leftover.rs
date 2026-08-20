//! Retire leftover path-hashed capsule-authority receipts after native import.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use astrid_core::dirs::AstridHome;
use astrid_storage::{PrincipalDirectory, RuntimePrincipalStore, StateOwner};

use crate::authority::{
    InstalledAuthority, parse_legacy_authority_receipt, quarantine_legacy_authority_receipt,
    retire_unmatched_authority_receipt_file, unmatched_active_receipts,
};

use super::read_verified_durable_package_for_owner;

/// Ingest uniquely bindable leftover receipts into durable packages, and
/// quarantine every other leftover with its original bytes preserved.
///
/// Pending or previous transaction artifacts fail closed and are not moved.
pub fn retire_unmatched_legacy_authority_receipts(
    store: &Arc<RuntimePrincipalStore>,
    home: &AstridHome,
    directory: &PrincipalDirectory,
    workspace_targets: &[PathBuf],
) -> anyhow::Result<()> {
    let leftovers = unmatched_active_receipts(home, workspace_targets)?;
    let id_counts = leftover_id_counts(&leftovers)?;
    let durable = durable_capsule_owners(store, directory)?;
    for path in leftovers {
        retire_one_leftover(store, home, &path, &id_counts, &durable)?;
    }
    Ok(())
}

fn leftover_id_counts(paths: &[PathBuf]) -> anyhow::Result<BTreeMap<String, usize>> {
    let mut counts = BTreeMap::new();
    for path in paths {
        if let Some((receipt, _)) = parse_legacy_authority_receipt(path)? {
            let id = receipt.capsule_id;
            let next = counts
                .get(&id)
                .copied()
                .unwrap_or(0_usize)
                .saturating_add(1);
            counts.insert(id, next);
        }
    }
    Ok(counts)
}

fn durable_capsule_owners(
    store: &Arc<RuntimePrincipalStore>,
    directory: &PrincipalDirectory,
) -> anyhow::Result<BTreeMap<String, Vec<StateOwner>>> {
    let mut owners = BTreeMap::<String, Vec<StateOwner>>::new();
    for (_alias, uid) in directory.bindings() {
        let owner = StateOwner::Principal(uid);
        for summary in store.capsules().list(&owner)? {
            owners
                .entry(summary.id().to_owned())
                .or_default()
                .push(owner);
        }
    }
    Ok(owners)
}

fn retire_one_leftover(
    store: &Arc<RuntimePrincipalStore>,
    home: &AstridHome,
    path: &std::path::Path,
    id_counts: &BTreeMap<String, usize>,
    durable: &BTreeMap<String, Vec<StateOwner>>,
) -> anyhow::Result<()> {
    let parsed = parse_legacy_authority_receipt(path)?;
    if let Some((receipt, bytes)) = parsed.as_ref()
        && id_counts.get(&receipt.capsule_id).copied() == Some(1)
        && durable.get(&receipt.capsule_id).map(Vec::len) == Some(1)
        && leftover_matches_durable(store, durable, receipt)?
    {
        retire_unmatched_authority_receipt_file(path, bytes).with_context(|| {
            format!(
                "retire ingested leftover capsule authority {}",
                path.display()
            )
        })?;
        return Ok(());
    }
    quarantine_legacy_authority_receipt(home, path)?;
    Ok(())
}

fn leftover_matches_durable(
    store: &Arc<RuntimePrincipalStore>,
    durable: &BTreeMap<String, Vec<StateOwner>>,
    leftover: &InstalledAuthority,
) -> anyhow::Result<bool> {
    let Some(owners) = durable.get(&leftover.capsule_id) else {
        return Ok(false);
    };
    if owners.len() != 1 {
        return Ok(false);
    }
    let Some(package) =
        read_verified_durable_package_for_owner(store, &owners[0], &leftover.capsule_id)?
    else {
        return Ok(false);
    };
    let published = package.authority();
    if leftover.capsule_id != published.capsule_id || leftover.version != published.version {
        return Ok(false);
    }
    if leftover.manifest_digest != published.manifest_digest {
        return Ok(false);
    }
    if leftover.approved_capabilities != published.approved_capabilities {
        return Ok(false);
    }
    if leftover.source != published.source {
        return Ok(false);
    }
    let expansions = package
        .manifest()
        .capabilities
        .expansions_from(&leftover.approved_capabilities);
    if !expansions.is_empty() {
        return Ok(false);
    }
    Ok(true)
}
