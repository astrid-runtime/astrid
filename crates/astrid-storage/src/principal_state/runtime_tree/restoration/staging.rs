//! Intent-scoped restoration temporary classification and restart discharge.

use std::collections::BTreeSet;
use std::path::Path;

use super::super::active::ActiveProjectionReceipt;
use super::super::{
    AstridHome, RuntimePrincipalStore, RuntimeTreeEntry, StateOwner, StorageResult, active,
    tree_error,
};
use super::PreparedRestoration;
use super::record_intent;

/// Classify exact-epoch temporary residue under an old RETIRING receipt and
/// discharge it through a fresh durable intent + rooted writer.
///
/// Ambient `scanned` names are untrusted relative input only. Eligible parents
/// come from the old receipt's file-entry parents and must not widen after
/// intent refresh. Returns `None` when the receipt has no staging scope or no
/// exact-epoch residue remains.
pub(in super::super) fn discharge_scoped_staging<'a>(
    home: &'a AstridHome,
    store: &'a RuntimePrincipalStore,
    receipt: &ActiveProjectionReceipt,
    scanned: &[RuntimeTreeEntry],
) -> StorageResult<Option<PreparedRestoration<'a>>> {
    let Some(scope) = receipt.staging_scope() else {
        return Ok(None);
    };
    let eligible_parents = eligible_file_parents(receipt);

    let mut staging = Vec::new();
    for entry in scanned {
        let name = entry.name().as_str();
        if receipt.contains_inventory_name(name) {
            continue;
        }
        if name.ends_with('/') {
            return Err(tree_error(
                home.root(),
                format!("retiring projection contains unreceipted host file {name}"),
            ));
        }
        let relative = Path::new(name);
        let Some(file_name) = relative.file_name() else {
            return Err(tree_error(
                home.root(),
                format!("retiring projection contains unreceipted host file {name}"),
            ));
        };
        if !scope.matches_temporary_basename(file_name)
            || !parent_is_eligible(&eligible_parents, relative)
            || store
                .content()
                .describe(&StateOwner::System, entry.name())
                .map_err(|error| tree_error(home.root(), error))?
                .is_some()
        {
            return Err(tree_error(
                home.root(),
                format!("retiring projection contains unreceipted host file {name}"),
            ));
        }
        staging.push(entry.name().clone());
    }
    if staging.is_empty() {
        return Ok(None);
    }

    let mut prepared = record_intent(home, store)?;
    if prepared.staging_scope() != scope {
        return Err(tree_error(
            home.root(),
            "restoration staging scope changed while discharging temporary residue",
        ));
    }
    let refreshed = active::read(home, store)?.ok_or_else(|| {
        tree_error(
            home.root(),
            "restoration staging intent disappeared while discharging temporary residue",
        )
    })?;
    // Singleton volume open owns this store/writer. Concurrent catalogue
    // mutation is outside that contract; revalidation still fail-closes if the
    // refreshed inventory/catalog changed under the same process.
    let writer = prepared.writer()?;
    let cleanup = (|| {
        for name in &staging {
            let relative = Path::new(name.as_str());
            let file_name = relative.file_name().ok_or_else(|| {
                tree_error(
                    home.root(),
                    format!(
                        "retiring projection contains unreceipted host file {}",
                        name.as_str()
                    ),
                )
            })?;
            if !scope.matches_temporary_basename(file_name)
                || !parent_is_eligible(&eligible_parents, relative)
                || refreshed.contains_inventory_name(name.as_str())
                || store
                    .content()
                    .describe(&StateOwner::System, name)
                    .map_err(|error| tree_error(home.root(), error))?
                    .is_some()
            {
                return Err(tree_error(
                    home.root(),
                    format!(
                        "retiring projection contains unreceipted host file {}",
                        name.as_str()
                    ),
                ));
            }
            writer
                .remove_staging(relative, scope)
                .map_err(|error| tree_error(home.root(), error))?;
        }
        Ok(())
    })();
    super::finish_cleanup(home, writer, cleanup)?;

    Ok(Some(prepared))
}

pub(in super::super) fn eligible_file_parents(
    receipt: &ActiveProjectionReceipt,
) -> BTreeSet<String> {
    // Directory markers (trailing '/') are not temporary parents. Only actual
    // file-entry parents from the old receipt may authorize discharge.
    receipt
        .inventory_names()
        .filter(|name| !name.ends_with('/'))
        .map(|name| {
            Path::new(name)
                .parent()
                .map(|parent| parent.to_string_lossy().into_owned())
                .unwrap_or_default()
        })
        .collect()
}

pub(in super::super) fn parent_is_eligible(
    eligible_parents: &BTreeSet<String>,
    relative: &Path,
) -> bool {
    let parent = relative
        .parent()
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_default();
    eligible_parents.contains(&parent)
}
