//! Private active-projection receipt retained inside durable volume media.
//!
//! The receipt is ordinary system-owned catalog content at a `run/` name that
//! projection restore never materializes. ACTIVE proves a run owned a host
//! projection and authorizes reconciliation. RETIRING is a durable inventory
//! publication and never infers deletions from a partially retired host.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::content::{ContentEntry, ContentName};
use crate::error::{StorageError, StorageResult};
use crate::storage_model::ObjectId;
use astrid_core::dirs::AstridHome;

use super::{RuntimePrincipalStore, StateOwner, runtime_tree::is_excluded};

pub(super) const ACTIVE_PROJECTION_NAME: &str = "run/.active-projection-v1.json";
const RECEIPT_SCHEMA: u32 = 1;
// Preserve the historical allowance for receipt framing and root spelling.
// Inventory allowance is derived separately from authenticated live catalog
// names, so a large fleet does not outgrow a fixed 4 MiB inventory ceiling.
const RECEIPT_FRAMING_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ActiveProjectionEntry {
    pub(super) name: ContentName,
    pub(super) file: ObjectId,
    pub(super) logical_bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum ReceiptPhase {
    Active,
    Retiring,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ActiveProjectionReceipt {
    schema: u32,
    phase: ReceiptPhase,
    root: String,
    entries: Vec<ActiveReceiptEntry>,
}

impl ActiveProjectionReceipt {
    pub(super) const fn phase(&self) -> ReceiptPhase {
        self.phase
    }

    pub(super) fn root_matches(&self, home: &AstridHome) -> StorageResult<bool> {
        Ok(self.root == canonical_root(home)?)
    }

    pub(super) fn contains_inventory_name(&self, name: &str) -> bool {
        self.entries
            .binary_search_by(|entry| entry.name.as_str().cmp(name))
            .is_ok()
    }

    #[cfg(test)]
    pub(super) fn inventory_identity(&self, name: &str) -> StorageResult<Option<ObjectId>> {
        let Some(entry) = self.entries.iter().find(|entry| entry.name == name) else {
            return Ok(None);
        };
        let bytes = hex::decode(&entry.file).map_err(|error| {
            tree_error(
                Path::new(&entry.name),
                format!("decode receipt object identity: {error}"),
            )
        })?;
        let expected: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            tree_error(
                Path::new(&entry.name),
                "receipt object identity is not 32 bytes",
            )
        })?;
        Ok(Some(ObjectId::new(expected)))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActiveReceiptEntry {
    name: String,
    file: String,
    logical_bytes: u64,
}

pub(super) fn active_projection_name() -> StorageResult<ContentName> {
    ContentName::new(ACTIVE_PROJECTION_NAME)
        .map_err(|error| StorageError::Internal(format!("validate active receipt: {error}")))
}

/// Verify that finalization is bound to this admitted runtime home.
pub(super) fn validate_retirement_home(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
) -> StorageResult<()> {
    if read(home, store)?.is_none() {
        return Err(tree_error(
            home.root(),
            "runtime retirement requires an admitted projection receipt",
        ));
    }
    Ok(())
}

pub(super) fn read(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
) -> StorageResult<Option<ActiveProjectionReceipt>> {
    let receipt = read_relocatable(home, store)?;
    if let Some(receipt) = &receipt
        && receipt.root != canonical_root(home)?
    {
        return Err(tree_error(
            &home.root().join(ACTIVE_PROJECTION_NAME),
            "active projection receipt is stale or redirected",
        ));
    }
    Ok(receipt)
}

/// Parse and validate inventory without rejecting a root mismatch.
///
/// Only the caller's bootstrap-only volume-copy recovery may accept a root
/// mismatch; all other relocation is rejected by the caller.
pub(super) fn read_relocatable(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
) -> StorageResult<Option<ActiveProjectionReceipt>> {
    let host_receipt = home.root().join(ACTIVE_PROJECTION_NAME);
    if std::fs::symlink_metadata(&host_receipt).is_ok() {
        return Err(tree_error(
            &host_receipt,
            "active projection receipt must never be materialized on the host",
        ));
    }

    let name = active_projection_name()?;
    let metadata = store
        .content()
        .describe(&StateOwner::System, &name)
        .map_err(receipt_error("inspect active projection receipt"))?;
    let Some(metadata) = metadata else {
        return Ok(None);
    };
    let catalog = store
        .content()
        .list(&StateOwner::System)
        .map_err(receipt_error("authenticate receipt inventory allowance"))?;
    let maximum_bytes = receipt_size_bound(catalog.iter().map(ContentEntry::name))?;
    enforce_receipt_bound(&host_receipt, metadata.logical_bytes(), maximum_bytes)?;
    let bytes = store
        .content()
        .read(&StateOwner::System, &name)
        .map_err(receipt_error("read active projection receipt"))?
        .ok_or_else(|| {
            tree_error(
                &host_receipt,
                "active projection receipt disappeared while being read",
            )
        })?;
    decode_receipt(&host_receipt, &bytes, catalog)
}

fn decode_receipt(
    host_receipt: &Path,
    bytes: &[u8],
    catalog: Vec<ContentEntry>,
) -> StorageResult<Option<ActiveProjectionReceipt>> {
    enforce_receipt_bound(
        host_receipt,
        u64::try_from(bytes.len())
            .map_err(|_| StorageError::Internal("receipt length overflow".to_owned()))?,
        receipt_size_bound(catalog.iter().map(ContentEntry::name))?,
    )?;
    let mut receipt =
        serde_json::from_slice::<ActiveProjectionReceipt>(bytes).map_err(|error| {
            tree_error(
                host_receipt,
                format!("parse active projection receipt: {error}"),
            )
        })?;
    if receipt.schema != RECEIPT_SCHEMA {
        return Err(tree_error(
            host_receipt,
            "active projection receipt has an unsupported schema",
        ));
    }
    let catalog = catalog
        .into_iter()
        .map(|entry| (entry.name().clone(), entry))
        .collect::<BTreeMap<_, _>>();
    if receipt.entries.len() > catalog.len() {
        return Err(tree_error(
            host_receipt,
            "active receipt has more entries than the durable catalog",
        ));
    }
    // Historical receipts need not be ordered. Normalize only this temporary
    // decoded inventory, so repeated membership checks remain logarithmic.
    receipt.entries.sort_by(|a, b| a.name.cmp(&b.name));
    if receipt
        .entries
        .windows(2)
        .any(|entries| entries[0].name == entries[1].name)
    {
        return Err(tree_error(
            host_receipt,
            "active receipt repeats a durable catalog name",
        ));
    }
    for entry in &receipt.entries {
        validate_receipt_entry(&catalog, entry)?;
    }
    Ok(Some(receipt))
}

pub(super) fn encode(
    home: &AstridHome,
    phase: ReceiptPhase,
    entries: &[ActiveProjectionEntry],
) -> StorageResult<Vec<u8>> {
    let receipt = ActiveProjectionReceipt {
        schema: RECEIPT_SCHEMA,
        phase,
        root: canonical_root(home)?,
        entries: entries
            .iter()
            .map(|entry| ActiveReceiptEntry {
                name: entry.name.as_str().to_owned(),
                file: hex::encode(entry.file.as_bytes()),
                logical_bytes: entry.logical_bytes,
            })
            .collect(),
    };
    let bytes = serde_json::to_vec(&receipt)
        .map_err(|error| tree_error(home.root(), format!("encode active receipt: {error}")))?;
    let length = u64::try_from(bytes.len())
        .map_err(|_| StorageError::Internal("receipt length overflow".to_owned()))?;
    enforce_receipt_bound(
        home.root(),
        length,
        receipt_size_bound(entries.iter().map(|entry| &entry.name))?,
    )?;
    Ok(bytes)
}

pub(super) fn clear(store: &RuntimePrincipalStore, home: &AstridHome) -> StorageResult<bool> {
    let name = active_projection_name()?;
    let removed = store
        .content()
        .delete(&StateOwner::System, &name)
        .map_err(|error| tree_error(home.root(), format!("remove active receipt: {error}")))?;
    if removed {
        store.content().flush().map_err(|error| {
            tree_error(
                home.root(),
                format!("flush active receipt removal: {error}"),
            )
        })?;
    }
    Ok(removed)
}

pub(super) fn removals(
    receipt: &ActiveProjectionReceipt,
    surviving: &[ContentName],
) -> StorageResult<Vec<ContentName>> {
    if receipt.phase != ReceiptPhase::Active {
        return Ok(Vec::new());
    }
    let surviving = surviving.iter().collect::<BTreeSet<_>>();
    receipt
        .entries
        .iter()
        .map(|entry| {
            let name = ContentName::new(&entry.name).map_err(|error| {
                tree_error(Path::new(&entry.name), format!("receipt name: {error}"))
            })?;
            if surviving.contains(&name) {
                Ok(None)
            } else {
                Ok(Some(name))
            }
        })
        .collect::<StorageResult<Vec<Option<ContentName>>>>()
        .map(|names| names.into_iter().flatten().collect())
}

// Each canonical JSON inventory entry contains its escaped catalog name,
// a 64-character object identity, a u64 length and less than 128 fixed bytes.
// JSON escapes occupy at most six bytes per source UTF-8 byte. The allowance
// is proportional to authenticated catalog metadata, never receipt claims.
fn receipt_size_bound<'a>(names: impl IntoIterator<Item = &'a ContentName>) -> StorageResult<u64> {
    names
        .into_iter()
        .try_fold(RECEIPT_FRAMING_BYTES, |total, name| {
            u64::try_from(name.as_str().len())
                .ok()
                .and_then(|bytes| bytes.checked_mul(6))
                .and_then(|bytes| bytes.checked_add(128))
                .and_then(|bytes| total.checked_add(bytes))
                .ok_or_else(|| {
                    StorageError::Internal("receipt inventory allowance overflow".to_owned())
                })
        })
}

fn enforce_receipt_bound(path: &Path, bytes: u64, maximum: u64) -> StorageResult<()> {
    if bytes > maximum {
        return Err(tree_error(
            path,
            format!("active projection receipt exceeds catalog-derived {maximum} bytes"),
        ));
    }
    Ok(())
}

fn validate_receipt_entry(
    catalog: &BTreeMap<ContentName, ContentEntry>,
    entry: &ActiveReceiptEntry,
) -> StorageResult<()> {
    let name = ContentName::new(&entry.name).map_err(|error| {
        tree_error(
            Path::new(&entry.name),
            format!("validate receipt catalog name: {error}"),
        )
    })?;
    let actual = catalog.get(&name).ok_or_else(|| {
        tree_error(
            Path::new(&entry.name),
            "active receipt names absent durable projection",
        )
    })?;

    let bytes = hex::decode(&entry.file).map_err(|error| {
        tree_error(
            Path::new(&entry.name),
            format!("decode receipt object identity: {error}"),
        )
    })?;
    let expected: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
        tree_error(
            Path::new(&entry.name),
            "receipt object identity is not 32 bytes",
        )
    })?;
    let identity_matches = actual.file().as_bytes() == &expected;
    if !identity_matches
        || actual.logical_bytes() != entry.logical_bytes
        || is_excluded(&entry.name)
    {
        return Err(tree_error(
            Path::new(&entry.name),
            "active receipt does not match durable projection",
        ));
    }
    Ok(())
}

fn canonical_root(home: &AstridHome) -> StorageResult<String> {
    home.root()
        .canonicalize()
        .map_err(|error| tree_error(home.root(), format!("resolve projection root: {error}")))?
        .into_os_string()
        .into_string()
        .map_err(|_| tree_error(home.root(), "projection root is not valid UTF-8"))
}

fn receipt_error(
    detail: &'static str,
) -> impl Fn(crate::content::PrincipalContentError) -> StorageError {
    move |error| StorageError::Internal(format!("{detail}: {error}"))
}

fn tree_error(path: &Path, detail: impl std::fmt::Display) -> StorageError {
    StorageError::Connection(format!("runtime tree {}: {detail}", path.display()))
}

#[cfg(test)]
mod tests;
