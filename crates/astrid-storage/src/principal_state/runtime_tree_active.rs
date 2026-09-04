//! Private active-projection receipt retained inside durable volume media.
//!
//! The receipt is ordinary system-owned catalog content at a `run/` name that
//! projection restore never materializes. It proves that a prior process owned
//! a running projection; arbitrary host files without it are not authority.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::content::ContentName;
use crate::error::{StorageError, StorageResult};
use crate::storage_model::ObjectId;
use astrid_core::dirs::AstridHome;

use super::{RuntimePrincipalStore, StateOwner, runtime_tree::is_excluded};

pub(super) const ACTIVE_PROJECTION_NAME: &str = "run/.active-projection-v1.json";
const RECEIPT_SCHEMA: u32 = 1;
// A projection inventory is catalog metadata, not a quota. This bounds a
// corrupted or hostile receipt before allocating its JSON payload.
const MAX_RECEIPT_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ActiveProjectionEntry {
    pub(super) name: ContentName,
    pub(super) file: ObjectId,
    pub(super) logical_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ActiveProjectionReceipt {
    schema: u32,
    root: String,
    entries: Vec<ActiveReceiptEntry>,
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

pub(super) fn read(
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
    if metadata.logical_bytes() > MAX_RECEIPT_BYTES {
        return Err(tree_error(
            &host_receipt,
            format!("active projection receipt exceeds {MAX_RECEIPT_BYTES} bytes"),
        ));
    }
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
    let receipt = serde_json::from_slice::<ActiveProjectionReceipt>(&bytes).map_err(|error| {
        tree_error(
            &host_receipt,
            format!("parse active projection receipt: {error}"),
        )
    })?;
    if receipt.schema != RECEIPT_SCHEMA || receipt.root != canonical_root(home)? {
        return Err(tree_error(
            &host_receipt,
            "active projection receipt is stale or redirected",
        ));
    }
    for entry in &receipt.entries {
        validate_receipt_entry(store, entry)?;
    }
    Ok(Some(receipt))
}

pub(super) fn write(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
    entries: &[ActiveProjectionEntry],
) -> StorageResult<()> {
    let receipt = ActiveProjectionReceipt {
        schema: RECEIPT_SCHEMA,
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
    let name = active_projection_name()?;
    store
        .content()
        .put(&StateOwner::System, &name, &bytes)
        .map_err(|error| {
            tree_error(
                home.root(),
                format!("publish active projection receipt: {error}"),
            )
        })?;
    store
        .content()
        .flush()
        .map_err(|error| tree_error(home.root(), format!("flush active receipt: {error}")))
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

fn validate_receipt_entry(
    store: &RuntimePrincipalStore,
    entry: &ActiveReceiptEntry,
) -> StorageResult<()> {
    let name = ContentName::new(&entry.name).map_err(|error| {
        tree_error(
            Path::new(&entry.name),
            format!("validate receipt catalog name: {error}"),
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
    let actual = store
        .content()
        .describe(&StateOwner::System, &name)
        .map_err(receipt_error("validate active receipt entry"))?
        .ok_or_else(|| {
            tree_error(
                Path::new(&entry.name),
                "active receipt names absent durable projection",
            )
        })?;
    if actual.file().as_bytes() != &expected
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
