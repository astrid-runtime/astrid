//! Private active-projection receipt retained inside durable volume media.
//!
//! The receipt is ordinary system-owned catalog content at a `run/` name that
//! projection restore never materializes. ACTIVE proves a run owned a host
//! projection and authorizes reconciliation. RETIRING is a durable inventory
//! publication and never infers deletions from a partially retired host.

use std::collections::BTreeSet;
use std::path::Path;

use serde::{Deserialize, Deserializer, Serialize};

use crate::content::ContentName;
use crate::error::{StorageError, StorageResult};
use crate::storage_model::ObjectId;
use astrid_core::dirs::AstridHome;
use astrid_core::platform_fs::StagingScope;

use super::{RuntimePrincipalStore, StateOwner, runtime_tree::is_excluded};

pub(super) const ACTIVE_PROJECTION_NAME: &str = "run/.active-projection-v1.json";
const RECEIPT_SCHEMA_V1: u32 = 1;
const RECEIPT_SCHEMA_V2: u32 = 2;
// A projection inventory is catalog metadata, not a quota. This bounds a
// corrupted or hostile receipt before allocating its JSON payload.
const MAX_RECEIPT_BYTES: u64 = 4 * 1024 * 1024;

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
    #[serde(
        default,
        deserialize_with = "deserialize_present_staging_scope",
        skip_serializing_if = "Option::is_none"
    )]
    staging_scope: Option<StagingScope>,
}

impl ActiveProjectionReceipt {
    pub(super) const fn phase(&self) -> ReceiptPhase {
        self.phase
    }

    pub(super) fn root_matches(&self, home: &AstridHome) -> StorageResult<bool> {
        Ok(self.root == canonical_root(home)?)
    }

    pub(super) fn contains_inventory_name(&self, name: &str) -> bool {
        self.entries.iter().any(|entry| entry.name == name)
    }

    pub(super) const fn staging_scope(&self) -> Option<StagingScope> {
        self.staging_scope
    }

    pub(super) fn inventory_names(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|entry| entry.name.as_str())
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

fn deserialize_present_staging_scope<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<StagingScope>, D::Error> {
    // Missing field uses serde `default` and never reaches this function.
    // Explicit JSON null must fail closed rather than becoming no-epoch.
    match Option::<StagingScope>::deserialize(deserializer)? {
        Some(scope) => Ok(Some(scope)),
        None => Err(serde::de::Error::custom(
            "staging_scope must not be null when present",
        )),
    }
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
    validate_receipt_schema(&receipt, &host_receipt)?;
    for entry in &receipt.entries {
        validate_receipt_entry(store, entry)?;
    }
    Ok(Some(receipt))
}

pub(super) fn encode(
    home: &AstridHome,
    phase: ReceiptPhase,
    entries: &[ActiveProjectionEntry],
    staging_scope: Option<StagingScope>,
) -> StorageResult<Vec<u8>> {
    let schema = match (phase, staging_scope) {
        (ReceiptPhase::Retiring, Some(_)) => RECEIPT_SCHEMA_V2,
        (_, None) => RECEIPT_SCHEMA_V1,
        (ReceiptPhase::Active, Some(_)) => {
            return Err(tree_error(
                home.root(),
                "active projection receipt cannot carry a staging scope",
            ));
        },
    };
    let receipt = ActiveProjectionReceipt {
        schema,
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
        staging_scope,
    };
    serde_json::to_vec(&receipt)
        .map_err(|error| tree_error(home.root(), format!("encode active receipt: {error}")))
}

fn validate_receipt_schema(
    receipt: &ActiveProjectionReceipt,
    host_receipt: &Path,
) -> StorageResult<()> {
    match receipt.schema {
        RECEIPT_SCHEMA_V1 => {
            if receipt.staging_scope.is_some() {
                return Err(tree_error(
                    host_receipt,
                    "schema 1 active projection receipt cannot carry a staging scope",
                ));
            }
            Ok(())
        },
        RECEIPT_SCHEMA_V2 => {
            if receipt.phase != ReceiptPhase::Retiring {
                return Err(tree_error(
                    host_receipt,
                    "schema 2 active projection receipt must be RETIRING",
                ));
            }
            if receipt.staging_scope.is_none() {
                return Err(tree_error(
                    host_receipt,
                    "schema 2 retiring receipt requires a staging scope",
                ));
            }
            Ok(())
        },
        _ => Err(tree_error(
            host_receipt,
            "active projection receipt has an unsupported schema",
        )),
    }
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
mod tests {
    use super::*;

    fn receipt(phase: ReceiptPhase, names: &[&str]) -> ActiveProjectionReceipt {
        ActiveProjectionReceipt {
            schema: RECEIPT_SCHEMA_V1,
            phase,
            root: String::new(),
            entries: names
                .iter()
                .map(|name| ActiveReceiptEntry {
                    name: (*name).to_owned(),
                    file: String::new(),
                    logical_bytes: 0,
                })
                .collect(),
            staging_scope: None,
        }
    }

    #[test]
    fn removals_preserve_receipt_order_with_duplicate_survivors() {
        let receipt = receipt(ReceiptPhase::Active, &["removed-b", "kept", "removed-a"]);
        let surviving = ["unreceipted", "kept", "kept"].map(|name| ContentName::new(name).unwrap());
        let removed = removals(&receipt, &surviving).unwrap();
        assert_eq!(
            removed.iter().map(ContentName::as_str).collect::<Vec<_>>(),
            ["removed-b", "removed-a"]
        );
    }

    #[test]
    fn removals_reject_invalid_active_names_and_do_not_reconcile_retiring() {
        let surviving = [ContentName::new("kept").unwrap()];
        for invalid in ["", "nul\0name"] {
            let active = receipt(ReceiptPhase::Active, &["kept", invalid]);
            assert!(removals(&active, &surviving).is_err());
            let retiring = receipt(ReceiptPhase::Retiring, &["kept", invalid]);
            assert!(removals(&retiring, &surviving).unwrap().is_empty());
        }
    }

    #[test]
    fn schema_rules_accept_v1_without_scope_and_v2_retiring_with_scope() {
        let host = Path::new("run/.active-projection-v1.json");
        let scope = StagingScope::parse("0123456789abcdef0123456789abcdef").unwrap();
        let v1 = ActiveProjectionReceipt {
            schema: RECEIPT_SCHEMA_V1,
            phase: ReceiptPhase::Retiring,
            root: String::new(),
            entries: Vec::new(),
            staging_scope: None,
        };
        validate_receipt_schema(&v1, host).unwrap();

        let v2 = ActiveProjectionReceipt {
            schema: RECEIPT_SCHEMA_V2,
            phase: ReceiptPhase::Retiring,
            root: String::new(),
            entries: Vec::new(),
            staging_scope: Some(scope),
        };
        validate_receipt_schema(&v2, host).unwrap();
    }

    #[test]
    fn schema_rules_reject_malformed_and_phase_illegal_scopes() {
        let host = Path::new("run/.active-projection-v1.json");
        let scope = StagingScope::parse("0123456789abcdef0123456789abcdef").unwrap();

        let v1_with_scope = ActiveProjectionReceipt {
            schema: RECEIPT_SCHEMA_V1,
            phase: ReceiptPhase::Retiring,
            root: String::new(),
            entries: Vec::new(),
            staging_scope: Some(scope),
        };
        assert!(validate_receipt_schema(&v1_with_scope, host).is_err());

        let v2_active = ActiveProjectionReceipt {
            schema: RECEIPT_SCHEMA_V2,
            phase: ReceiptPhase::Active,
            root: String::new(),
            entries: Vec::new(),
            staging_scope: Some(scope),
        };
        assert!(validate_receipt_schema(&v2_active, host).is_err());

        let v2_without_scope = ActiveProjectionReceipt {
            schema: RECEIPT_SCHEMA_V2,
            phase: ReceiptPhase::Retiring,
            root: String::new(),
            entries: Vec::new(),
            staging_scope: None,
        };
        assert!(validate_receipt_schema(&v2_without_scope, host).is_err());

        let unsupported = ActiveProjectionReceipt {
            schema: 3,
            phase: ReceiptPhase::Retiring,
            root: String::new(),
            entries: Vec::new(),
            staging_scope: Some(scope),
        };
        assert!(validate_receipt_schema(&unsupported, host).is_err());
    }

    #[test]
    fn schema1_present_null_staging_scope_is_rejected() {
        let rejected =
            r#"{"schema":1,"phase":"retiring","root":"/tmp/x","entries":[],"staging_scope":null}"#;
        let error = serde_json::from_str::<ActiveProjectionReceipt>(rejected).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("staging_scope must not be null when present"),
            "{error}"
        );
    }
}
