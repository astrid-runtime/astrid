//! Boot-time admission of the host runtime tree into packed system content.
//!
//! Admission runs in the singleton-owned migrate-only window. The receipt is
//! host migration metadata, not runtime content, so the packed catalog remains
//! the authority once the barrier completes.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::Path;

use astrid_core::dirs::AstridHome;
use astrid_storage::{RuntimePrincipalStore, RuntimeTreeEntry, StateOwner};
use serde::{Deserialize, Serialize};

const RECEIPT_NAME: &str = "runtime-tree-v1.json";
const RECEIPT_SCHEMA: u32 = 1;
// A receipt is host migration metadata, not an operator quota. This hard
// parser guard bounds allocation for a corrupted or hostile local file.
const MAX_RECEIPT_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeTreeReceipt {
    schema: u32,
    entries: Vec<RuntimeTreeReceiptEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeTreeReceiptEntry {
    name: String,
    bytes: u64,
    modified_nanos: i128,
}

impl RuntimeTreeReceipt {
    fn from_entries(entries: &[RuntimeTreeEntry]) -> Self {
        Self {
            schema: RECEIPT_SCHEMA,
            entries: entries
                .iter()
                .map(|entry| RuntimeTreeReceiptEntry {
                    name: entry.name().as_str().to_owned(),
                    bytes: entry.logical_bytes(),
                    modified_nanos: entry.modified_nanos(),
                })
                .collect(),
        }
    }

    fn matches_entries(&self, entries: &[RuntimeTreeEntry]) -> bool {
        self.schema == RECEIPT_SCHEMA
            && self.entries.len() == entries.len()
            && self.entries.iter().zip(entries).all(|(receipt, entry)| {
                receipt.name == entry.name().as_str()
                    && receipt.bytes == entry.logical_bytes()
                    && receipt.modified_nanos == entry.modified_nanos()
            })
    }
}

/// Admit one host runtime tree, skipping a receipt-matching catalog.
///
/// The blocking walk and packed publication run off the async executor. A
/// receipt is written only after a second metadata scan agrees with the first,
/// so a source mutation during ingest cannot be mistaken for a completed
/// admission.
pub(crate) async fn admit(home: &AstridHome, store: &RuntimePrincipalStore) -> io::Result<()> {
    let home = home.clone();
    let store = store.clone();
    tokio::task::spawn_blocking(move || admit_blocking(&home, &store))
        .await
        .map_err(|error| {
            io::Error::other(format!("runtime tree admission worker failed: {error}"))
        })?
}

fn admit_blocking(home: &AstridHome, store: &RuntimePrincipalStore) -> io::Result<()> {
    let entries = scan(store, home.root())?;
    let receipt_path = home.migrations_dir().join(RECEIPT_NAME);
    if let Some(receipt) = read_receipt(&receipt_path)?
        && receipt.matches_entries(&entries)
        && catalog_contains_entries(store, &entries)?
    {
        return Ok(());
    }

    store
        .admit_runtime_tree(home.root())
        .map_err(storage_error)?;
    let after = scan(store, home.root())?;
    if !RuntimeTreeReceipt::from_entries(&entries).matches_entries(&after) {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "runtime tree changed while packed admission was in progress",
        ));
    }
    let receipt = RuntimeTreeReceipt::from_entries(&after);
    let bytes = serde_json::to_vec(&receipt).map_err(io::Error::other)?;
    astrid_core::platform_fs::ensure_private_directory(&home.migrations_dir())?;
    astrid_core::platform_fs::atomic_write_private_file(&receipt_path, &bytes)
}

fn scan(store: &RuntimePrincipalStore, root: &Path) -> io::Result<Vec<RuntimeTreeEntry>> {
    store.scan_runtime_tree(root).map_err(storage_error)
}

fn catalog_contains_entries(
    store: &RuntimePrincipalStore,
    entries: &[RuntimeTreeEntry],
) -> io::Result<bool> {
    let catalog = store
        .content()
        .list(&StateOwner::System)
        .map_err(|error| io::Error::other(format!("list packed runtime catalog: {error}")))?;
    let catalog_sizes = catalog
        .into_iter()
        .map(|entry| (entry.name().as_str().to_owned(), entry.logical_bytes()))
        .collect::<BTreeMap<_, _>>();
    Ok(entries
        .iter()
        .all(|entry| catalog_sizes.get(entry.name().as_str()) == Some(&entry.logical_bytes())))
}

fn read_receipt(path: &Path) -> io::Result<Option<RuntimeTreeReceipt>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "runtime tree receipt is not a regular file: {}",
                path.display()
            ),
        ));
    }
    if metadata.len() > MAX_RECEIPT_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("runtime tree receipt exceeds {MAX_RECEIPT_BYTES} bytes"),
        ));
    }
    astrid_core::platform_fs::validate_private_file(path)?;
    let bytes = fs::read(path)?;
    serde_json::from_slice(&bytes).map(Some).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("parse runtime tree receipt: {error}"),
        )
    })
}

fn storage_error(error: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::other(error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use astrid_storage::{AstridFilesystem, FilesystemPath, KvQuotaResolver};
    use sha2::{Digest as _, Sha256};
    use std::sync::Arc;

    fn unlimited_quota() -> Arc<dyn KvQuotaResolver<StateOwner>> {
        Arc::new(|owner: &StateOwner| {
            Ok(match owner {
                StateOwner::System => None,
                StateOwner::Principal(_) | StateOwner::Fleet(_) => Some(u64::MAX),
            })
        })
    }

    #[tokio::test]
    async fn admits_runtime_tree_once_and_reopens_from_preclose_copy() {
        let home_dir = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(home_dir.path());
        home.ensure().unwrap();
        let wasm = b"\0asm\x01\0\0\0kernel-admit".to_vec();
        let hash = blake3::hash(&wasm).to_hex().to_string();
        let wasm_path = home.bin_dir().join(format!("{hash}.wasm"));
        fs::write(&wasm_path, &wasm).unwrap();
        let metadata_path = home.root().join("run/capsules/example/meta.json");
        fs::create_dir_all(metadata_path.parent().unwrap()).unwrap();
        fs::write(&metadata_path, format!("{{\"wasm_hash\":\"{hash}\"}}")).unwrap();

        let store = astrid_storage::open_runtime_principal_store(&home, unlimited_quota())
            .await
            .unwrap();
        admit(&home, &store).await.unwrap();
        let first_volume_size = fs::metadata(home.storage_volume_path()).unwrap().len();
        admit(&home, &store).await.unwrap();
        assert_eq!(
            fs::metadata(home.storage_volume_path()).unwrap().len(),
            first_volume_size,
            "receipt-matching admission republished content"
        );

        let copied_dir = tempfile::tempdir().unwrap();
        let copied_home = AstridHome::from_path(copied_dir.path());
        copied_home.ensure().unwrap();
        fs::copy(
            home.storage_volume_path(),
            copied_home.storage_volume_path(),
        )
        .unwrap();
        let reopened =
            astrid_storage::open_runtime_principal_store(&copied_home, unlimited_quota())
                .await
                .unwrap();
        let filesystem = AstridFilesystem::new(reopened.content(), StateOwner::System);
        let path = FilesystemPath::new(format!("bin/{hash}.wasm")).unwrap();
        let entry = filesystem.stat(&path).unwrap();
        let actual = filesystem.read(&path, 0, entry.logical_bytes()).unwrap();
        assert_eq!(Sha256::digest(&actual), Sha256::digest(&wasm));
        assert!(
            filesystem
                .stat(&FilesystemPath::new("var/astrid.volume").unwrap())
                .is_err()
        );
        assert!(fs::read_to_string(home.migrations_dir().join(RECEIPT_NAME)).is_ok());
    }

    #[tokio::test]
    async fn fresh_home_admits_no_generated_control_files() {
        let directory = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(directory.path());
        home.ensure().unwrap();
        let store = astrid_storage::open_runtime_principal_store(&home, unlimited_quota())
            .await
            .unwrap();
        admit(&home, &store).await.unwrap();
        let names = store
            .content()
            .list(&StateOwner::System)
            .unwrap()
            .into_iter()
            .map(|entry| entry.name().as_str().to_owned())
            .collect::<Vec<_>>();
        assert!(
            names.is_empty(),
            "fresh home admitted generated files: {names:?}"
        );
        assert!(fs::read_to_string(home.migrations_dir().join(RECEIPT_NAME)).is_ok());
    }
}
