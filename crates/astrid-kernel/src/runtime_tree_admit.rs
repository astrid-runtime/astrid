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
use astrid_storage::{
    ContentName, ContiguousFileIngest, RuntimePrincipalStore, RuntimeTreeEntry, StateOwner,
};
use serde::{Deserialize, Serialize};

const RECEIPT_NAME: &str = "runtime-tree-v1.json";
const RECEIPT_RELATIVE_PATH: &str = "var/migrations/runtime-tree-v1.json";
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
/// admission. The receipt itself is runtime content, so it is published in a
/// second batch after the receipt is written.
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
        && catalog_contains_receipt(store, &receipt_path)?
    {
        return Ok(());
    }

    store
        .admit_runtime_tree(home.root())
        .map_err(storage_error)?;
    #[cfg(test)]
    run_source_mutation_hook(home)?;
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
    astrid_core::platform_fs::atomic_write_private_file(&receipt_path, &bytes)?;
    admit_receipt(store, &receipt_path)?;
    store
        .establish_runtime_projection_receipt(home)
        .map_err(storage_error)
}

fn admit_receipt(store: &RuntimePrincipalStore, receipt_path: &Path) -> io::Result<()> {
    let name = ContentName::new(RECEIPT_RELATIVE_PATH.to_owned()).map_err(io::Error::other)?;
    let bytes = fs::metadata(receipt_path)?.len();
    store
        .put_contiguous_files(
            StateOwner::System,
            [ContiguousFileIngest::new(
                name,
                receipt_path.to_owned(),
                bytes,
            )],
        )
        .map_err(storage_error)
}

fn scan(store: &RuntimePrincipalStore, root: &Path) -> io::Result<Vec<RuntimeTreeEntry>> {
    store
        .scan_runtime_tree(root)
        .map(|entries| {
            entries
                .into_iter()
                .filter(|entry| entry.name().as_str() != RECEIPT_RELATIVE_PATH)
                .collect()
        })
        .map_err(storage_error)
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

fn catalog_contains_receipt(
    store: &RuntimePrincipalStore,
    receipt_path: &Path,
) -> io::Result<bool> {
    let receipt_bytes = fs::metadata(receipt_path)?.len();
    let catalog = store
        .content()
        .list(&StateOwner::System)
        .map_err(|error| io::Error::other(format!("list packed runtime catalog: {error}")))?;
    Ok(catalog.iter().any(|entry| {
        entry.name().as_str() == RECEIPT_RELATIVE_PATH && entry.logical_bytes() == receipt_bytes
    }))
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
type SourceMutationHook = Box<dyn FnOnce(&Path) -> io::Result<()> + Send + 'static>;

#[cfg(test)]
static SOURCE_MUTATION_HOOK: std::sync::OnceLock<
    std::sync::Mutex<Option<(std::path::PathBuf, SourceMutationHook)>>,
> = std::sync::OnceLock::new();

#[cfg(test)]
fn inject_source_mutation_once(home: &AstridHome, hook: SourceMutationHook) {
    *SOURCE_MUTATION_HOOK
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .expect("runtime-tree test hook lock") = Some((home.root().to_path_buf(), hook));
}

#[cfg(test)]
fn run_source_mutation_hook(home: &AstridHome) -> io::Result<()> {
    let mut requested = SOURCE_MUTATION_HOOK
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .expect("runtime-tree test hook lock");
    if requested
        .as_ref()
        .is_some_and(|(target, _)| target == home.root())
    {
        let (_, hook) = requested.take().expect("runtime-tree test hook present");
        return hook(home.root());
    }
    Ok(())
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
        let store = astrid_storage::open_runtime_principal_store(&home, unlimited_quota())
            .await
            .unwrap();
        let wasm = b"\0asm\x01\0\0\0kernel-admit".to_vec();
        let hash = blake3::hash(&wasm).to_hex().to_string();
        fs::create_dir_all(home.bin_dir()).unwrap();
        let wasm_path = home.bin_dir().join(format!("{hash}.wasm"));
        fs::write(&wasm_path, &wasm).unwrap();
        let metadata_path = home.root().join("run/capsules/example/meta.json");
        fs::create_dir_all(metadata_path.parent().unwrap()).unwrap();
        fs::write(&metadata_path, format!("{{\"wasm_hash\":\"{hash}\"}}")).unwrap();
        store
            .publish_runtime_projection(&home)
            .expect("admit restart fixture");
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
                .stat(&FilesystemPath::new("volume").unwrap())
                .is_err()
        );
        assert!(fs::read_to_string(home.migrations_dir().join(RECEIPT_NAME)).is_ok());
    }

    #[tokio::test]
    async fn fresh_home_admits_generated_control_files() {
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
        for expected in [
            "etc/layout-version",
            "var/content-staging/intents.v1.log",
            RECEIPT_RELATIVE_PATH,
        ] {
            assert!(
                names.iter().any(|name| name == expected),
                "fresh home omitted generated runtime file {expected}: {names:?}"
            );
        }
        assert!(!names.iter().any(|name| name == "volume"));
        assert!(fs::read_to_string(home.migrations_dir().join(RECEIPT_NAME)).is_ok());
    }

    #[tokio::test]
    async fn source_mutation_during_admission_fails_closed_without_receipt() {
        let directory = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(directory.path());
        home.ensure().unwrap();
        let store = astrid_storage::open_runtime_principal_store(&home, unlimited_quota())
            .await
            .unwrap();
        let wasm = b"\0asm\x01\0\0\0mutation-check".to_vec();
        let hash = blake3::hash(&wasm).to_hex().to_string();
        fs::create_dir_all(home.bin_dir()).unwrap();
        let wasm_path = home.bin_dir().join(format!("{hash}.wasm"));
        fs::write(&wasm_path, &wasm).unwrap();
        store
            .publish_runtime_projection(&home)
            .expect("admit mutation fixture");
        let receipt_path = home.migrations_dir().join(RECEIPT_NAME);

        let mutation_path = wasm_path.clone();
        inject_source_mutation_once(
            &home,
            Box::new(move |_| {
                let mut bytes = fs::read(&mutation_path)?;
                let last = bytes.last_mut().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "test wasm is empty")
                })?;
                *last ^= 0xff;
                fs::write(mutation_path, bytes)
            }),
        );

        let error = admit(&home, &store)
            .await
            .expect_err("admission must fail closed");
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert!(
            !receipt_path.exists(),
            "changed source must not mint a receipt"
        );
    }
}
