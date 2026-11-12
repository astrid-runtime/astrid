//! Boot-time admission of the host runtime tree into packed system content.
//!
//! Admission runs in the singleton-owned migrate-only window. Its migration
//! receipt is published as system content with the ACTIVE inventory; the packed
//! catalog remains the authority once the barrier completes.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::Path;

use astrid_core::dirs::AstridHome;
use astrid_storage::{ContentName, RuntimePrincipalStore, RuntimeTreeEntry, StateOwner};
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
                .filter(|entry| entry.name().as_str() != RECEIPT_RELATIVE_PATH)
                .map(|entry| RuntimeTreeReceiptEntry {
                    name: entry.name().as_str().to_owned(),
                    bytes: entry.logical_bytes(),
                    modified_nanos: entry.modified_nanos(),
                })
                .collect(),
        }
    }

    fn matches_entries(&self, entries: &[RuntimeTreeEntry]) -> bool {
        let mut actual = entries
            .iter()
            .filter(|entry| entry.name().as_str() != RECEIPT_RELATIVE_PATH);
        self.schema == RECEIPT_SCHEMA
            && self.entries.iter().all(|receipt| {
                actual.next().is_some_and(|entry| {
                    receipt.name == entry.name().as_str()
                        && receipt.bytes == entry.logical_bytes()
                        && receipt.modified_nanos == entry.modified_nanos()
                })
            })
            && actual.next().is_none()
    }
}

/// Admit one host runtime tree, skipping a receipt-matching catalog.
///
/// The blocking walk and packed publication run off the async executor. A
/// receipt is written only after a second metadata scan agrees with the first,
/// so a source mutation during ingest cannot be mistaken for a completed
/// admission. The receipt and ACTIVE inventory publish together using the
/// already committed payload identities.
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

    let admission = store.admit_runtime_tree_snapshot(
        home,
        &entries,
        ContentName::new(RECEIPT_RELATIVE_PATH).map_err(io::Error::other)?,
    )?;
    #[cfg(test)]
    run_source_mutation_hook(home)?;
    let receipt = RuntimeTreeReceipt::from_entries(&entries);
    let bytes = serde_json::to_vec(&receipt).map_err(io::Error::other)?;
    admission.finish(bytes)
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
        .filter(|entry| entry.name().as_str() != RECEIPT_RELATIVE_PATH)
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

    fn private_home_fixture() -> (tempfile::TempDir, AstridHome) {
        #[cfg(windows)]
        let parent = tempfile::Builder::new()
            .prefix("astrid-boot-admission-")
            .tempdir_in(std::env::var_os("LOCALAPPDATA").expect("local app data"))
            .unwrap();
        #[cfg(not(windows))]
        let parent = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(parent.path().join("home"));
        home.ensure().unwrap();
        (parent, home)
    }

    struct ScanObserver(Arc<std::sync::atomic::AtomicUsize>);

    impl tracing::Subscriber for ScanObserver {
        fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
            metadata.is_event() && metadata.target() == "astrid_storage::runtime_tree_scan"
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, _: &tracing::Event<'_>) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    #[tokio::test]
    async fn cold_admission_walks_source_only_for_snapshot_and_final_check() {
        let (_directory, home) = private_home_fixture();
        let store = astrid_storage::open_runtime_principal_store(&home, unlimited_quota())
            .await
            .unwrap();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        tracing::subscriber::with_default(ScanObserver(Arc::clone(&calls)), || {
            admit_blocking(&home, &store).unwrap();
        });
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::Relaxed),
            2,
            "observe every real storage source-walk boundary, including kernel calls"
        );
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
    async fn same_size_host_edit_is_persisted_then_warm_admission_is_unchanged() {
        let (_directory, home) = private_home_fixture();
        let store = astrid_storage::open_runtime_principal_store(&home, unlimited_quota())
            .await
            .unwrap();
        let path = home.root().join("config.toml");
        fs::write(&path, b"old").unwrap();
        admit(&home, &store).await.unwrap();
        fs::write(&path, b"new").unwrap();
        fs::File::open(&path)
            .unwrap()
            .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1))
            .unwrap();
        admit(&home, &store).await.unwrap();
        let name = ContentName::new("config.toml").unwrap();
        assert_eq!(
            store.content().read(&StateOwner::System, &name).unwrap(),
            Some(b"new".to_vec())
        );
        let before = fs::metadata(home.storage_volume_path()).unwrap().len();
        admit(&home, &store).await.unwrap();
        assert_eq!(
            fs::metadata(home.storage_volume_path()).unwrap().len(),
            before
        );
    }

    #[tokio::test]
    async fn malformed_migration_receipt_is_a_hard_error_without_publication() {
        let (_directory, home) = private_home_fixture();
        let store = astrid_storage::open_runtime_principal_store(&home, unlimited_quota())
            .await
            .unwrap();
        astrid_core::platform_fs::atomic_write_private_file(
            &home.migrations_dir().join(RECEIPT_NAME),
            b"{",
        )
        .unwrap();
        let before = fs::metadata(home.storage_volume_path()).unwrap().len();
        assert_eq!(
            admit(&home, &store).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            fs::metadata(home.storage_volume_path()).unwrap().len(),
            before
        );
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
