//! Explicit admission of the durable native runtime file tree.
//!
//! The runtime tree is a host-facing source snapshot. Its durable regular
//! files become system-owned named content; only the hosted volume and live
//! IPC socket remain outside the volume.

use std::path::{Component, Path, PathBuf};

use crate::content::ContentName;
use crate::error::{StorageError, StorageResult};
use astrid_core::dirs::AstridHome;

use super::{ContiguousFileIngest, RuntimePrincipalStore, StateOwner};

const VOLUME_PATH_PREFIX: &str = "volume";
const SOCKET_PATH: &str = "run/system.sock";
const CANONICAL_VOLUME: &str = "astrid.volume";
const LEGACY_VAR_VOLUME: &str = "var/astrid.volume";
const DIRECTORY_STORE_PREFIX: &str = "var/principal-store";
const QUARANTINE_PREFIX: &str = "quarantine/principal-store";
const TRANSIENT_PREFIX: &str = "run";
const RUNTIME_KEY_PROJECTION: &str = "keys/runtime.key";
const HOST_EXECUTABLES: &[&str] = &["astrid", "astrid-daemon", "bin/astrid", "bin/astrid-daemon"];

/// One regular file discovered in the native runtime tree.
///
/// The source path is retained only for the immediate packed admission. The
/// name, length, and modification time form the host-side receipt identity
/// used by the kernel to skip an unchanged tree on later boots.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeTreeEntry {
    name: ContentName,
    source_path: PathBuf,
    logical_bytes: u64,
    modified_nanos: i128,
}

impl RuntimeTreeEntry {
    /// Borrow the slash-separated catalog name.
    #[must_use]
    pub const fn name(&self) -> &ContentName {
        &self.name
    }

    /// Return the source file length captured by the scan.
    #[must_use]
    pub const fn logical_bytes(&self) -> u64 {
        self.logical_bytes
    }

    /// Return the source modification time as signed Unix nanoseconds.
    #[must_use]
    pub const fn modified_nanos(&self) -> i128 {
        self.modified_nanos
    }
}

/// Scan the native runtime tree without reading file payloads.
pub(super) fn scan(runtime_root: &Path) -> StorageResult<Vec<RuntimeTreeEntry>> {
    let metadata = std::fs::symlink_metadata(runtime_root)
        .map_err(|error| tree_error(runtime_root, format!("inspect source root: {error}")))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(tree_error(
            runtime_root,
            "source root is not a real directory".to_owned(),
        ));
    }

    let mut files = Vec::new();
    collect_files(runtime_root, runtime_root, &mut files)?;
    files.sort_by(|left, right| left.0.cmp(&right.0));
    files
        .into_iter()
        .map(|(_, path, metadata)| {
            let name = content_name_from_relative(&path, runtime_root)?;
            let modified_nanos = modified_nanos(&metadata, &path)?;
            Ok(RuntimeTreeEntry {
                name,
                source_path: path,
                logical_bytes: metadata.len(),
                modified_nanos,
            })
        })
        .collect()
}

/// Walk `runtime_root` and publish its durable regular files as one packed
/// system-owned content batch.
pub(super) fn admit(store: &RuntimePrincipalStore, runtime_root: &Path) -> StorageResult<()> {
    let entries = scan(runtime_root)?;
    let validated = entries
        .into_iter()
        .map(|entry| ContiguousFileIngest::new(entry.name, entry.source_path, entry.logical_bytes));
    store.put_contiguous_files(StateOwner::System, validated)
}

fn collect_files(
    root: &Path,
    directory: &Path,
    files: &mut Vec<(String, PathBuf, std::fs::Metadata)>,
) -> StorageResult<()> {
    let mut entries = std::fs::read_dir(directory)
        .map_err(|error| tree_error(directory, format!("read directory: {error}")))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| tree_error(directory, format!("read directory entry: {error}")))?;
    entries.sort_by_key(std::fs::DirEntry::file_name);

    for entry in entries {
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .map_err(|_| tree_error(&path, "source entry escaped runtime root".to_owned()))?;
        let metadata = std::fs::symlink_metadata(&path)
            .map_err(|error| tree_error(&path, format!("inspect source entry: {error}")))?;
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            return Err(tree_error(
                &path,
                "source tree contains a symbolic link".to_owned(),
            ));
        }
        // Sockets and other host-special entries are never catalog content.
        // Ignore them so a stale endpoint cannot fail admission of the
        // regular files that make up the runtime snapshot.
        if let Some(relative_text) = relative.to_str() {
            let relative_text = normalize_relative_path(relative_text);
            if is_excluded(&relative_text) {
                continue;
            }
            if metadata.is_dir() {
                collect_files(root, &path, files)?;
            } else if metadata.is_file() {
                files.push((relative_text, path, metadata));
            }
        } else if metadata.is_dir() || metadata.is_file() {
            return Err(tree_error(
                &path,
                "source entry path is not valid UTF-8".to_owned(),
            ));
        }
    }
    Ok(())
}

fn modified_nanos(metadata: &std::fs::Metadata, path: &Path) -> StorageResult<i128> {
    let modified = metadata
        .modified()
        .map_err(|error| tree_error(path, format!("read source modification time: {error}")))?;
    let duration = match modified.duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => i128::try_from(duration.as_nanos()).map_err(|_| {
            tree_error(
                path,
                "source modification time exceeds receipt range".to_owned(),
            )
        })?,
        Err(error) => {
            let nanos = i128::try_from(error.duration().as_nanos()).map_err(|_| {
                tree_error(
                    path,
                    "source modification time exceeds receipt range".to_owned(),
                )
            })?;
            nanos.checked_neg().ok_or_else(|| {
                tree_error(
                    path,
                    "source modification time exceeds receipt range".to_owned(),
                )
            })?
        },
    };
    Ok(duration)
}

fn content_name_from_relative(path: &Path, root: &Path) -> StorageResult<ContentName> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| tree_error(path, "source entry escaped runtime root".to_owned()))?;
    let mut name = String::new();
    for component in relative.components() {
        let Component::Normal(segment) = component else {
            return Err(tree_error(
                path,
                "source entry has a non-normal path component".to_owned(),
            ));
        };
        let segment = segment
            .to_str()
            .ok_or_else(|| tree_error(path, "source entry path is not valid UTF-8".to_owned()))?;
        if !name.is_empty() {
            name.push('/');
        }
        name.push_str(segment);
    }
    ContentName::new(name).map_err(|error| {
        tree_error(
            path,
            format!("source entry is not a valid content name: {error}"),
        )
    })
}

fn normalize_relative_path(relative: &str) -> String {
    relative.replace('\\', "/")
}

fn is_path_or_descendant(relative: &str, prefix: &str) -> bool {
    relative == prefix || relative.starts_with(&format!("{prefix}/"))
}

fn is_excluded(relative: &str) -> bool {
    relative == CANONICAL_VOLUME
        || relative == LEGACY_VAR_VOLUME
        || is_path_or_descendant(relative, VOLUME_PATH_PREFIX)
        || (relative.starts_with(&format!("{TRANSIENT_PREFIX}/"))
            && !is_path_or_descendant(relative, &format!("{TRANSIENT_PREFIX}/capsules")))
        || is_path_or_descendant(relative, DIRECTORY_STORE_PREFIX)
        || HOST_EXECUTABLES.contains(&relative)
        || relative == SOCKET_PATH
        || std::path::Path::new(relative)
            .extension()
            .is_some_and(|extension| {
                matches!(
                    extension.to_ascii_lowercase().to_str(),
                    Some("next" | "migrating")
                )
            })
}

/// Replace durable host files with volume-backed running projections.
pub(super) fn restore_projection(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
    content: &super::NativePrincipalContentStore,
) -> StorageResult<()> {
    let layout_version = home
        .layout_version()
        .map_err(|error| tree_io_error(&error))?;
    if layout_version.as_deref() == Some(astrid_core::dirs::LEGACY_LAYOUT_VERSION) {
        return Ok(());
    }
    ingest_runtime_key(home, store)?;
    seed_layout_version(home, store)?;
    let entries = content
        .list(&StateOwner::System)
        .map_err(|error| tree_error(home.root(), format!("list volume projection: {error}")))?;
    for entry in entries {
        let name = entry.name().as_str();
        if is_excluded(name) {
            continue;
        }
        if is_retired_legacy_projection(home, name) {
            continue;
        }
        let Some(bytes) = content
            .read(&StateOwner::System, entry.name())
            .map_err(|error| tree_error(home.root(), format!("read projection {name}: {error}")))?
        else {
            continue;
        };
        write_projection_file(home.root(), name, &bytes)?;
    }
    Ok(())
}

fn is_retired_legacy_projection(home: &AstridHome, name: &str) -> bool {
    [home.state_db_path(), home.cow_dir()]
        .into_iter()
        .filter_map(|path| {
            path.strip_prefix(home.root())
                .ok()
                .and_then(|relative| relative.to_str())
                .map(ToOwned::to_owned)
        })
        .any(|relative| normalize_relative_path(&relative) == name)
}

/// Admit an incomplete legacy-store tree as durable System-owned quarantine.
///
/// Residue is published only after its source bytes are read without
/// following redirects. The host tree is removed only after the complete
/// quarantine batch is flushed, so an interrupted quarantine fails closed
/// with the source still present and retries under a fresh generation.
pub(super) fn quarantine_principal_store(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
) -> StorageResult<()> {
    let source = home.principal_store_path();
    validate_legacy_retirement_candidate(&source)?;
    let mut files = Vec::new();
    collect_files(&source, &source, &mut files)?;
    files.sort_by(|left, right| left.0.cmp(&right.0));

    let generation = next_quarantine_generation(store)?;
    let mut ingests = Vec::with_capacity(files.len());
    for (relative, path, metadata) in files {
        let name = ContentName::new(format!("{QUARANTINE_PREFIX}/{generation}/{relative}"))
            .map_err(|error| tree_error(&path, format!("validate quarantine name: {error}")))?;
        ingests.push(ContiguousFileIngest::new(name, path, metadata.len()));
    }
    store.put_contiguous_files(StateOwner::System, ingests)?;
    store
        .content()
        .flush()
        .map_err(|error| tree_error(&source, format!("flush quarantine: {error}")))?;
    astrid_core::dirs::retire_legacy_source_tree(&source)
        .map_err(|error| tree_error(&source, format!("retire quarantine source: {error}")))
}

/// Refuse ingest before publication unless the source is a real same-device
/// tree with no redirects or special entries.
fn validate_legacy_retirement_candidate(source: &Path) -> StorageResult<()> {
    let metadata = std::fs::symlink_metadata(source)
        .map_err(|error| tree_error(source, format!("inspect retirement source: {error}")))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(tree_error(
            source,
            "retirement source is redirected or not a directory".to_owned(),
        ));
    }
    let root_device = legacy_tree_device(&metadata);
    validate_retirement_tree(source, root_device)
}

#[cfg(unix)]
fn legacy_tree_device(metadata: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt as _;

    metadata.dev()
}

#[cfg(not(unix))]
fn legacy_tree_device(_metadata: &std::fs::Metadata) -> u64 {
    0
}

fn validate_retirement_tree(path: &Path, root_device: u64) -> StorageResult<()> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| tree_error(path, format!("inspect retirement source: {error}")))?;
    if metadata.file_type().is_symlink() {
        return Err(tree_error(
            path,
            "retirement source contains a symbolic link".to_owned(),
        ));
    }
    if !metadata.is_dir() && !metadata.is_file() {
        return Err(tree_error(
            path,
            "retirement source contains a special file".to_owned(),
        ));
    }
    if legacy_tree_device(&metadata) != root_device {
        return Err(tree_error(
            path,
            "retirement source crosses a filesystem boundary".to_owned(),
        ));
    }
    astrid_core::platform_fs::verify_no_redirects(path)
        .map_err(|error| tree_error(path, format!("validate retirement source: {error}")))?;
    if !metadata.is_dir() {
        return Ok(());
    }
    for entry in std::fs::read_dir(path)
        .map_err(|error| tree_error(path, format!("read retirement source: {error}")))?
    {
        let child = entry
            .map_err(|error| tree_error(path, format!("read retirement entry: {error}")))?
            .path();
        validate_retirement_tree(&child, root_device)?;
    }
    Ok(())
}

fn next_quarantine_generation(store: &RuntimePrincipalStore) -> StorageResult<u32> {
    let names = store
        .content()
        .list_prefix(&StateOwner::System, QUARANTINE_PREFIX)
        .map_err(|error| tree_error_home(QUARANTINE_PREFIX, error))?;
    let mut next = 0_u32;
    for entry in names {
        let Some(relative) = entry.name().as_str().strip_prefix(QUARANTINE_PREFIX) else {
            continue;
        };
        let Some(generation) = relative.trim_start_matches('/').split('/').next() else {
            continue;
        };
        if let Ok(value) = generation.parse::<u32>() {
            next = next.max(value.saturating_add(1));
        }
    }
    Ok(next)
}

fn tree_error_home(path: &str, error: impl std::fmt::Display) -> StorageError {
    StorageError::Connection(format!("runtime tree {path}: {error}"))
}

/// Preserve a pre-cutover runtime signing key across volume initialization.
///
/// A first open may discover an installed runtime key before a volume exists.
/// The key must enter system-owned volume content before the durable-root
/// cleanup, or later capsule verification sees a newly generated identity.
fn ingest_runtime_key(home: &AstridHome, store: &RuntimePrincipalStore) -> StorageResult<()> {
    let source = home.runtime_key_path();
    let metadata = match std::fs::symlink_metadata(&source) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(tree_error(&source, format!("inspect runtime key: {error}"))),
    };
    if metadata.file_type().is_symlink() {
        return Err(tree_error(
            &source,
            "runtime key contains a symbolic link".to_owned(),
        ));
    }
    if !metadata.is_file() {
        return Err(tree_error(
            &source,
            "runtime key is not a regular file".to_owned(),
        ));
    }

    let name = ContentName::new(RUNTIME_KEY_PROJECTION.to_owned()).map_err(|error| {
        tree_error(
            &source,
            format!("runtime key is not a valid content name: {error}"),
        )
    })?;
    if store
        .content()
        .describe(&StateOwner::System, &name)
        .map_err(|error| tree_error(&source, format!("inspect runtime key: {error}")))?
        .is_some()
    {
        return Ok(());
    }

    store.put_contiguous_files(
        StateOwner::System,
        [ContiguousFileIngest::new(name, source, metadata.len())],
    )
}

/// Materialize the compatibility sentinel from durable volume authority.
fn seed_layout_version(home: &AstridHome, store: &RuntimePrincipalStore) -> StorageResult<()> {
    let name = ContentName::new("etc/layout-version".to_owned())
        .map_err(|error| tree_error(home.root(), format!("validate layout sentinel: {error}")))?;
    if store
        .content()
        .describe(&StateOwner::System, &name)
        .map_err(|error| tree_error(home.root(), format!("inspect layout sentinel: {error}")))?
        .is_some()
    {
        return Ok(());
    }
    let staging = std::env::temp_dir().join(format!(
        "astrid-layout-{}.tmp",
        uuid::Uuid::new_v4().simple()
    ));
    let result = (|| {
        std::fs::write(&staging, astrid_core::dirs::LAYOUT_VERSION).map_err(|error| {
            tree_error(
                home.root(),
                format!("write layout sentinel source: {error}"),
            )
        })?;
        store.put_contiguous_files(
            StateOwner::System,
            [ContiguousFileIngest::new(
                name,
                &staging,
                astrid_core::dirs::LAYOUT_VERSION.len() as u64,
            )],
        )
    })();
    let _ = std::fs::remove_file(&staging);
    result
}

/// Publish current running projection changes, then retire their host files.
pub(super) fn pack_and_retire_projection(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
) -> StorageResult<()> {
    admit(store, home.root())?;
    store
        .content()
        .flush()
        .map_err(|error| tree_error(home.root(), format!("flush volume projection: {error}")))?;
    retire_projection(home)
}

fn write_projection_file(root: &Path, relative: &str, bytes: &[u8]) -> StorageResult<()> {
    let path = root.join(relative);
    let parent = path
        .parent()
        .ok_or_else(|| tree_error(&path, "projection path has no parent".to_owned()))?;
    super::native_io::ensure_private_directory(parent)?;
    astrid_core::platform_fs::atomic_write_private_file(&path, bytes)
        .map_err(|error| tree_error(&path, format!("project volume-backed file: {error}")))?;
    Ok(())
}

fn retire_projection(home: &AstridHome) -> StorageResult<()> {
    let root = home.root();
    let mut entries = std::fs::read_dir(root)
        .map_err(|error| tree_error(root, format!("read durable root: {error}")))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| tree_error(root, format!("read durable root entry: {error}")))?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        if entry.file_name() == std::ffi::OsStr::new(CANONICAL_VOLUME) {
            continue;
        }
        let metadata = std::fs::symlink_metadata(&path)
            .map_err(|error| tree_error(&path, format!("inspect projection: {error}")))?;
        if metadata.file_type().is_symlink() {
            return Err(tree_error(
                &path,
                "running projection contains a symbolic link".to_owned(),
            ));
        }
        if metadata.is_dir() {
            astrid_core::dirs::retire_legacy_source_tree(&path)
                .map_err(|error| tree_error(&path, format!("retire projection: {error}")))?;
        } else if metadata.is_file() {
            std::fs::remove_file(&path)
                .map_err(|error| tree_error(&path, format!("retire projection: {error}")))?;
        } else {
            return Err(tree_error(
                &path,
                "running projection contains a special file".to_owned(),
            ));
        }
    }
    super::native_io::sync_directory(root)
}

fn tree_io_error(error: &std::io::Error) -> StorageError {
    StorageError::Connection(error.to_string())
}

fn tree_error(path: &Path, detail: impl std::fmt::Display) -> StorageError {
    StorageError::Connection(format!("runtime tree {}: {detail}", path.display()))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use sha2::{Digest as _, Sha256};

    use super::*;
    use crate::principal_state::open_runtime_principal_store_for_pack;
    use crate::volume::{AstridVolume as _, HostedFileVolume};
    use crate::{AstridFilesystem, FilesystemPath, KvQuotaResolver, open_runtime_principal_store};
    use astrid_core::dirs::AstridHome;

    fn unlimited_quota() -> Arc<dyn KvQuotaResolver<StateOwner>> {
        Arc::new(|owner: &StateOwner| {
            Ok(match owner {
                StateOwner::System => None,
                StateOwner::Principal(_) | StateOwner::Fleet(_) => Some(u64::MAX),
            })
        })
    }

    #[test]
    fn excludes_windows_separator_paths() {
        for path in ["volume", "volume\\compacting", "run\\system.sock"] {
            let normalized = normalize_relative_path(path);
            assert!(is_excluded(&normalized), "path was not excluded: {path}");
        }
        assert_eq!(
            normalize_relative_path("run\\system.ready"),
            "run/system.ready"
        );
    }

    #[test]
    fn excludes_paths_only_at_exact_or_directory_boundaries() {
        for path in [
            "volume",
            "volume/compacting",
            "volume2",
            "volumetric.txt",
            "volume.previous",
            "var/principal-store",
            "var/principal-store/agent.json",
            "var/principal-store2",
            "var/principal-store2/agent.json",
            "run/capsulesX",
            "run/capsulesX/example/component.wasm",
            "run/capsules/example/component.wasm",
        ] {
            let normalized = normalize_relative_path(path);
            let excluded = is_excluded(&normalized);
            let expected = !matches!(
                path,
                "volume2"
                    | "volumetric.txt"
                    | "volume.previous"
                    | "var/principal-store2"
                    | "var/principal-store2/agent.json"
                    | "run/capsules/example/component.wasm"
            );
            assert_eq!(excluded, expected, "unexpected admission for {path}");
        }
        assert!(!is_excluded("run/capsules"));
    }

    #[test]
    fn allows_run_capsule_projections() {
        let normalized = normalize_relative_path("run/capsules/example/component.wasm");
        assert!(!is_excluded(&normalized));
        assert!(!is_excluded("run"));
        assert!(!is_excluded("run/capsules"));

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("run/capsules/example/component.wasm");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"run-capsule").unwrap();
        let entries = scan(directory.path()).unwrap();
        assert_eq!(entries.len(), 1, "scan entries: {entries:?}");
        assert_eq!(
            entries[0].name().as_str(),
            "run/capsules/example/component.wasm"
        );
    }

    fn durable_files(wasm_hash: &str, wasm: &[u8]) -> Vec<(String, Vec<u8>)> {
        vec![
            (format!("bin/{wasm_hash}.wasm"), wasm.to_vec()),
            (
                "wit/astrid-contracts.wit".to_owned(),
                b"package astrid:contracts;".to_vec(),
            ),
            ("etc/layout-version".to_owned(), b"2".to_vec()),
            ("keys/runtime.key".to_owned(), b"runtime-key".to_vec()),
            ("var/content-staging/payload".to_owned(), b"staged".to_vec()),
            ("var/config.json".to_owned(), b"{\"durable\":true}".to_vec()),
            ("var/migrations/marker".to_owned(), b"migration".to_vec()),
        ]
    }

    #[tokio::test]
    async fn admits_runtime_tree_and_reopens_from_preclose_volume_copy() {
        let source = tempfile::tempdir().unwrap();
        let home_dir = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(home_dir.path());
        home.ensure().unwrap();
        let wasm = b"\0asm\x01\0\0\0runtime-wasm-unique".to_vec();
        let wasm_hash = blake3::hash(&wasm).to_hex().to_string();
        let durable = durable_files(&wasm_hash, &wasm);
        for (relative, bytes) in &durable {
            let path = source.path().join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, bytes).unwrap();
        }
        for relative in [
            "volume",
            "volume.compacting",
            "volume.previous",
            "run/system.sock",
        ] {
            let path = source.path().join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, b"host-only").unwrap();
        }

        let store = open_runtime_principal_store(&home, unlimited_quota())
            .await
            .unwrap();
        store.admit_runtime_tree(source.path()).unwrap();

        let names = store
            .content()
            .list(&StateOwner::System)
            .unwrap()
            .into_iter()
            .map(|entry| entry.name().as_str().to_owned())
            .collect::<Vec<_>>();
        let mut expected_names = durable
            .iter()
            .map(|(name, _)| name.clone())
            .collect::<Vec<_>>();
        expected_names.extend(["volume.compacting", "volume.previous"].map(str::to_owned));
        expected_names.sort();
        assert_eq!(names, expected_names);

        let copied_home_dir = tempfile::tempdir().unwrap();
        let copied_home = AstridHome::from_path(copied_home_dir.path());
        copied_home.ensure().unwrap();
        std::fs::copy(
            home.storage_volume_path(),
            copied_home.storage_volume_path(),
        )
        .unwrap();
        let volume = HostedFileVolume::open(copied_home.storage_volume_path()).unwrap();
        assert!(
            volume
                .list_regions("representations/blobs/loose")
                .unwrap()
                .is_empty()
        );
        drop(volume);

        let reopened = open_runtime_principal_store(&copied_home, unlimited_quota())
            .await
            .unwrap();
        let filesystem = AstridFilesystem::new(reopened.content(), StateOwner::System);
        let expected_count = durable.len();
        let mut reconstructed = BTreeMap::new();
        for (name, bytes) in durable {
            let path = FilesystemPath::new(name).unwrap();
            let entry = filesystem.stat(&path).unwrap();
            let actual = filesystem.read(&path, 0, entry.logical_bytes()).unwrap();
            let expected_digest = Sha256::digest(&bytes);
            assert_eq!(Sha256::digest(&actual), expected_digest);
            reconstructed.insert(path.as_str().to_owned(), actual);
        }
        assert_eq!(reconstructed.len(), expected_count);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_redirects_before_publication() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        symlink(outside.path(), root.path().join("redirect")).unwrap();
        let error = scan(root.path()).unwrap_err();
        assert!(error.to_string().contains("symbolic link"));
    }

    #[cfg(unix)]
    #[test]
    fn skips_special_entries_without_failing_scan() {
        use std::os::unix::net::UnixListener;

        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("run")).unwrap();
        std::fs::write(root.path().join("regular"), b"durable").unwrap();
        let _socket = UnixListener::bind(root.path().join("run/other.sock")).unwrap();

        let entries = scan(root.path()).unwrap();
        assert_eq!(
            entries
                .iter()
                .map(|entry| entry.name().as_str())
                .collect::<Vec<_>>(),
            ["regular"]
        );
    }

    #[tokio::test]
    async fn preserves_runtime_key_across_initialization_and_restart() {
        let home_dir = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(home_dir.path());
        let key_path = home.runtime_key_path();
        std::fs::create_dir_all(key_path.parent().unwrap()).unwrap();
        std::fs::write(&key_path, b"original-runtime-key").unwrap();

        let store = open_runtime_principal_store(&home, unlimited_quota())
            .await
            .unwrap();
        assert_eq!(std::fs::read(&key_path).unwrap(), b"original-runtime-key");
        let runtime_key = ContentName::new(RUNTIME_KEY_PROJECTION).unwrap();
        assert!(
            store
                .content()
                .describe(&StateOwner::System, &runtime_key)
                .unwrap()
                .is_some()
        );
        drop(store);

        let store = open_runtime_principal_store_for_pack(&home, unlimited_quota())
            .await
            .unwrap();
        store
            .pack_and_retire_runtime_projection(&home)
            .expect("pack runtime key");
        drop(store);
        assert!(!key_path.exists());
        assert!(!home.keys_dir().exists());
        let stopped = std::fs::read_dir(home.root())
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(stopped.len(), 1);
        assert_eq!(
            stopped[0].file_name(),
            std::ffi::OsStr::new(CANONICAL_VOLUME)
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                stopped[0].metadata().unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        let reopened = open_runtime_principal_store(&home, unlimited_quota())
            .await
            .unwrap();
        assert_eq!(std::fs::read(&key_path).unwrap(), b"original-runtime-key");
        drop(reopened);
    }

    #[tokio::test]
    async fn packs_trust_projection_and_excludes_run_on_clean_stop() {
        let home_dir = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(home_dir.path());
        let store = open_runtime_principal_store(&home, unlimited_quota())
            .await
            .unwrap();
        let trust = home.root().join("trust/test.pub");
        std::fs::create_dir_all(trust.parent().unwrap()).unwrap();
        std::fs::write(&trust, b"ed25519:test").unwrap();
        let transient = home.run_dir().join("system.pid");
        std::fs::create_dir_all(transient.parent().unwrap()).unwrap();
        std::fs::write(&transient, b"pid").unwrap();

        drop(store);
        let store = open_runtime_principal_store_for_pack(&home, unlimited_quota())
            .await
            .unwrap();
        store
            .pack_and_retire_runtime_projection(&home)
            .expect("pack running projection");
        assert!(!trust.exists());
        assert!(!home.run_dir().exists());

        let catalog = store
            .content()
            .list(&StateOwner::System)
            .unwrap()
            .into_iter()
            .map(|entry| entry.name().as_str().to_owned())
            .collect::<Vec<_>>();
        assert!(catalog.iter().any(|name| name == "trust/test.pub"));
        assert!(!catalog.iter().any(|name| name.starts_with("run/")));

        drop(store);
        let reopened = open_runtime_principal_store(&home, unlimited_quota())
            .await
            .unwrap();
        assert!(trust.is_file(), "trusted pin must be mounted on restart");
        assert!(!home.run_dir().exists());
        reopened
            .pack_and_retire_runtime_projection(&home)
            .expect("retire restarted projection");

        let stopped = std::fs::read_dir(home.root())
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(stopped.len(), 1);
        assert_eq!(
            stopped[0].file_name(),
            std::ffi::OsStr::new("astrid.volume")
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                stopped[0].metadata().unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[tokio::test]
    async fn clean_stop_restores_capsules_and_layout_receipts_on_restart() {
        let home_dir = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(home_dir.path());
        let store = open_runtime_principal_store(&home, unlimited_quota())
            .await
            .unwrap();
        drop(store);

        let capsule = home
            .home_dir()
            .join("default/.local/capsules/example/capsule.json");
        let receipt = home.migrations_dir().join("layout-v1-to-v2.complete");
        let retirement = home.migrations_dir().join("layout-v1-to-v2.retiring");
        std::fs::create_dir_all(capsule.parent().unwrap()).unwrap();
        std::fs::create_dir_all(receipt.parent().unwrap()).unwrap();
        std::fs::write(&capsule, br#"{"id":"example"}"#).unwrap();
        std::fs::write(&receipt, b"layout-v1-to-v2\n").unwrap();
        std::fs::write(&retirement, b"retirement-source\n").unwrap();

        let store = open_runtime_principal_store_for_pack(&home, unlimited_quota())
            .await
            .unwrap();
        store
            .pack_and_retire_runtime_projection(&home)
            .expect("pack capsule and receipt");
        let stopped = std::fs::read_dir(home.root())
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(stopped.len(), 1);
        assert_eq!(
            stopped[0].file_name(),
            std::ffi::OsStr::new(CANONICAL_VOLUME)
        );
        drop(store);

        let reopened = open_runtime_principal_store(&home, unlimited_quota())
            .await
            .unwrap();
        assert_eq!(std::fs::read(&capsule).unwrap(), br#"{"id":"example"}"#);
        assert_eq!(std::fs::read(&receipt).unwrap(), b"layout-v1-to-v2\n");
        assert_eq!(std::fs::read(&retirement).unwrap(), b"retirement-source\n");
        reopened
            .pack_and_retire_runtime_projection(&home)
            .expect("retire restarted projection");
        assert_eq!(std::fs::read_dir(home.root()).unwrap().count(), 1);
    }
}
