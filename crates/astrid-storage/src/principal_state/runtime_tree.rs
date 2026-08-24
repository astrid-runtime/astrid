//! Explicit admission of the durable native runtime file tree.
//!
//! The runtime tree is a host-facing source snapshot. Its durable regular
//! files become system-owned named content; live IPC endpoints and bootstrap
//! executables remain outside the volume.

use std::path::{Component, Path, PathBuf};

use crate::content::ContentName;
use crate::error::{StorageError, StorageResult};

use super::{ContiguousFileIngest, RuntimePrincipalStore, StateOwner};

const EXCLUDED_PATHS: [&str; 8] = [
    "etc/layout-version",
    "var/astrid.volume",
    "keys/runtime.key",
    "run/system.sock",
    "run/system.lock",
    "run/system.pid",
    "run/system.ready",
    "run/system.token",
];

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
        let relative_text = relative
            .to_str()
            .ok_or_else(|| tree_error(&path, "source entry path is not valid UTF-8".to_owned()))?;
        if is_excluded(relative_text) {
            continue;
        }

        let metadata = std::fs::symlink_metadata(&path)
            .map_err(|error| tree_error(&path, format!("inspect source entry: {error}")))?;
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            return Err(tree_error(
                &path,
                "source tree contains a symbolic link".to_owned(),
            ));
        }
        if metadata.is_dir() {
            collect_files(root, &path, files)?;
        } else if metadata.is_file() {
            files.push((
                relative_text.replace(std::path::MAIN_SEPARATOR, "/"),
                path,
                metadata,
            ));
        } else {
            return Err(tree_error(
                &path,
                "source tree contains a special entry".to_owned(),
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

fn is_excluded(relative: &str) -> bool {
    EXCLUDED_PATHS.contains(&relative)
        || relative == "var/migrations"
        || relative.starts_with("var/migrations/")
        || relative == "var/content-staging"
        || relative.starts_with("var/content-staging/")
        || relative == "var/principal-store"
        || relative.starts_with("var/principal-store/")
        || matches!(
            relative,
            "astrid" | "astrid-daemon" | "bin/astrid" | "bin/astrid-daemon"
        )
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

    #[tokio::test]
    async fn admits_runtime_tree_and_reopens_from_preclose_volume_copy() {
        let source = tempfile::tempdir().unwrap();
        let home_dir = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(home_dir.path());
        home.ensure().unwrap();
        let wasm = b"\0asm\x01\0\0\0runtime-wasm-unique".to_vec();
        let nested_wasm = b"\0asm\x01\0\0\0nested-wasm-unique".to_vec();
        let wasm_hash = blake3::hash(&wasm).to_hex().to_string();
        let durable = vec![
            (format!("bin/{wasm_hash}.wasm"), wasm.clone()),
            (
                "run/capsules/example/meta.json".to_owned(),
                format!("{{\"wasm_hash\":\"{wasm_hash}\"}}").into_bytes(),
            ),
            (
                "run/capsules/example/component.wasm".to_owned(),
                nested_wasm.clone(),
            ),
            (
                "wit/astrid-contracts.wit".to_owned(),
                b"package astrid:contracts;".to_vec(),
            ),
            ("var/config.json".to_owned(), b"{\"durable\":true}".to_vec()),
        ];
        for (relative, bytes) in &durable {
            let path = source.path().join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, bytes).unwrap();
        }
        for relative in [
            "var/astrid.volume",
            "run/system.sock",
            "run/system.lock",
            "run/system.pid",
            "run/system.ready",
            "run/system.token",
            "astrid",
            "astrid-daemon",
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
        let mut reconstructed = BTreeMap::new();
        for (name, bytes) in durable {
            let path = FilesystemPath::new(name).unwrap();
            let entry = filesystem.stat(&path).unwrap();
            let actual = filesystem.read(&path, 0, entry.logical_bytes()).unwrap();
            let expected_digest = Sha256::digest(&bytes);
            assert_eq!(Sha256::digest(&actual), expected_digest);
            reconstructed.insert(path.as_str().to_owned(), actual);
        }
        assert_eq!(reconstructed.len(), 5);
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
}
