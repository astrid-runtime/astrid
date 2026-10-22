//! Restore regular files and explicit filesystem directory markers distinctly.

use super::{Path, PathBuf, StorageResult, normalize_relative_path, tree_error};

pub(super) fn confined_projection_path(root: &Path, relative: &str) -> StorageResult<PathBuf> {
    let normalized = normalize_relative_path(relative);
    let escaped = || {
        tree_error(
            root,
            format!("projection name escaped runtime root: {relative}"),
        )
    };
    if normalized.is_empty() || normalized.starts_with('/') || Path::new(relative).is_absolute() {
        return Err(escaped());
    }
    let mut path = root.to_path_buf();
    for segment in normalized.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(tree_error(
                root,
                format!("projection name has a non-normal path component: {relative}"),
            ));
        }
        if segment.len() == 2 && segment.as_bytes()[1] == b':' {
            return Err(escaped());
        }
        path.push(segment);
    }
    if !path.starts_with(root) {
        return Err(escaped());
    }
    Ok(path)
}

pub(super) fn write_projection_file(
    root: &Path,
    relative: &str,
    bytes: &[u8],
) -> StorageResult<()> {
    let path = confined_projection_path(root, relative)?;
    let parent = path
        .parent()
        .ok_or_else(|| tree_error(&path, "projection path has no parent".to_owned()))?;
    super::super::native_io::ensure_private_directory(parent)?;
    astrid_core::platform_fs::atomic_write_private_file(&path, bytes)
        .map_err(|error| tree_error(&path, format!("project volume-backed file: {error}")))?;
    Ok(())
}

pub(super) fn restore_directory(root: &Path, name: &str, logical_bytes: u64) -> StorageResult<()> {
    if logical_bytes != 0 {
        return Err(tree_error(root, "directory marker contains file bytes"));
    }
    let path = confined_projection_path(root, name)?;
    super::super::native_io::ensure_private_directory(&path)
}

pub(super) fn surviving_directory(root: &Path, name: &str) -> bool {
    let Some(relative) = name.strip_suffix('/') else {
        return false;
    };
    confined_projection_path(root, relative)
        .and_then(|path| std::fs::symlink_metadata(path).map_err(|error| tree_error(root, error)))
        .is_ok_and(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
}

#[cfg(test)]
mod tests {
    use crate::{
        AstridFilesystem, FilesystemPath, KvQuotaResolver, StateOwner, open_runtime_principal_store,
    };
    use astrid_core::dirs::AstridHome;
    use std::sync::Arc;

    #[tokio::test]
    async fn empty_admin_directory_survives_volume_only_stop_and_reopen() {
        let root = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(root.path());
        let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|_: &StateOwner| Ok(None));
        let store = open_runtime_principal_store(&home, quota.clone())
            .await
            .unwrap();
        let filesystem = AstridFilesystem::new(store.content(), StateOwner::System);
        filesystem
            .create_dir(&FilesystemPath::new(".fseventsd").unwrap())
            .unwrap();
        std::fs::create_dir(home.root().join(".fseventsd")).unwrap();
        store.establish_runtime_projection_receipt(&home).unwrap();
        drop(filesystem);
        store.pack_and_retire_runtime_projection(&home).unwrap();
        drop(store);
        assert_eq!(std::fs::read_dir(home.root()).unwrap().count(), 1);

        for _ in 0..2 {
            let store = open_runtime_principal_store(&home, quota.clone())
                .await
                .unwrap();
            assert!(home.root().join(".fseventsd").is_dir());
            let filesystem = AstridFilesystem::new(store.content(), StateOwner::System);
            assert!(
                filesystem
                    .stat(&FilesystemPath::new(".fseventsd").unwrap())
                    .is_ok()
            );
            drop(filesystem);
            store.pack_and_retire_runtime_projection(&home).unwrap();
            drop(store);
        }
    }
}
