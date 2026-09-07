//! Keep acknowledged administrative edits in the live runtime projection.
//!
//! Shutdown packs that projection back into the volume. Without write-through,
//! a successful system-owner edit would be overwritten by old host bytes.
//! Principal/fleet mounts never enter this path. Directory capabilities confine
//! every host operation to the already-selected runtime root.

use super::filesystem::CallbackFilesystem;
use super::*;
use cap_std::fs::{Dir, OpenOptions};
use std::io::Write;

pub(super) fn execute(
    home: &astrid_core::dirs::AstridHome,
    store: &astrid_storage::RuntimePrincipalStore,
    operation: StorageFilesystemOperationV1,
) -> Result<StorageFilesystemSuccessV1, FilesystemError> {
    let directory = Dir::open_ambient_dir(home.root(), cap_std::ambient_authority())
        .map_err(|error| host_error(&error))?;
    let filesystem = AstridFilesystem::new(store.content(), StateOwner::System);
    let paths = mutation_paths(&operation);
    for path in &paths {
        validate(&directory, path)?;
    }
    // Publish through the ordinary owner-root transaction first. An operation
    // is acknowledged only once its matching host projection also succeeds.
    let result = execute_blocking(&filesystem, operation.clone())?;
    match operation {
        StorageFilesystemOperationV1::Write { path, .. }
        | StorageFilesystemOperationV1::SetLength { path, .. } => {
            project_file(&directory, &filesystem, &path)?;
        },
        StorageFilesystemOperationV1::Create { path, kind } => match kind {
            StorageFilesystemEntryKindV1::File => project_file(&directory, &filesystem, &path)?,
            StorageFilesystemEntryKindV1::Directory => {
                directory
                    .create_dir(&path)
                    .map_err(|error| host_error(&error))?;
            },
        },
        StorageFilesystemOperationV1::Remove { path } => match directory.symlink_metadata(&path) {
            Ok(metadata) if metadata.is_dir() => directory
                .remove_dir(path)
                .map_err(|error| host_error(&error))?,
            Ok(_) => directory
                .remove_file(path)
                .map_err(|error| host_error(&error))?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {},
            Err(error) => return Err(host_error(&error)),
        },
        StorageFilesystemOperationV1::Rename { from, to, .. } => {
            directory
                .rename(from, &directory, to)
                .map_err(|error| host_error(&error))?;
        },
        _ => {},
    }
    store
        .establish_runtime_projection_receipt(home)
        .map_err(|error| FilesystemError::Staging(error.to_string()))?;
    Ok(result)
}

fn mutation_paths(operation: &StorageFilesystemOperationV1) -> Vec<&str> {
    match operation {
        StorageFilesystemOperationV1::Write { path, .. }
        | StorageFilesystemOperationV1::SetLength { path, .. }
        | StorageFilesystemOperationV1::Create { path, .. }
        | StorageFilesystemOperationV1::Remove { path } => vec![path],
        StorageFilesystemOperationV1::Rename { from, to, .. } => vec![from, to],
        _ => Vec::new(),
    }
}

fn validate(directory: &Dir, path: &str) -> Result<(), FilesystemError> {
    FilesystemPath::new(path)?;
    // Live IPC and the backing store are never ordinary editable files inside
    // their own mount. The key projection is owned by the identity service.
    let protected = [
        "astrid.volume",
        "astrid.migrating",
        "volume",
        "run",
        "var/principal-store",
        "keys/runtime.key",
    ];
    if path.is_empty()
        || protected.iter().any(|prefix| {
            path == *prefix
                || path
                    .strip_prefix(prefix)
                    .is_some_and(|tail| tail.starts_with('/'))
        })
    {
        return Err(FilesystemError::InvalidPath(path.to_owned()));
    }
    let mut current = PathBuf::new();
    for component in path.split('/') {
        current.push(component);
        match directory.symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(FilesystemError::InvalidPath(path.to_owned()));
            },
            Ok(_) => {},
            Err(error) if error.kind() == io::ErrorKind::NotFound => {},
            Err(error) => return Err(host_error(&error)),
        }
    }
    Ok(())
}

fn project_file(
    directory: &Dir,
    filesystem: &impl CallbackFilesystem,
    path: &str,
) -> Result<(), FilesystemError> {
    let logical = FilesystemPath::new(path)?;
    let length = filesystem.stat(&logical)?.logical_bytes();
    let bytes = filesystem.read(&logical, 0, length)?;
    let target = std::path::Path::new(path);
    let parent = target
        .parent()
        .ok_or_else(|| FilesystemError::InvalidPath(path.to_owned()))?;
    let temporary = parent.join(format!(".astrid-edit-{}", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut file =
            directory.open_with(&temporary, OpenOptions::new().write(true).create_new(true))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(cap_std::fs::Permissions::from_std(
                std::fs::Permissions::from_mode(0o600),
            ))?;
        }
        file.write_all(&bytes)?;
        file.sync_all()?;
        directory.rename(&temporary, directory, target)
    })();
    if result.is_err() {
        let _ = directory.remove_file(&temporary);
    }
    result.map_err(|error| host_error(&error))
}

fn host_error(error: &io::Error) -> FilesystemError {
    FilesystemError::Staging(format!("update live administrative projection: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn admin_edit_updates_host_and_survives_shutdown_publication() {
        let root = tempfile::tempdir().unwrap();
        let home = astrid_core::dirs::AstridHome::from_path(root.path().join("runtime"));
        let kernel = crate::test_kernel_with_home(home.clone()).await;
        let store = kernel.principal_store.clone().unwrap();
        let filesystem = AstridFilesystem::new(store.content(), StateOwner::System);
        let path = FilesystemPath::new("config.toml").unwrap();
        let original = b"# old config\n";
        std::fs::write(home.root().join(path.as_str()), original).unwrap();
        filesystem.write(&path, original).unwrap();
        store.establish_runtime_projection_receipt(&home).unwrap();
        let updated = b"# new config\n";
        execute(
            &home,
            &store,
            StorageFilesystemOperationV1::Write {
                path: path.as_str().to_owned(),
                offset: 0,
                data: updated.to_vec(),
            },
        )
        .unwrap();
        assert_eq!(
            std::fs::read(home.root().join(path.as_str())).unwrap(),
            updated
        );
        store.publish_runtime_projection(&home).unwrap();
        assert_eq!(
            filesystem.read(&path, 0, updated.len() as u64).unwrap(),
            updated
        );
        execute(
            &home,
            &store,
            StorageFilesystemOperationV1::Rename {
                from: path.as_str().to_owned(),
                to: "config-saved.toml".to_owned(),
                replace: false,
            },
        )
        .unwrap();
        assert!(!home.root().join("config.toml").exists());
        assert_eq!(
            std::fs::read(home.root().join("config-saved.toml")).unwrap(),
            updated
        );
        execute(
            &home,
            &store,
            StorageFilesystemOperationV1::Remove {
                path: "config-saved.toml".to_owned(),
            },
        )
        .unwrap();
        assert!(!home.root().join("config-saved.toml").exists());
    }

    #[test]
    fn refuses_internal_paths_and_redirects_before_mutation() {
        let root = tempfile::tempdir().unwrap();
        let directory = Dir::open_ambient_dir(root.path(), cap_std::ambient_authority()).unwrap();
        for path in [
            "",
            "../escape",
            "astrid.volume",
            "run/system.sock",
            "var/principal-store/data",
        ] {
            assert!(validate(&directory, path).is_err(), "{path}");
        }
        assert!(validate(&directory, "config.toml").is_ok());
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(root.path(), root.path().join("alias")).unwrap();
            assert!(validate(&directory, "alias/config.toml").is_err());
        }
    }
}
