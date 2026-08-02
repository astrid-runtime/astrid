//! Private native filesystem mechanics shared by store migrations and staging.

use std::fs::{File, OpenOptions};
#[cfg(not(windows))]
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::error::{StorageError, StorageResult};

pub(super) fn ensure_private_directory(path: &Path) -> StorageResult<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(connection(format!(
                "private directory {} is redirected or not a directory",
                path.display()
            )));
        },
        Ok(_) => {},
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
        Err(error) => {
            return Err(connection(format!(
                "inspect private directory {}: {error}",
                path.display()
            )));
        },
    }
    astrid_core::platform_fs::ensure_private_directory(path).map_err(|error| {
        connection(format!(
            "create private directory {}: {error}",
            path.display()
        ))
    })?;
    astrid_core::platform_fs::verify_no_redirects(path).map_err(|error| {
        connection(format!(
            "validate private directory {}: {error}",
            path.display()
        ))
    })?;
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        connection(format!(
            "inspect private directory {}: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(connection(format!(
            "private directory {} is redirected or not a directory",
            path.display()
        )));
    }
    Ok(())
}

pub(super) fn validate_private_regular_file(path: &Path) -> StorageResult<u64> {
    astrid_core::platform_fs::verify_no_redirects(path).map_err(|error| {
        connection(format!("validate private path {}: {error}", path.display()))
    })?;
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| connection(format!("inspect private file {}: {error}", path.display())))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(connection(format!(
            "private file {} is redirected or not a regular file",
            path.display()
        )));
    }
    astrid_core::platform_fs::validate_private_file(path).map_err(|error| {
        connection(format!("validate private file {}: {error}", path.display()))
    })?;
    Ok(metadata.len())
}

pub(super) fn create_private_file(path: &Path) -> StorageResult<File> {
    let parent = path
        .parent()
        .ok_or_else(|| connection(format!("private file {} has no parent", path.display())))?;
    ensure_private_directory(parent)?;
    let mut options = OpenOptions::new();
    options.create_new(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let file = options
        .open(path)
        .map_err(|error| connection(format!("create private file {}: {error}", path.display())))?;
    astrid_core::platform_fs::restrict_private_file(path).map_err(|error| {
        connection(format!("restrict private file {}: {error}", path.display()))
    })?;
    validate_private_regular_file(path)?;
    Ok(file)
}

pub(super) fn open_private_file(path: &Path) -> StorageResult<File> {
    validate_private_regular_file(path)?;
    OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|error| connection(format!("open private file {}: {error}", path.display())))
}

pub(super) fn open_private_file_rw(path: &Path) -> StorageResult<File> {
    validate_private_regular_file(path)?;
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|error| {
            connection(format!(
                "open private file for update {}: {error}",
                path.display()
            ))
        })
}

pub(super) fn atomic_write(path: &Path, bytes: &[u8]) -> StorageResult<()> {
    let parent = path
        .parent()
        .ok_or_else(|| connection(format!("path {} has no parent", path.display())))?;
    ensure_private_directory(parent)?;

    #[cfg(windows)]
    {
        astrid_core::platform_fs::atomic_write_private_file(path, bytes).map_err(|error| {
            connection(format!(
                "atomically write private file {}: {error}",
                path.display()
            ))
        })
    }

    #[cfg(not(windows))]
    {
        let temporary = temporary_path(path);
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary).map_err(|error| {
            connection(format!(
                "open temporary state file {}: {error}",
                temporary.display()
            ))
        })?;
        let result = (|| {
            file.write_all(bytes).map_err(|error| {
                connection(format!(
                    "write temporary state file {}: {error}",
                    temporary.display()
                ))
            })?;
            file.sync_all().map_err(|error| {
                connection(format!(
                    "flush temporary state file {}: {error}",
                    temporary.display()
                ))
            })?;
            std::fs::rename(&temporary, path).map_err(|error| {
                connection(format!(
                    "publish state file {} as {}: {error}",
                    temporary.display(),
                    path.display()
                ))
            })?;
            sync_directory(parent)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        result
    }
}

pub(super) fn quarantine_directory(path: &Path, classification: &str) -> StorageResult<PathBuf> {
    let parent = path
        .parent()
        .ok_or_else(|| connection(format!("path {} has no parent directory", path.display())))?;
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| connection(format!("path {} is not valid UTF-8", path.display())))?;
    let mut suffix = 0_u64;
    let destination = loop {
        let candidate = parent.join(format!("{name}.{classification}.{suffix}"));
        if !candidate.exists() {
            break candidate;
        }
        suffix = suffix
            .checked_add(1)
            .ok_or_else(|| connection("too many quarantined directories".to_owned()))?;
    };
    std::fs::rename(path, &destination).map_err(|error| {
        connection(format!(
            "quarantine directory {} as {}: {error}",
            path.display(),
            destination.display()
        ))
    })?;
    sync_directory(parent)?;
    Ok(destination)
}

pub(super) fn sync_directory(path: &Path) -> StorageResult<()> {
    #[cfg(unix)]
    {
        File::open(path)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| connection(format!("flush directory {}: {error}", path.display())))
    }

    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

#[cfg(not(windows))]
fn temporary_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map_or_else(|| "state".into(), std::ffi::OsString::from);
    name.push(format!(".{}.tmp", uuid::Uuid::new_v4()));
    path.with_file_name(name)
}

fn connection(message: String) -> StorageError {
    StorageError::Connection(message)
}
