//! Durable native namespace transitions shared by staging and migration.

#[cfg(windows)]
use super::PrivateDirectory;
use super::{StorageResult, connection};
#[cfg(unix)]
use std::fs::File;
use std::path::Path;

/// Rename an entry at the platform's durable namespace boundary.
///
/// Windows requests write-through for the rename and callers also retain their
/// explicit directory-structure fence. Unix keeps its existing parent sync.
pub(in crate::principal_state) fn rename_private_entry(
    source: &Path,
    destination: &Path,
) -> StorageResult<()> {
    astrid_core::platform_fs::rename_with_write_through(source, destination).map_err(|error| {
        connection(format!(
            "rename private entry {} as {}: {error}",
            source.display(),
            destination.display()
        ))
    })
}

pub(in crate::principal_state) fn sync_directory(path: &Path) -> StorageResult<()> {
    #[cfg(unix)]
    {
        File::open(path)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| connection(format!("flush directory {}: {error}", path.display())))
    }

    #[cfg(windows)]
    {
        PrivateDirectory::open(path)?.sync()
    }
    #[cfg(not(any(unix, windows)))]
    {
        Err(connection(format!(
            "directory flush unsupported on this target: {}",
            path.display()
        )))
    }
}
