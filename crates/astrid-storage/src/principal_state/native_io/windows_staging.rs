//! Windows staging flush cache and exclusive capability rename.

use super::{
    PrivateDirectoryIdentity, PrivateFileIdentity, connection, private_directory_file_identity,
    private_file_identity,
};
use crate::error::StorageResult;
use cap_std::fs::Dir;
use std::ffi::OsStr;
use std::path::Path;

pub(super) fn open_flush_for_ambient(
    path: &Path,
    directory: &Dir,
) -> StorageResult<astrid_core::platform_fs::directory_capability::DirectoryFlushCapability> {
    use std::os::windows::io::AsHandle as _;
    astrid_core::platform_fs::directory_capability::open_directory_flush(
        path,
        directory.as_handle(),
    )
    .map_err(|error| {
        connection(format!(
            "open directory flush capability {}: {error}",
            path.display()
        ))
    })
}

pub(super) fn child_flush(
    parent_flush: Option<&astrid_core::platform_fs::directory_capability::DirectoryFlushCapability>,
    parent: &Dir,
    name: &Path,
    child: &Dir,
) -> StorageResult<Option<astrid_core::platform_fs::directory_capability::DirectoryFlushCapability>>
{
    if parent_flush.is_none() {
        return Ok(None);
    }
    Ok(Some(open_flush_relative_for_child(
        parent,
        name.as_os_str(),
        child,
    )?))
}

pub(super) fn open_flush_relative_for_child(
    parent: &Dir,
    name: &OsStr,
    child: &Dir,
) -> StorageResult<astrid_core::platform_fs::directory_capability::DirectoryFlushCapability> {
    use std::os::windows::io::AsHandle as _;
    astrid_core::platform_fs::directory_capability::open_directory_flush_relative(
        parent.as_handle(),
        name,
        child.as_handle(),
    )
    .map_err(|error| {
        connection(format!(
            "open relative directory flush capability {}: {error}",
            name.to_string_lossy()
        ))
    })
}

pub(super) fn sync_windows(
    path: &Path,
    flush: Option<&astrid_core::platform_fs::directory_capability::DirectoryFlushCapability>,
) -> StorageResult<()> {
    let Some(flush) = flush else {
        return Err(connection(format!(
            "directory {} has no published flush authority",
            path.display()
        )));
    };
    flush
        .flush()
        .map_err(|error| connection(format!("flush directory {}: {error}", path.display())))
}

fn single_component<'a>(path: &'a Path, label: &str) -> StorageResult<&'a OsStr> {
    let mut components = path.components();
    let Some(std::path::Component::Normal(name)) = components.next() else {
        return Err(connection(format!(
            "{label} must be a single path component"
        )));
    };
    if components.next().is_some() || path.as_os_str() != name {
        return Err(connection(format!(
            "{label} must be a single path component"
        )));
    }
    astrid_core::platform_fs::directory_capability::validate_relative_component(name)
        .map_err(|error| connection(format!("{label} must be a single path component: {error}")))
}

/// Required source identity for exclusive Windows capability rename.
#[derive(Debug, Clone, Copy)]
pub(super) enum ExpectedRenameIdentity {
    File(PrivateFileIdentity),
    Directory(PrivateDirectoryIdentity),
}

pub(super) fn rename_no_replace_windows(
    source_directory: &Dir,
    source: &Path,
    destination_directory: &Dir,
    destination: &Path,
    expected: ExpectedRenameIdentity,
) -> StorageResult<()> {
    let source_name = single_component(source, "private rename source")?;
    let destination_name = single_component(destination, "private rename destination")?;

    let source_file = match &expected {
        ExpectedRenameIdentity::Directory(_) => {
            astrid_core::platform_fs::directory_capability::open_directory_child_for_exclusive_rename(
                source_directory,
                source_name,
            )
        }
        ExpectedRenameIdentity::File(_) => {
            astrid_core::platform_fs::directory_capability::open_file_child_for_exclusive_rename(
                source_directory,
                source_name,
            )
        }
    }
    .map_err(|error| {
        connection(format!(
            "open exclusive rename source {}: {error}",
            source.display()
        ))
    })?;

    match &expected {
        ExpectedRenameIdentity::File(expected) => {
            let actual = private_file_identity(&source_file)?;
            if actual != *expected {
                return Err(connection(format!(
                    "private source {} changed before exclusive rename",
                    source.display()
                )));
            }
        },
        ExpectedRenameIdentity::Directory(expected) => {
            let actual = private_directory_file_identity(&source_file)?;
            if actual != *expected {
                return Err(connection(format!(
                    "private directory source {} changed before exclusive rename",
                    source.display()
                )));
            }
        },
    }

    astrid_core::platform_fs::directory_capability::rename_handle_no_replace(
        &source_file,
        destination_directory,
        destination_name,
    )
    .map_err(|error| {
        connection(format!(
            "exclusive rename {} as {}: {error}",
            source.display(),
            destination.display()
        ))
    })
}
