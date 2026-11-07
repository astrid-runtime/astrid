//! Read-only path checks, including reuse of an already captured DELETE owner.

use super::{
    FileIdentity, LockedPathComponent, OwnedHandle, TrustedPathGuard, file_identity,
    nearest_existing_ancestor, open_directory_identity, open_directory_identity_relative,
};
use std::fs::File;
use std::io;
use std::os::windows::fs::MetadataExt as _;
use std::os::windows::io::IntoRawHandle as _;
use std::path::{Component, Path, PathBuf};
use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

pub(in crate::platform_fs) fn verify_no_redirects(path: &Path) -> io::Result<()> {
    verify_using(path, TrustedPathGuard::capture)
}

pub(in crate::platform_fs::windows) fn verify_captured_no_redirects(
    path: &Path,
    root: &Path,
    file: &File,
) -> io::Result<()> {
    verify_using(path, |boundary| {
        TrustedPathGuard::capture_with_directory(boundary, Some((root, file)))
    })
}

pub(super) fn capture_component(
    parent: Option<&LockedPathComponent>,
    path: &Path,
    file: &File,
) -> io::Result<(OwnedHandle, FileIdentity)> {
    let (observation, _) = if let Some(parent) = parent {
        let name = path
            .file_name()
            .ok_or_else(|| io::Error::other("captured path has no name"))?;
        open_directory_identity_relative(parent.handle.0, name, false)?
    } else {
        open_directory_identity(path, true)?
    };
    // Only the independently captured object's full identity permits reusing
    // its handle. The observation shares DELETE; the retained owner still
    // denies deletion/rename. No ordinary path acquires this exception.
    if super::super::captured_directory::query_directory_identity(&observation)?
        != super::super::captured_directory::query_directory_identity(file)?
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "captured Windows directory no longer names the retained object",
        ));
    }
    let identity = file_identity(file)?;
    let handle = OwnedHandle(file.try_clone()?.into_raw_handle().cast());
    Ok((handle, identity))
}

fn verify_using(
    path: &Path,
    capture: impl FnOnce(&Path) -> io::Result<TrustedPathGuard>,
) -> io::Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "security-sensitive Windows path must be absolute without traversal: {}",
                path.display()
            ),
        ));
    }

    let mut current = PathBuf::new();
    let mut rooted = false;
    for component in path.components() {
        current.push(component.as_os_str());
        if matches!(component, Component::RootDir) {
            rooted = true;
        }
        if !rooted {
            continue;
        }
        let metadata = match std::fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "security-sensitive Windows path contains a reparse point: {}",
                    current.display()
                ),
            ));
        }
    }
    let guard_path = match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => path.to_path_buf(),
        Ok(_) => path
            .parent()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?
            .to_path_buf(),
        Err(error) if error.kind() == io::ErrorKind::NotFound => nearest_existing_ancestor(path)?,
        Err(error) => return Err(error),
    };
    capture(&guard_path)?.verify()
}
