//! Digest-bound retirement of admitted legacy component trees.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use super::SourceIdentity;
use super::fs_hooks::run_test_retire_leaf_hook;
#[cfg(test)]
use super::host_fs::snapshot_path;
use super::host_fs::{
    active_mountpoint, device_id, snapshot_owner_controlled_path, sync_directory,
};

#[derive(Clone, Copy)]
enum RetirementAccess {
    #[cfg(test)]
    Private,
    OwnerControlled,
}

#[cfg(test)]
pub(super) fn retire_tree(
    path: &Path,
    expected: &SourceIdentity,
    protected: &[PathBuf],
) -> io::Result<()> {
    retire_tree_with_access(path, expected, protected, RetirementAccess::Private)
}

pub(super) fn retire_owner_controlled_tree(
    path: &Path,
    expected: &SourceIdentity,
    protected: &[PathBuf],
) -> io::Result<()> {
    retire_tree_with_access(path, expected, protected, RetirementAccess::OwnerControlled)
}

fn retire_tree_with_access(
    path: &Path,
    expected: &SourceIdentity,
    protected: &[PathBuf],
    access: RetirementAccess,
) -> io::Result<()> {
    let actual = snapshot_with_access(path, access)?;
    if !actual.present {
        // A prior post-ledger attempt completed its unlink before a crash.
        // Absence is the idempotent terminal state regardless of whether the
        // historical source identity was present.
        return Ok(());
    }
    if &actual != expected {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "legacy source changed before retirement: {}",
                path.display()
            ),
        ));
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "legacy retirement root is not a directory: {}",
                path.display()
            ),
        ));
    }
    if active_mountpoint(path)? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("legacy source is an active mount: {}", path.display()),
        ));
    }
    let device = device_id(&metadata);
    for entry in fs::read_dir(path).map_err(io::Error::other)? {
        let child = entry.map_err(io::Error::other)?.path();
        if protected.iter().any(|candidate| candidate == &child) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "legacy component source reappeared during ordinary retirement: {}",
                    child.display()
                ),
            ));
        }
        let child_meta = fs::symlink_metadata(&child).map_err(io::Error::other)?;
        if child_meta.file_type().is_symlink() || (!child_meta.is_file() && !child_meta.is_dir()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "legacy source contains redirect or special entry: {}",
                    child.display()
                ),
            ));
        }
        if active_mountpoint(&child)? || device_id(&child_meta) != device {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "legacy source crosses a mount or device boundary: {}",
                    child.display()
                ),
            ));
        }
        if child_meta.is_dir() {
            let child_snapshot = snapshot_with_access(&child, access)?;
            retire_tree_with_access(&child, &child_snapshot, protected, access)?;
        } else {
            astrid_core::platform_fs::verify_no_redirects(&child)?;
            let leaf_snapshot = snapshot_with_access(&child, access)?;
            if leaf_snapshot.entries != 1 || leaf_snapshot.bytes != child_meta.len() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!(
                        "legacy source changed before retirement: {}",
                        child.display()
                    ),
                ));
            }
            retire_leaf(&child, child_meta.len(), &leaf_snapshot, access)?;
        }
    }
    sync_directory(path)?;
    fs::remove_dir(path).map_err(io::Error::other)
}

fn retire_leaf(
    child: &Path,
    expected_len: u64,
    leaf_snapshot: &SourceIdentity,
    access: RetirementAccess,
) -> io::Result<()> {
    run_test_retire_leaf_hook(child);
    let replacement_meta = fs::symlink_metadata(child).map_err(io::Error::other)?;
    if replacement_meta.file_type().is_symlink()
        || (!replacement_meta.is_file() && !replacement_meta.is_dir())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "legacy source contains redirect or special entry: {}",
                child.display()
            ),
        ));
    }
    if replacement_meta.len() != expected_len
        || snapshot_with_access(child, access)? != *leaf_snapshot
    {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "legacy source changed before retirement: {}",
                child.display()
            ),
        ));
    }
    fs::remove_file(child).map_err(io::Error::other)
}

fn snapshot_with_access(path: &Path, access: RetirementAccess) -> io::Result<SourceIdentity> {
    match access {
        #[cfg(test)]
        RetirementAccess::Private => snapshot_path(path),
        RetirementAccess::OwnerControlled => snapshot_owner_controlled_path(path),
    }
}
