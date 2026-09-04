//! The single fail-closed boundary for retiring an Astrid runtime projection.

use std::fs::File;
use std::io;
use std::path::Path;

const CANONICAL_VOLUME: &str = "astrid.volume";

/// Validate the complete projection before deleting any entry.
///
/// Every caller must use this function so a regular file is never removed
/// before a later root special or nested redirect can stop retirement. The
/// canonical media file is the only survivor.
///
/// # Errors
///
/// Returns an I/O error when a projection entry is redirected, is neither a
/// regular file nor a real directory, or cannot be removed. A preflight error
/// leaves the tree untouched; a mid-retire error leaves the durable volume as
/// the recovery authority.
pub fn retire_projection_root(root: &Path) -> io::Result<()> {
    preflight_projection_entry(root)?;
    let mut entries = std::fs::read_dir(root)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        if entry.file_name() == std::ffi::OsStr::new(CANONICAL_VOLUME) {
            continue;
        }
        let metadata = std::fs::symlink_metadata(&path)?;
        if metadata.is_dir() {
            crate::dirs::retire_legacy_source_tree(&path)?;
        } else {
            std::fs::remove_file(&path)?;
        }
    }
    File::open(root)?.sync_all()?;
    Ok(())
}

fn preflight_projection_entry(path: &Path) -> io::Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("runtime projection is redirected: {}", path.display()),
        ));
    }
    if metadata.is_dir() {
        for entry in std::fs::read_dir(path)? {
            let child = entry?.path();
            preflight_projection_entry(&child)?;
        }
        return Ok(());
    }
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "runtime projection contains a special entry: {}",
                path.display()
            ),
        ));
    }
    Ok(())
}
