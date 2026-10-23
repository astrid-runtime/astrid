//! The single fail-closed boundary for retiring an Astrid runtime projection.

use std::fs::File;
use std::io;
use std::path::Path;

const CANONICAL_VOLUME: &str = "astrid.volume";

/// Validate the complete projection before deleting any entry.
///
/// The canonical media file is the only survivor. Full descendant directory
/// barriers are preserved for legacy projection packing and migration.
///
/// # Errors
///
/// Returns an I/O error for redirects, special entries or failed removal or
/// synchronization. A preflight error leaves the complete tree untouched.
pub fn retire_projection_root(root: &Path) -> io::Result<()> {
    retire_projection_root_with_barrier(root, crate::dirs::retire_legacy_source_tree, |path| {
        File::open(path)?.sync_all()
    })
}

/// Retire a projection whose bytes and RETIRING inventory are already durable.
///
/// Performs the same complete preflight as [`retire_projection_root`], then
/// synchronizes surviving containing directories rather than each removed
/// descendant. The caller must retain durable inventory custody until success.
///
/// # Errors
///
/// Returns an I/O error for redirects, special entries, failed removal or
/// synchronization. A mid-retire error leaves the volume and retirement
/// inventory as recovery authority; it must not acknowledge completion.
pub fn retire_packed_projection_root(root: &Path) -> io::Result<()> {
    retire_projection_root_with_barrier(
        root,
        super::dirs_layout::retire_packed_projection_tree,
        |path| File::open(path)?.sync_all(),
    )
}

fn retire_projection_root_with_barrier(
    root: &Path,
    mut retire_tree: impl FnMut(&Path) -> io::Result<()>,
    mut final_barrier: impl FnMut(&Path) -> io::Result<()>,
) -> io::Result<()> {
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
            retire_tree(&path)?;
        } else {
            std::fs::remove_file(&path)?;
        }
    }
    final_barrier(root)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn final_projection_barrier_failure_cannot_acknowledge_retirement() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp.path().join("var/agents/profile")).unwrap();
        std::fs::write(temp.path().join("var/agents/profile/data"), b"packed").unwrap();
        std::fs::write(temp.path().join(CANONICAL_VOLUME), b"authority").unwrap();
        let mut barriers = 0;
        let error = retire_projection_root_with_barrier(
            temp.path(),
            super::super::dirs_layout::retire_packed_projection_tree,
            |_| {
                barriers += 1;
                Err(io::Error::other(
                    "injected final projection barrier failure",
                ))
            },
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("injected final projection barrier failure")
        );
        assert_eq!(barriers, 1);
        assert_eq!(
            std::fs::read(temp.path().join(CANONICAL_VOLUME)).unwrap(),
            b"authority"
        );
        retire_projection_root_with_barrier(
            temp.path(),
            super::super::dirs_layout::retire_packed_projection_tree,
            |path| {
                barriers += 1;
                File::open(path)?.sync_all()
            },
        )
        .unwrap();
        assert_eq!(barriers, 2);
        assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 1);
    }
}
