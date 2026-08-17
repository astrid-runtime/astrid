//! No-follow retirement of the released directory-backed state tree.

use std::fs::File;
use std::io;
use std::path::Path;
#[cfg(target_os = "linux")]
use std::path::PathBuf;

pub(super) fn validate_legacy_retirement_candidate(path: &Path) -> io::Result<()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "legacy state source is redirected or not a directory: {}",
                path.display()
            ),
        ));
    }
    validate_legacy_tree(path, legacy_tree_device(&metadata))
}

#[cfg(unix)]
pub(super) fn legacy_tree_device(metadata: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt as _;

    metadata.dev()
}

#[cfg(not(unix))]
pub(super) fn legacy_tree_device(_metadata: &std::fs::Metadata) -> u64 {
    0
}

pub(super) fn validate_legacy_tree(path: &Path, root_device: u64) -> io::Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("legacy state source is redirected: {}", path.display()),
        ));
    }
    if !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("legacy state source is not a directory: {}", path.display()),
        ));
    }
    crate::platform_fs::verify_no_redirects(path)?;
    ensure_legacy_tree_boundary(path, root_device, &metadata)?;

    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let child = entry.path();
        let child_metadata = std::fs::symlink_metadata(&child)?;
        if child_metadata.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "legacy state source contains a redirect: {}",
                    child.display()
                ),
            ));
        }
        ensure_legacy_tree_boundary(&child, root_device, &child_metadata)?;
        if child_metadata.is_dir() {
            validate_legacy_tree(&child, root_device)?;
        } else if child_metadata.is_file() {
            // Opening only after the no-follow validation ensures a replaced
            // symlink is rejected rather than read or removed through it.
            crate::platform_fs::verify_no_redirects(&child)?;
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "legacy state source contains a special file: {}",
                    child.display()
                ),
            ));
        }
    }
    Ok(())
}

pub(super) fn delete_legacy_tree(path: &Path, root_device: u64) -> io::Result<()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("legacy state source changed type: {}", path.display()),
        ));
    }
    crate::platform_fs::verify_no_redirects(path)?;
    ensure_legacy_tree_boundary(path, root_device, &metadata)?;

    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let child = entry.path();
        let child_metadata = std::fs::symlink_metadata(&child)?;
        if child_metadata.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "legacy state source contains a redirect: {}",
                    child.display()
                ),
            ));
        }
        ensure_legacy_tree_boundary(&child, root_device, &child_metadata)?;
        if child_metadata.is_dir() {
            delete_legacy_tree(&child, root_device)?;
        } else if child_metadata.is_file() {
            crate::platform_fs::verify_no_redirects(&child)?;
            std::fs::remove_file(&child)?;
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "legacy state source contains a special file: {}",
                    child.display()
                ),
            ));
        }
    }

    // Flush the directory's child removals before removing the directory
    // entry itself. The caller also flushes the containing `var/` directory.
    sync_directory(path)?;
    std::fs::remove_dir(path)
}

fn ensure_legacy_tree_boundary(
    path: &Path,
    root_device: u64,
    metadata: &std::fs::Metadata,
) -> io::Result<()> {
    #[cfg(unix)]
    {
        if legacy_tree_device(metadata) != root_device {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "legacy state source crosses a filesystem boundary: {}",
                    path.display()
                ),
            ));
        }
    }
    #[cfg(not(unix))]
    let _ = (root_device, metadata);
    if is_active_mountpoint(path)? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("legacy state source is an active mount: {}", path.display()),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(super) fn is_active_mountpoint(path: &Path) -> io::Result<bool> {
    let canonical = std::fs::canonicalize(path)?;
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo")?;
    Ok(mountinfo.lines().any(|line| {
        let Some(mountpoint) = line.split_whitespace().nth(4) else {
            return false;
        };
        decode_mountinfo_path(mountpoint).is_some_and(|mountpoint| mountpoint == canonical)
    }))
}

#[cfg(target_os = "linux")]
fn decode_mountinfo_path(encoded: &str) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStringExt as _;

    let bytes = encoded.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            let digit_start = index.checked_add(1)?;
            let end = digit_start.checked_add(3)?;
            let digits = bytes.get(digit_start..end)?;
            if !digits.iter().all(|digit| (b'0'..=b'7').contains(digit)) {
                return None;
            }
            let value = digits.iter().try_fold(0_u8, |value, digit| {
                value
                    .checked_mul(8)?
                    .checked_add((*digit).checked_sub(b'0')?)
            })?;
            decoded.push(value);
            index = end;
        } else {
            decoded.push(bytes[index]);
            index = index.checked_add(1)?;
        }
    }
    Some(PathBuf::from(std::ffi::OsString::from_vec(decoded)))
}

#[cfg(all(unix, not(target_os = "linux")))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "the platform-independent mount-boundary helper shares the Unix fallible signature"
)]
pub(super) fn is_active_mountpoint(_path: &Path) -> io::Result<bool> {
    // Device identity below catches ordinary mount points on Unix hosts. The
    // Linux mount table additionally catches bind mounts that reuse a device.
    Ok(false)
}

#[cfg(not(unix))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "the platform-independent mount-boundary helper shares the Unix fallible signature"
)]
pub(super) fn is_active_mountpoint(_path: &Path) -> io::Result<bool> {
    // Windows junctions and volume mount points are rejected by
    // `verify_no_redirects`; no separate mount table is needed here.
    Ok(false)
}

#[cfg(unix)]
pub(super) fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(not(unix))]
// Keep the fallible contract shared with Unix callers. These platforms do not
// expose a portable directory-fsync operation, so retirement ends after the
// successful directory removal.
#[allow(clippy::unnecessary_wraps)]
pub(super) fn sync_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}
