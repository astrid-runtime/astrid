//! Secure cleanup for disposable per-process principal scratch.
//!
//! Runtime scratch is deliberately separate from the durable Astrid home
//! layout. It is cleared during boot before any capsule runtime is admitted;
//! unlike durable state, no bytes in this subtree carry a persistence
//! guarantee. The cleanup is fail-closed: redirects, mount boundaries, and
//! special files reject the complete operation before any child is removed.

use std::io;
use std::path::Path;
#[cfg(target_os = "linux")]
use std::path::PathBuf;

/// Clear all stale children beneath `run/principals`, retaining its root.
pub(crate) fn clear_runtime_scratch(kind: &'static str, path: &Path) -> io::Result<()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{kind} is redirected or not a directory: {}",
                path.display()
            ),
        ));
    }

    let root_device = tree_device(&metadata);
    validate_tree(kind, path, root_device)?;

    // Validation above guarantees that the recursive deletes below see only
    // regular files and directories. Re-check each child immediately before
    // removal so a replacement symlink is rejected rather than followed.
    for entry in std::fs::read_dir(path)? {
        let child = entry?.path();
        let child_metadata = std::fs::symlink_metadata(&child)?;
        ensure_tree_boundary(kind, &child, root_device, &child_metadata)?;
        if child_metadata.is_dir() {
            delete_tree(kind, &child, root_device)?;
        } else if child_metadata.is_file() {
            crate::platform_fs::verify_no_redirects(&child)?;
            std::fs::remove_file(&child)?;
        } else {
            return Err(invalid_entry(kind, &child));
        }
    }
    sync_directory(path)
}

// Runtime-scratch accessors remain adjacent to their validated remover.
impl crate::dirs::AstridHome {
    /// Clear stale runtime scratch from a prior daemon process.
    ///
    /// Only the disposable `run/principals/` subtree is touched. The complete
    /// tree is validated without following redirects before anything is
    /// removed; symlinks, mount boundaries, and special entries fail closed.
    /// Each subtree root is retained. Principal scratch is recreated on
    /// demand by the capsule runtime; stale process storage children are
    /// reclaimed before a new daemon admits runtimes.
    ///
    /// # Errors
    ///
    /// Returns an error and leaves the subtree untouched when a redirect,
    /// mount boundary, or special entry is present.
    pub fn clear_runtime_principal_scratch(&self) -> io::Result<()> {
        clear_runtime_scratch(
            "runtime principal scratch",
            &self.run_dir().join("principals"),
        )
    }
}

fn validate_tree(kind: &'static str, path: &Path, root_device: u64) -> io::Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{kind} is redirected: {}", path.display()),
        ));
    }
    if !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{kind} is not a directory: {}", path.display()),
        ));
    }
    crate::platform_fs::verify_no_redirects(path)?;
    ensure_tree_boundary(kind, path, root_device, &metadata)?;

    for entry in std::fs::read_dir(path)? {
        let child = entry?.path();
        let child_metadata = std::fs::symlink_metadata(&child)?;
        if child_metadata.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{kind} contains a redirect: {}", child.display()),
            ));
        }
        ensure_tree_boundary(kind, &child, root_device, &child_metadata)?;
        if child_metadata.is_dir() {
            validate_tree(kind, &child, root_device)?;
        } else if child_metadata.is_file() {
            // Opening only after no-follow validation ensures a replaced
            // symlink is rejected rather than read or removed through it.
            crate::platform_fs::verify_no_redirects(&child)?;
        } else {
            return Err(invalid_entry(kind, &child));
        }
    }
    Ok(())
}

fn delete_tree(kind: &'static str, path: &Path, root_device: u64) -> io::Result<()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{kind} changed type: {}", path.display()),
        ));
    }
    crate::platform_fs::verify_no_redirects(path)?;
    ensure_tree_boundary(kind, path, root_device, &metadata)?;

    for entry in std::fs::read_dir(path)? {
        let child = entry?.path();
        let child_metadata = std::fs::symlink_metadata(&child)?;
        if child_metadata.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{kind} contains a redirect: {}", child.display()),
            ));
        }
        ensure_tree_boundary(kind, &child, root_device, &child_metadata)?;
        if child_metadata.is_dir() {
            delete_tree(kind, &child, root_device)?;
        } else if child_metadata.is_file() {
            crate::platform_fs::verify_no_redirects(&child)?;
            std::fs::remove_file(&child)?;
        } else {
            return Err(invalid_entry(kind, &child));
        }
    }

    sync_directory(path)?;
    std::fs::remove_dir(path)
}

fn invalid_entry(kind: &str, path: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("{kind} contains a special file: {}", path.display()),
    )
}

fn ensure_tree_boundary(
    kind: &'static str,
    path: &Path,
    root_device: u64,
    metadata: &std::fs::Metadata,
) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        if metadata.dev() != root_device {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{kind} crosses a filesystem boundary: {}", path.display()),
            ));
        }
    }
    #[cfg(not(unix))]
    let _ = (root_device, metadata);
    if is_active_mountpoint(path)? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{kind} is an active mount: {}", path.display()),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn tree_device(metadata: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt as _;

    metadata.dev()
}

#[cfg(not(unix))]
fn tree_device(_metadata: &std::fs::Metadata) -> u64 {
    0
}

#[cfg(target_os = "linux")]
fn is_active_mountpoint(path: &Path) -> io::Result<bool> {
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
    reason = "platform-independent mount-boundary helper shares Linux fallible signature"
)]
fn is_active_mountpoint(_path: &Path) -> io::Result<bool> {
    // Device identity above catches ordinary mount points on Unix hosts.
    Ok(false)
}

#[cfg(not(unix))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "platform-independent mount-boundary helper shares Linux fallible signature"
)]
fn is_active_mountpoint(_path: &Path) -> io::Result<bool> {
    // Windows junctions and volume mount points are rejected by
    // `verify_no_redirects`; no separate mount table is needed here.
    Ok(false)
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> io::Result<()> {
    std::fs::File::open(path)?.sync_all()
}

#[cfg(not(unix))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "non-Unix has no portable directory fsync operation"
)]
fn sync_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn runtime_scratch_rejects_an_active_mount_boundary() {
        let mountpoint = Path::new("/proc");
        if !is_active_mountpoint(mountpoint).expect("read Linux mount table") {
            // Minimal containers may not mount procfs. Do not synthesize a
            // mount without CAP_SYS_ADMIN; the other rejection tests remain.
            return;
        }

        let error = clear_runtime_scratch("process storage scratch", mountpoint).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("active mount"), "{error}");
    }
}
