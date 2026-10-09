//! No-follow retirement of the released directory-backed state tree.

#[cfg(unix)]
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

fn delete_tree(
    path: &Path,
    root_device: u64,
    preserve_root_finder_metadata: bool,
    before_runtime_run_removal: &mut impl FnMut(&Path) -> io::Result<()>,
) -> io::Result<()> {
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
        if preserve_root_finder_metadata && entry.file_name() == std::ffi::OsStr::new(".DS_Store") {
            if !child_metadata.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "runtime directory Finder metadata is not a regular file: {}",
                        child.display()
                    ),
                ));
            }
            continue;
        }
        if child_metadata.is_dir() {
            delete_tree(&child, root_device, false, before_runtime_run_removal)?;
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
    if preserve_root_finder_metadata {
        before_runtime_run_removal(path)?;
        remove_runtime_run_directory(path)
    } else {
        std::fs::remove_dir(path)
    }
}

fn remove_runtime_run_directory(path: &Path) -> io::Result<()> {
    match std::fs::remove_dir(path) {
        Ok(()) => Ok(()),
        Err(error)
            if error.kind() == io::ErrorKind::DirectoryNotEmpty
                && contains_only_regular_finder_metadata(path)? =>
        {
            // Finder may recreate this metadata after the walk. Leave it in
            // place: accepting it is safe, while validating then unlinking it
            // would introduce a replacement race.
            sync_directory(path)
        },
        Err(error) => Err(error),
    }
}

fn contains_only_regular_finder_metadata(path: &Path) -> io::Result<bool> {
    let mut entries = std::fs::read_dir(path)?;
    let Some(entry) = entries.next() else {
        return Ok(false);
    };
    let entry = entry?;
    if entry.file_name() != std::ffi::OsStr::new(".DS_Store") || entries.next().is_some() {
        return Ok(false);
    }
    let metadata = std::fs::symlink_metadata(entry.path())?;
    Ok(metadata.is_file() && !metadata.file_type().is_symlink())
}

pub(super) fn validate_legacy_surrealkv_entry(
    relative: &Path,
    is_directory: bool,
    is_file: bool,
) -> io::Result<()> {
    let components: Vec<_> = relative.components().collect();
    let valid = match components.as_slice() {
        // Finder may touch the database root or an admitted store directory.
        // Keep these regular files in the content inventory: this preserves
        // existing receipt identities rather than silently changing the hash
        // contract. Redirects and special entries are never metadata.
        [name] | [_, name] if name.as_os_str() == ".DS_Store" => is_file,
        [entry] if entry.as_os_str() == "LOCK" => is_file,
        [entry]
            if matches!(
                entry.as_os_str().to_str(),
                Some("manifest" | "wal" | "sstables" | "vlog" | "versioned_index")
            ) =>
        {
            is_directory
        },
        [directory, name] if directory.as_os_str() == "manifest" && is_file => {
            is_numbered_legacy_file(name.as_os_str(), b".manifest")
        },
        [directory, name] if directory.as_os_str() == "wal" && is_file => {
            is_numbered_legacy_file(name.as_os_str(), b".wal")
        },
        [directory, name] if directory.as_os_str() == "sstables" && is_file => {
            is_numbered_legacy_file(name.as_os_str(), b".sst")
        },
        [directory, name] if directory.as_os_str() == "vlog" && is_file => {
            is_numbered_legacy_file(name.as_os_str(), b".vlog")
        },
        [directory, name]
            if directory.as_os_str() == "versioned_index" && name.as_os_str() == "index.bpt" =>
        {
            is_file
        },
        _ => false,
    };
    if !valid {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "unexpected entry in released legacy SurrealKV source: {}",
                relative.display()
            ),
        ));
    }
    Ok(())
}

fn is_numbered_legacy_file(name: &std::ffi::OsStr, extension: &[u8]) -> bool {
    let bytes = name.as_encoded_bytes();
    bytes.split_at_checked(20).is_some_and(|(digits, suffix)| {
        digits.iter().all(u8::is_ascii_digit) && suffix == extension
    })
}

pub(super) fn retire_legacy_source_tree(path: &Path) -> io::Result<()> {
    retire_tree_root(path, false)
}

pub(super) fn retire_runtime_run_directory(path: &Path) -> io::Result<()> {
    retire_tree_root_with_hook(path, true, &mut |_| Ok(()))
}

fn retire_tree_root(path: &Path, preserve_root_finder_metadata: bool) -> io::Result<()> {
    retire_tree_root_with_hook(path, preserve_root_finder_metadata, &mut |_| Ok(()))
}

fn retire_tree_root_with_hook(
    path: &Path,
    preserve_root_finder_metadata: bool,
    before_runtime_run_removal: &mut impl FnMut(&Path) -> io::Result<()>,
) -> io::Result<()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
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

    // Validate the complete tree before removing anything. In particular,
    // `remove_dir_all` is intentionally not used: it can walk into a mount
    // boundary and its path-based recursion has no type check for special
    // entries. A failed validation leaves every legacy byte available for a
    // later operator repair or an idempotent restart.
    let root_device = legacy_tree_device(&metadata);
    validate_legacy_tree(path, root_device)?;
    delete_tree(
        path,
        root_device,
        preserve_root_finder_metadata,
        before_runtime_run_removal,
    )?;
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("legacy state source has no parent"))?;
    sync_directory(parent)
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

#[cfg(test)]
mod tests {
    use super::{
        remove_runtime_run_directory, retire_runtime_run_directory, retire_tree_root_with_hook,
    };

    #[test]
    fn runtime_run_retirement_keeps_regular_finder_metadata_without_failing_stop() {
        let temp = tempfile::tempdir().unwrap();
        let run = temp.path().join("run");
        std::fs::create_dir(&run).unwrap();
        std::fs::write(run.join("stale-socket"), b"stale transient").unwrap();
        std::fs::write(run.join(".DS_Store"), b"Finder metadata").unwrap();

        retire_runtime_run_directory(&run).unwrap();

        assert_eq!(
            std::fs::read(run.join(".DS_Store")).unwrap(),
            b"Finder metadata"
        );
        assert!(!run.join("stale-socket").exists());
    }

    #[test]
    fn runtime_run_retirement_keeps_finder_metadata_created_after_the_walk() {
        let temp = tempfile::tempdir().unwrap();
        let run = temp.path().join("run");
        std::fs::create_dir(&run).unwrap();
        std::fs::write(run.join("stale-socket"), b"stale transient").unwrap();

        retire_tree_root_with_hook(&run, true, &mut |path| {
            std::fs::write(path.join(".DS_Store"), b"late Finder metadata")
        })
        .unwrap();

        assert_eq!(
            std::fs::read(run.join(".DS_Store")).unwrap(),
            b"late Finder metadata"
        );
        assert!(!run.join("stale-socket").exists());
    }

    #[test]
    fn runtime_run_final_removal_rejects_nonmetadata_residue() {
        let temp = tempfile::tempdir().unwrap();
        let run = temp.path().join("run");
        std::fs::create_dir(&run).unwrap();
        std::fs::write(run.join("late-runtime-marker"), b"keep me").unwrap();

        let error = remove_runtime_run_directory(&run).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::DirectoryNotEmpty);
        assert_eq!(
            std::fs::read(run.join("late-runtime-marker")).unwrap(),
            b"keep me"
        );
    }

    #[cfg(unix)]
    #[test]
    fn runtime_run_final_removal_rejects_finder_symlink_impostor() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let run = temp.path().join("run");
        std::fs::create_dir(&run).unwrap();
        std::fs::write(temp.path().join("target"), b"outside").unwrap();
        symlink(temp.path().join("target"), run.join(".DS_Store")).unwrap();

        let error = remove_runtime_run_directory(&run).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::DirectoryNotEmpty);
        assert!(
            std::fs::symlink_metadata(run.join(".DS_Store"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            std::fs::read(temp.path().join("target")).unwrap(),
            b"outside"
        );
    }
}
