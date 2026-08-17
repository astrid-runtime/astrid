//! No-follow inventory and retirement primitives for the layout barrier.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::path::Path;
use std::path::PathBuf;

use super::{MAX_BYTES, MAX_ENTRIES, SourceIdentity};

pub(super) fn add_source(
    sources: &mut BTreeMap<String, SourceIdentity>,
    name: String,
    path: impl AsRef<Path>,
) -> io::Result<()> {
    sources.insert(name, snapshot_path(path.as_ref())?);
    Ok(())
}

pub(super) fn retire_empty_directory(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "legacy source is not an empty regular directory: {}",
                path.display()
            ),
        ));
    }
    astrid_core::platform_fs::verify_no_redirects(path)?;
    fs::remove_dir(path).map_err(io::Error::other)?;
    sync_parent(path)
}

/// Check every alias-keyed child of the released `secrets/` root.  The
/// barrier passes `allow_empty_cleanup=false` while resuming a completed
/// ledger, so a deleted or renamed principal cannot leave a reappeared empty
/// directory that is silently swept on restart.
pub(super) fn ensure_legacy_secret_aliases(
    root: &Path,
    allow_empty_cleanup: bool,
) -> io::Result<()> {
    let metadata = match fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "legacy secrets root is not a regular directory: {}",
                root.display()
            ),
        ));
    }
    astrid_core::platform_fs::validate_private_directory(root)?;
    astrid_core::platform_fs::verify_no_redirects(root)?;
    let entries = fs::read_dir(root)
        .map_err(io::Error::other)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(io::Error::other)?;
    for entry in entries {
        if entry.file_name() == "__host__" {
            continue;
        }
        let path = entry.path();
        let snapshot = snapshot_path(&path)?;
        if snapshot.entries != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "legacy secret source remains after migration: {}",
                    path.display()
                ),
            ));
        }
        if allow_empty_cleanup {
            retire_empty_directory(&path)?;
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "legacy secret source reappeared after cut-over: {}",
                    path.display()
                ),
            ));
        }
    }
    Ok(())
}

/// A completed v2 ledger must be tied either to the explicit fresh-home
/// disposition or to the durable layout cutover intent and receipt.  This
/// check runs before stores open, so a canonical but invented component list
/// cannot authorize the legacy layout finalizer.
pub(super) fn require_layout_provenance(migrations: &Path, fresh_layout: bool) -> io::Result<()> {
    if fresh_layout {
        return Ok(());
    }
    for name in ["layout-v1-to-v2.intent", "layout-v1-to-v2.complete"] {
        let path = migrations.join(name);
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "layout-two ledger has no durable cutover record: {}",
                        path.display()
                    ),
                )
            } else {
                error
            }
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "layout cutover record is not a regular file: {}",
                    path.display()
                ),
            ));
        }
        validate_private_entry(&path, &metadata)?;
        astrid_core::platform_fs::verify_no_redirects(&path)?;
        if metadata.len() == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("layout cutover record is empty: {}", path.display()),
            ));
        }
    }
    Ok(())
}

pub(super) fn retire_tree(
    path: &Path,
    expected: &SourceIdentity,
    protected: &[PathBuf],
) -> io::Result<()> {
    let actual = snapshot_path(path)?;
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
            let child_snapshot = snapshot_path(&child)?;
            retire_tree(&child, &child_snapshot, protected)?;
        } else {
            astrid_core::platform_fs::verify_no_redirects(&child)?;
            let leaf_snapshot = snapshot_path(&child)?;
            if leaf_snapshot.entries != 1 || leaf_snapshot.bytes != child_meta.len() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!(
                        "legacy source changed before retirement: {}",
                        child.display()
                    ),
                ));
            }
            fs::remove_file(&child).map_err(io::Error::other)?;
        }
    }
    sync_directory(path)?;
    fs::remove_dir(path).map_err(io::Error::other)
}

fn device_id(metadata: &fs::Metadata) -> u64 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        metadata.dev()
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        0
    }
}

pub(super) fn snapshot_path(path: &Path) -> io::Result<SourceIdentity> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(SourceIdentity::absent());
        },
        Err(error) => return Err(error),
    };
    astrid_core::platform_fs::verify_no_redirects(path)?;
    validate_private_entry(path, &metadata)?;
    if active_mountpoint(path)? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("legacy source is an active mount: {}", path.display()),
        ));
    }
    let device = device_id(&metadata);
    let mut hasher = blake3::Hasher::new_derive_key("astrid layout component source v1");
    let mut identity = SourceIdentity {
        digest: String::new(),
        entries: 0,
        bytes: 0,
        present: true,
    };
    if metadata.is_file() {
        // A top-level regular file is itself one source entry.  Directory
        // snapshots count children in `snapshot_dir`; keeping the same
        // cardinality here lets retirement bind a single-file source to the
        // exact preflight manifest as well.
        identity.entries = 1;
        read_regular_file(path, &mut hasher, &mut identity)?;
    } else if metadata.is_dir() {
        snapshot_dir(path, path, device, &mut hasher, &mut identity)?;
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("legacy source contains a special entry: {}", path.display()),
        ));
    }
    identity.digest = hasher.finalize().to_hex().to_string();
    Ok(identity)
}

/// Validate one regular-file source using the same no-follow, private,
/// same-device, and mount checks as recursive snapshots.  Distro lock files
/// keep their component-owned digest format, so they use this structural
/// check instead of the generic tree hash.
pub(super) fn validate_source_path(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("legacy source is not a regular file: {}", path.display()),
        ));
    }
    astrid_core::platform_fs::verify_no_redirects(path)?;
    validate_private_entry(path, &metadata)?;
    if active_mountpoint(path)? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("legacy source is an active mount: {}", path.display()),
        ));
    }
    if let Some(parent) = path.parent()
        && let Ok(parent_metadata) = fs::symlink_metadata(parent)
        && device_id(&parent_metadata) != device_id(&metadata)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "legacy source crosses a device boundary: {}",
                path.display()
            ),
        ));
    }
    Ok(())
}

fn snapshot_dir(
    root: &Path,
    dir: &Path,
    device: u64,
    hasher: &mut blake3::Hasher,
    identity: &mut SourceIdentity,
) -> io::Result<()> {
    let mut children = fs::read_dir(dir)
        .map_err(io::Error::other)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(io::Error::other)?;
    children.sort_by_key(std::fs::DirEntry::file_name);
    for entry in children {
        let path = entry.path();
        let relative = path.strip_prefix(root).map_err(io::Error::other)?;
        let metadata = fs::symlink_metadata(&path).map_err(io::Error::other)?;
        if metadata.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("legacy source contains redirect: {}", path.display()),
            ));
        }
        validate_private_entry(&path, &metadata)?;
        if device_id(&metadata) != device {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "legacy source crosses a device boundary: {}",
                    path.display()
                ),
            ));
        }
        if active_mountpoint(&path)? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("legacy source is an active mount: {}", path.display()),
            ));
        }
        hasher.update(&(relative.as_os_str().as_encoded_bytes().len() as u64).to_le_bytes());
        hasher.update(relative.as_os_str().as_encoded_bytes());
        identity.entries = identity
            .entries
            .checked_add(1)
            .ok_or_else(|| io::Error::other("legacy source entry limit exceeded"))?;
        if identity.entries > MAX_ENTRIES {
            return Err(io::Error::other("legacy source entry limit exceeded"));
        }
        if metadata.is_dir() {
            hasher.update(b"dir");
            snapshot_dir(root, &path, device, hasher, identity)?;
        } else if metadata.is_file() {
            hasher.update(b"file");
            read_regular_file(&path, hasher, identity)?;
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("legacy source contains a special entry: {}", path.display()),
            ));
        }
    }
    Ok(())
}

fn read_regular_file(
    path: &Path,
    hasher: &mut blake3::Hasher,
    identity: &mut SourceIdentity,
) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC | nix::libc::O_NONBLOCK);
    }
    let mut file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("legacy source changed type: {}", path.display()),
        ));
    }
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        identity.bytes = identity
            .bytes
            .checked_add(read as u64)
            .ok_or_else(|| io::Error::other("legacy source byte limit exceeded"))?;
        if identity.bytes > MAX_BYTES {
            return Err(io::Error::other("legacy source byte limit exceeded"));
        }
        hasher.update(&buffer[..read]);
    }
    Ok(())
}

fn validate_private_entry(path: &Path, metadata: &fs::Metadata) -> io::Result<()> {
    if metadata.is_dir() {
        astrid_core::platform_fs::validate_private_directory(path)
    } else if metadata.is_file() {
        astrid_core::platform_fs::validate_private_file(path)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("legacy source contains a special entry: {}", path.display()),
        ))
    }
}

#[cfg_attr(not(target_os = "linux"), allow(clippy::unnecessary_wraps))]
fn active_mountpoint(path: &Path) -> io::Result<bool> {
    #[cfg(target_os = "linux")]
    {
        let canonical = fs::canonicalize(path)?;
        let mountinfo = fs::read_to_string("/proc/self/mountinfo")?;
        return Ok(mountinfo.lines().any(|line| {
            line.split_whitespace()
                .nth(4)
                .and_then(|raw| decode_mountinfo_path(raw))
                .is_some_and(|mount| mount == canonical)
        }));
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        Ok(false)
    }
}

#[cfg(target_os = "linux")]
fn decode_mountinfo_path(raw: &str) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStringExt;
    let mut decoded = Vec::with_capacity(raw.len());
    let bytes = raw.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' && index + 3 < bytes.len() {
            let value =
                u8::from_str_radix(std::str::from_utf8(&bytes[index + 1..index + 4]).ok()?, 8)
                    .ok()?;
            decoded.push(value);
            index += 4;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    Some(PathBuf::from(std::ffi::OsString::from_vec(decoded)))
}

pub(super) fn path_exists(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

pub(super) fn read_bounded_file(path: &Path, max: u64) -> io::Result<Option<Vec<u8>>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("legacy source is not a regular file: {}", path.display()),
        ));
    }
    astrid_core::platform_fs::validate_private_file(path)?;
    if metadata.len() > max {
        return Err(io::Error::other(format!(
            "legacy source exceeds migration cap: {}",
            path.display()
        )));
    }
    astrid_core::platform_fs::verify_no_redirects(path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC);
    }
    let mut file = options.open(path)?;
    let opened = file.metadata()?;
    if !opened.is_file() || opened.len() != metadata.len() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("legacy source changed while opening: {}", path.display()),
        ));
    }
    let capacity = usize::try_from(opened.len())
        .map_err(|_| io::Error::other("legacy source is too large for this platform"))?;
    let mut bytes = Vec::with_capacity(capacity);
    file.read_to_end(&mut bytes)?;
    Ok(Some(bytes))
}

pub(super) fn sync_parent(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        sync_directory(parent)?;
    }
    Ok(())
}

pub(super) fn sync_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(path)?.sync_all()?;
    }
    Ok(())
}

pub(super) fn storage_io(error: impl std::fmt::Display) -> io::Error {
    io::Error::other(error.to_string())
}
