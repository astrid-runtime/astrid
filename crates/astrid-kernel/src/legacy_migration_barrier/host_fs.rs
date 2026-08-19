//! No-follow inventory and retirement primitives for the layout barrier.

use std::collections::BTreeMap;
#[cfg(unix)]
use std::fs::File;
use std::fs::{self, OpenOptions};
use std::io::{self, Read};
use std::path::Path;
use std::path::PathBuf;

use super::{AstridHome, MAX_BYTES, MAX_ENTRIES, PrincipalId, PrincipalUid, SourceIdentity};

use super::fs_hooks::run_test_retire_leaf_hook;
#[cfg(test)]
pub(super) use super::fs_hooks::set_test_retire_leaf_hook;

pub(super) fn add_source(
    sources: &mut BTreeMap<String, SourceIdentity>,
    name: String,
    path: impl AsRef<Path>,
) -> io::Result<()> {
    sources.insert(name, snapshot_path(path.as_ref())?);
    Ok(())
}

pub(super) fn add_principal_scope_sources(
    sources: &mut BTreeMap<String, SourceIdentity>,
    home: &AstridHome,
    alias: &PrincipalId,
    uid: PrincipalUid,
    capsule_ids: &[String],
) -> io::Result<()> {
    for capsule in capsule_ids {
        add_source(
            sources,
            format!("principal:{uid}:env:{capsule}"),
            home.principal_home(alias)
                .env_dir()
                .join(format!("{capsule}.env.json")),
        )?;
        add_source(
            sources,
            format!("principal:{uid}:secret:{capsule}"),
            home.secrets_dir().join(alias.as_str()).join(capsule),
        )?;
    }
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

/// Collect capsule directories below a workspace portal without following
/// redirects.  The migration barrier uses this inventory when checking that
/// no legacy authority receipts remain attached to a workspace capsule.
pub(super) fn collect_workspace_targets(root: &Path) -> io::Result<Vec<PathBuf>> {
    const MAX_WORKSPACE_TARGETS: usize = 4096;
    let metadata = match fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "workspace capsule portal is not a regular directory: {}",
                root.display()
            ),
        ));
    }
    astrid_core::platform_fs::verify_no_redirects(root)?;
    let mut targets = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let mut entries = fs::read_dir(&dir)
            .map_err(io::Error::other)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(io::Error::other)?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).map_err(io::Error::other)?;
            if metadata.file_type().is_symlink() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "workspace capsule portal contains a redirect: {}",
                        path.display()
                    ),
                ));
            }
            if !metadata.is_dir() {
                continue;
            }
            astrid_core::platform_fs::verify_no_redirects(&path)?;
            if path.join("Capsule.toml").is_file() {
                targets.push(path.clone());
                if targets.len() > MAX_WORKSPACE_TARGETS {
                    return Err(io::Error::other(
                        "workspace capsule portal exceeds target limit",
                    ));
                }
            }
            stack.push(path);
        }
    }
    Ok(targets)
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
            retire_leaf(&child, child_meta.len(), &leaf_snapshot)?;
        }
    }
    sync_directory(path)?;
    fs::remove_dir(path).map_err(io::Error::other)
}

fn retire_leaf(child: &Path, expected_len: u64, leaf_snapshot: &SourceIdentity) -> io::Result<()> {
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
    if replacement_meta.len() != expected_len || snapshot_path(child)? != *leaf_snapshot {
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

/// Validate the released audit-source boundary on every native host.  Unix
/// adds device and mount checks; all hosts retain no-follow, regular-entry,
/// and default-principal-only checks before the audit importer opens a source.
#[cfg(not(unix))]
pub(super) fn preflight_legacy_audit_sources(
    home: &AstridHome,
    default_source: &Path,
) -> io::Result<bool> {
    let root = home.home_dir();
    let metadata = match fs::symlink_metadata(&root) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "legacy principal-home root is not a directory: {}",
                    root.display()
                ),
            ));
        },
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    let root_device = device_id(&metadata);
    let mut default_source_present = false;
    astrid_core::platform_fs::verify_no_redirects(&root)?;
    for entry in fs::read_dir(&root).map_err(io::Error::other)? {
        let principal_root = entry.map_err(io::Error::other)?.path();
        let principal_metadata = fs::symlink_metadata(&principal_root).map_err(io::Error::other)?;
        if principal_metadata.file_type().is_symlink() || !principal_metadata.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "legacy principal-home entry is not a regular directory: {}",
                    principal_root.display()
                ),
            ));
        }
        if device_id(&principal_metadata) != root_device {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "legacy principal-home entry crosses a filesystem boundary: {}",
                    principal_root.display()
                ),
            ));
        }
        astrid_core::platform_fs::verify_no_redirects(&principal_root)?;
        let local_root = principal_root.join(".local");
        match fs::symlink_metadata(&local_root) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "legacy principal .local path is not a directory: {}",
                        local_root.display()
                    ),
                ));
            },
            Ok(_) => astrid_core::platform_fs::verify_no_redirects(&local_root)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        }
        let audit_source = local_root.join("audit");
        let audit_metadata = match fs::symlink_metadata(&audit_source) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if audit_source == default_source {
            default_source_present = true;
            validate_audit_tree(&audit_source, device_id(&audit_metadata))?;
        } else {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "unsupported legacy audit source {}; only the default principal source is admitted",
                    audit_source.display()
                ),
            ));
        }
    }
    Ok(default_source_present)
}

/// Retire the imported default audit tree through a private staging rename.
/// The rename makes interrupted deletion resumable, while every pre/post
/// traversal revalidates no-follow, regular-entry, device, and mount bounds.
#[cfg(not(unix))]
pub(super) fn retire_legacy_audit_dir(home: &AstridHome, source: &Path) -> io::Result<()> {
    let retired = home.migrations_dir().join("audit-principal-home.retired");
    let expected = home.principal_home(&PrincipalId::default()).audit_dir();
    if source != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "legacy audit retirement source is outside the default principal audit path",
        ));
    }
    astrid_core::platform_fs::verify_no_redirects(source.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "legacy audit source has no parent",
        )
    })?)?;
    astrid_core::platform_fs::ensure_private_directory(&home.migrations_dir())?;
    astrid_core::platform_fs::verify_no_redirects(&home.migrations_dir())?;
    match fs::symlink_metadata(source) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "legacy audit source is not a regular directory: {}",
                    source.display()
                ),
            ));
        },
        Ok(_) => {
            if fs::symlink_metadata(&retired).is_ok() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!(
                        "legacy audit retirement is ambiguous: {}",
                        retired.display()
                    ),
                ));
            }
            let root_device = device_id(&fs::symlink_metadata(source)?);
            validate_audit_tree(source, root_device)?;
            astrid_core::platform_fs::rename_with_write_through(source, &retired)?;
            sync_directory(source.parent().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "legacy audit source has no parent",
                )
            })?)?;
            sync_directory(&home.migrations_dir())?;
            validate_audit_tree(&retired, root_device)?;
            delete_audit_tree(&retired, root_device)?;
            sync_directory(&home.migrations_dir())?;
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if fs::symlink_metadata(&retired).is_ok() {
                let root_device = device_id(&fs::symlink_metadata(&retired)?);
                validate_audit_tree(&retired, root_device)?;
                delete_audit_tree(&retired, root_device)?;
                sync_directory(&home.migrations_dir())?;
            }
        },
        Err(error) => return Err(error),
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_audit_tree(path: &Path, root_device: u64) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "legacy audit tree is redirected or not a directory: {}",
                path.display()
            ),
        ));
    }
    if device_id(&metadata) != root_device || active_mountpoint(path)? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "legacy audit tree crosses a filesystem or mount boundary: {}",
                path.display()
            ),
        ));
    }
    astrid_core::platform_fs::verify_no_redirects(path)?;
    for entry in fs::read_dir(path).map_err(io::Error::other)? {
        let child = entry.map_err(io::Error::other)?.path();
        let child_metadata = fs::symlink_metadata(&child).map_err(io::Error::other)?;
        if child_metadata.file_type().is_symlink()
            || device_id(&child_metadata) != root_device
            || active_mountpoint(&child)?
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "legacy audit tree contains a redirect or boundary: {}",
                    child.display()
                ),
            ));
        }
        if child_metadata.is_dir() {
            validate_audit_tree(&child, root_device)?;
        } else if child_metadata.is_file() {
            astrid_core::platform_fs::verify_no_redirects(&child)?;
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "legacy audit tree contains a special file: {}",
                    child.display()
                ),
            ));
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn delete_audit_tree(path: &Path, root_device: u64) -> io::Result<()> {
    validate_audit_tree(path, root_device)?;
    for entry in fs::read_dir(path).map_err(io::Error::other)? {
        let child = entry.map_err(io::Error::other)?.path();
        let metadata = fs::symlink_metadata(&child).map_err(io::Error::other)?;
        if metadata.is_dir() {
            delete_audit_tree(&child, root_device)?;
        } else {
            astrid_core::platform_fs::verify_no_redirects(&child)?;
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
    snapshot_path_with_access(path, SourceAccess::Private)
}

/// Snapshot a released non-secret tree without requiring permissions that the
/// released binary never set. Historical database and capsule-package children
/// were commonly `0755` directories and `0644` files. They remain admissible
/// only when the current user owns every entry, nobody else can modify it, and
/// no extended ACL, redirect, mount, device boundary, or special entry exists.
pub(super) fn snapshot_owner_controlled_path(path: &Path) -> io::Result<SourceIdentity> {
    snapshot_path_with_access(path, SourceAccess::OwnerControlled)
}

#[derive(Clone, Copy)]
enum SourceAccess {
    Private,
    OwnerControlled,
}

fn snapshot_path_with_access(path: &Path, access: SourceAccess) -> io::Result<SourceIdentity> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(SourceIdentity::absent());
        },
        Err(error) => return Err(error),
    };
    astrid_core::platform_fs::verify_no_redirects(path)?;
    validate_source_entry(path, &metadata, access)?;
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
        snapshot_dir(path, path, device, access, &mut hasher, &mut identity)?;
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
    access: SourceAccess,
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
        validate_source_entry(&path, &metadata, access)?;
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
            snapshot_dir(root, &path, device, access, hasher, identity)?;
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

fn validate_source_entry(
    path: &Path,
    metadata: &fs::Metadata,
    access: SourceAccess,
) -> io::Result<()> {
    match access {
        SourceAccess::Private => validate_private_entry(path, metadata),
        SourceAccess::OwnerControlled => validate_owner_controlled_entry(path, metadata),
    }
}

fn validate_owner_controlled_entry(path: &Path, metadata: &fs::Metadata) -> io::Result<()> {
    if !metadata.is_dir() && !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("legacy source contains a special entry: {}", path.display()),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        if metadata.uid() != nix::unistd::getuid().as_raw() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "legacy source entry is not owned by the current user: {}",
                    path.display()
                ),
            ));
        }
        if metadata.mode() & 0o022 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "legacy source entry is group/world writable: {}",
                    path.display()
                ),
            ));
        }
        astrid_core::platform_fs::validate_no_extended_acl(path)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        validate_private_entry(path, metadata)
    }
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
        Ok(mountinfo.lines().any(|line| {
            line.split_whitespace()
                .nth(4)
                .and_then(decode_mountinfo_path)
                .is_some_and(|mount| mount == canonical)
        }))
    }
    #[cfg(target_os = "macos")]
    {
        let parent_path = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(path);
        if parent_path == path {
            return Ok(true);
        }
        let target_stats = nix::sys::statfs::statfs(path).map_err(io::Error::from)?;
        let parent_stats = nix::sys::statfs::statfs(parent_path).map_err(io::Error::from)?;
        Ok(target_stats.filesystem_id() != parent_stats.filesystem_id())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = path;
        Ok(false)
    }
}

#[cfg(all(test, target_os = "macos"))]
pub(super) fn test_active_mountpoint(path: &Path) -> io::Result<bool> {
    active_mountpoint(path)
}

#[cfg(target_os = "linux")]
fn decode_mountinfo_path(raw: &str) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStringExt;
    let mut decoded = Vec::with_capacity(raw.len());
    let bytes = raw.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let escape_end = index.checked_add(4)?;
        let escape_start = index.checked_add(1)?;
        if bytes[index] == b'\\' && escape_end <= bytes.len() {
            let value = u8::from_str_radix(
                std::str::from_utf8(bytes.get(escape_start..escape_end)?).ok()?,
                8,
            )
            .ok()?;
            decoded.push(value);
            index = escape_end;
        } else {
            decoded.push(bytes[index]);
            index = index.checked_add(1)?;
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

// Windows publication uses write-through replacement APIs; retain one
// fallible signature for shared retirement call sites.
#[cfg_attr(not(unix), allow(clippy::unnecessary_wraps))]
pub(super) fn sync_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(path)?.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

pub(super) fn storage_io(error: impl std::fmt::Display) -> io::Error {
    io::Error::other(error.to_string())
}
