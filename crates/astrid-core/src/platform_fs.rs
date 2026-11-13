//! Internal platform filesystem boundary.
//!
//! Public Astrid path types stay in [`crate::dirs`]. This module owns the
//! operating-system mechanics needed to make those paths private and to
//! replace authenticated executables. Captured Windows directory owners may
//! duplicate their native object as a standard File with traversal rights only.
//! Mutation authority stays with the owner; removal still requires a
//! handle-relative proof that the name is absent.

#[cfg(target_os = "macos")]
#[path = "platform_fs/macos_acl.rs"]
mod macos_acl;

mod executable;
#[cfg(any(unix, test))]
mod mount_boundary;
pub mod name_semantics;
mod private_projection;
pub use executable::replace_executable_set;
#[cfg(any(unix, windows))]
pub(crate) use private_projection::compare::matches_file_from as matches_projection_file_from;
#[cfg(not(target_family = "wasm"))]
mod private_scratch;
mod staging_scope;

#[cfg(unix)]
use mount_boundary::MountBoundary;
#[cfg(target_os = "linux")]
pub(crate) use mount_boundary::MountId;
#[cfg(all(test, target_os = "linux"))]
pub(crate) use mount_boundary::fixtures as mount_fixtures;
#[cfg(all(any(test, feature = "test-support"), target_os = "linux"))]
pub use mount_boundary::fixtures as mount_test_fixtures;
#[cfg(any(target_os = "macos", target_os = "linux", windows))]
pub use name_semantics::directory_is_case_sensitive;
pub use private_projection::{
    PrivateFileProjection, PrivateFilePublication, PrivateFileReplacement, PrivateFileWriteOutcome,
    PrivateProjectionInspection,
};
#[cfg(not(target_family = "wasm"))]
pub use private_scratch::create_private_scratch_file;
pub use staging_scope::{
    StagingScope, StagingScopeError, is_private_atomic_staging_name,
    is_scoped_private_staging_name, is_structural_private_staging_name, staging_name_scope,
};

#[cfg(any(windows, test))]
use std::collections::HashSet;
use std::io;
use std::path::{Path, PathBuf};

#[cfg(windows)]
#[path = "platform_fs/windows.rs"]
pub(crate) mod windows;

#[path = "platform_fs/directory_identity.rs"]
mod directory_identity;

pub use directory_identity::DirectoryIdentity;
#[cfg(windows)]
pub use windows::directory_capability;
#[cfg(windows)]
pub use windows::{
    CapturedDirectory, create_new_private_file, create_new_private_file_shared,
    validate_private_file_handle,
};

#[cfg(any(windows, test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum AclPrincipal {
    CurrentUser,
    LocalSystem,
    Administrators,
    Other,
}

#[cfg(any(windows, test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AclRule {
    principal: AclPrincipal,
    access: AclAccess,
    inheritance: AclInheritance,
}

#[cfg(any(windows, test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AclAccess {
    AllowFullControl,
    Other,
}

#[cfg(any(windows, test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AclInheritance {
    None,
    Children,
    InheritedOrOther,
}

#[cfg(any(windows, test))]
fn acl_rules_are_private(
    is_directory: bool,
    dacl_is_protected: bool,
    owner_is_allowed: bool,
    rules: &[AclRule],
) -> bool {
    if !dacl_is_protected || !owner_is_allowed || rules.len() != 3 {
        return false;
    }

    let mut principals = HashSet::with_capacity(3);
    for rule in rules {
        let expected_inheritance = if is_directory {
            AclInheritance::Children
        } else {
            AclInheritance::None
        };
        if rule.access != AclAccess::AllowFullControl
            || rule.inheritance != expected_inheritance
            || rule.principal == AclPrincipal::Other
            || !principals.insert(rule.principal)
        {
            return false;
        }
    }

    principals
        == HashSet::from([
            AclPrincipal::CurrentUser,
            AclPrincipal::LocalSystem,
            AclPrincipal::Administrators,
        ])
}

/// Return the platform's private per-user Astrid root.
///
/// Unix resolution remains in [`crate::dirs::AstridHome`] because its existing
/// `$HOME/.astrid` contract must not move. Windows uses the `LocalAppData` known
/// folder and never falls back to the current directory or a shared root.
///
/// # Errors
///
/// Returns an error if Windows cannot resolve a per-user `LocalAppData` folder or
/// if that folder is not a local absolute path.
pub fn default_astrid_home_root() -> io::Result<PathBuf> {
    #[cfg(windows)]
    {
        windows::default_astrid_home_root()
    }

    #[cfg(not(windows))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the Unix Astrid home is resolved from HOME",
        ))
    }
}

/// Create a security-sensitive directory and enforce the platform's private
/// access policy.
///
/// Unix keeps Astrid's existing owner-only `0700` behavior. Windows installs a
/// protected DACL containing only the current user, `LocalSystem`, and the local
/// Administrators group, with inheritable full-control entries for children.
///
/// # Errors
///
/// Returns an error when the path cannot be created, is redirected through a
/// symlink or reparse point, or cannot be made private.
pub fn ensure_private_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        ensure_private_directory_unix(path)
    }

    #[cfg(windows)]
    {
        windows::ensure_private_directory(path)
    }

    #[cfg(not(any(unix, windows)))]
    {
        std::fs::create_dir_all(path)
    }
}

/// Exclusively create one private directory beneath an existing trusted parent.
///
/// Unlike [`ensure_private_directory`], this never adopts an existing name.
/// Windows installs the protected private DACL at namespace creation; callers
/// must not first create an inheriting directory with a generic temp API.
///
/// # Errors
///
/// Returns an error if the name exists, its parent is missing or redirected,
/// or the platform cannot create and validate the private directory.
pub fn create_private_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use nix::sys::stat::{Mode, mkdirat};
        let parent = path.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "private directory has no parent",
            )
        })?;
        let name = path.file_name().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "private directory has no name")
        })?;
        let directory = open_directory_no_follow_unix(parent)?;
        mkdirat(&directory, name, Mode::from_bits_truncate(0o700)).map_err(nix_io_error)?;
        ensure_private_directory_unix(path)
    }
    #[cfg(windows)]
    {
        windows::create_private_directory(path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        std::fs::create_dir(path)
    }
}

/// Make `path` and every nested real directory owner-only.
///
/// Layout-1 leftovers often have `0755` children (COW slots, unpacked homes).
/// Cutover must repair those itself; a user should not have to chmod first.
///
/// # Errors
///
/// Returns an error when any real directory cannot be made private. Symlinks
/// are skipped and not followed.
pub fn ensure_private_directory_tree(path: &Path) -> io::Result<()> {
    ensure_private_directory(path)?;
    #[cfg(unix)]
    {
        ensure_private_children_unix(path)?;
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_private_children_unix(path: &Path) -> io::Result<()> {
    let entries = match std::fs::read_dir(path) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    for entry in entries {
        let entry = entry?;
        let child = entry.path();
        let metadata = std::fs::symlink_metadata(&child)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            continue;
        }
        ensure_private_directory(&child)?;
        ensure_private_children_unix(&child)?;
    }
    Ok(())
}

/// Validate an existing directory against the platform's private-access policy.
///
/// Unix requires a current-user-owned directory with exactly owner-only mode
/// bits and rejects redirects in every existing path component. Windows uses
/// the same protected-DACL contract as creation.
///
/// # Errors
///
/// Returns an error when the directory is missing, redirected, not owned by the
/// current user, or does not satisfy the platform private-access policy.
pub fn validate_private_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        validate_private_directory_unix(path)
    }

    #[cfg(windows)]
    {
        windows::validate_private_directory(path)
    }

    #[cfg(not(any(unix, windows)))]
    {
        let metadata = std::fs::symlink_metadata(path)?;
        if !metadata.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "private path is not a directory",
            ));
        }
        Ok(())
    }
}

/// Rename one filesystem entry with the strongest supported namespace
/// durability for the host platform.
///
/// Windows uses `MoveFileExW(MOVEFILE_WRITE_THROUGH)`, which does not return
/// until the move has been flushed. Unix callers must still synchronize the
/// affected parent directories after this atomic rename.
///
/// Windows rejects an existing destination because the write-through move does
/// not request replacement. Other platforms retain `std::fs::rename`
/// replacement semantics. Security-sensitive callers remain responsible for
/// serializing destination selection and validating both parent boundaries.
///
/// # Errors
///
/// Returns an error when either path is invalid or the operating system cannot
/// complete the rename at its platform-specific durability boundary. Windows
/// also returns an error when the destination already exists.
pub fn rename_with_write_through(source: &Path, destination: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        windows::rename_with_write_through(source, destination)
    }

    #[cfg(not(windows))]
    {
        std::fs::rename(source, destination)
    }
}

/// Enforce and validate private access on an existing regular file.
///
/// Unix retains its caller-owned mode behavior. Windows rejects reparse points
/// and applies a protected non-inheritable DACL for the current user,
/// `LocalSystem`, and local Administrators.
///
/// # Errors
///
/// Returns an error if the file is missing, not regular, redirected, or cannot
/// be secured and validated.
pub fn restrict_private_file(path: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        windows::restrict_private_file(path)
    }

    #[cfg(unix)]
    {
        restrict_private_file_unix(path)
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "private host-file permissions are unavailable on this target",
        ))
    }
}

/// Validate that an existing private file still has the platform's required
/// access policy.
///
/// On Unix the existing mode checks remain with their current callers.
///
/// # Errors
///
/// Returns an error on Windows for an unexpected owner, permissive or inherited
/// ACL, reparse point, or non-regular file.
pub fn validate_private_file(path: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        windows::validate_private_file(path)
    }

    #[cfg(unix)]
    {
        validate_private_file_unix(path)
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "private host-file validation is unavailable on this target",
        ))
    }
}

/// Observe privacy without acquiring content-read authority or excluding a live
/// writer. Stopped-volume recognition is only a structural preflight; storage
/// subsequently authenticates and locks the canonical volume before recovery.
pub(crate) fn validate_private_file_metadata(path: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        windows::validate_private_file_metadata(path)
    }
    #[cfg(not(windows))]
    {
        validate_private_file(path)
    }
}

/// Reject a native path carrying an extended access-control list.
///
/// macOS ACL entries can grant access beyond owner-only POSIX mode bits, so
/// security-sensitive paths must satisfy both checks. Platforms without this
/// additional ACL surface accept the path unchanged.
///
/// # Errors
///
/// Returns an error when the ACL cannot be inspected or contains any entry.
pub fn validate_no_extended_acl(path: &Path) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        match open_file_no_follow_unix(path) {
            Ok(file) => macos_acl::validate(&file),
            // Darwin cannot open a socket vnode as a file. Inspect its ACL
            // relative to the captured parent and verify the socket identity.
            Err(error) if error.raw_os_error() == Some(nix::libc::EOPNOTSUPP) => {
                macos_acl::validate_socket(path)
            },
            Err(error) => Err(error),
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = path;
        Ok(())
    }
}

/// Read one private text file through the platform's protected filesystem
/// boundary.
///
/// Windows serializes the read with private-file replacement, recovers any
/// pending journal before opening the live name, validates the exact private
/// ACL, and holds an identity-bound handle through the read. Unix retains
/// `std::fs::read_to_string` unchanged.
///
/// # Errors
///
/// Returns an error if recovery is blocked or fails, the file is missing,
/// redirected, permissive, replaced during validation, or is not valid UTF-8.
pub(crate) fn read_private_file_to_string(path: &Path) -> io::Result<String> {
    #[cfg(windows)]
    {
        windows::read_private_file_to_string(path)
    }

    #[cfg(unix)]
    {
        if validate_private_file(path).is_err() {
            restrict_private_file(path)?;
        }
        std::fs::read_to_string(path)
    }

    #[cfg(not(any(unix, windows)))]
    {
        std::fs::read_to_string(path)
    }
}

/// Atomically write one private file.
///
/// The temporary is created exclusively beside the destination, secured before
/// it becomes visible under the live name, flushed through the supported file
/// API, and installed with a same-volume replacement. A private transaction
/// journal and independent rollback copy restore the prior file when a failure
/// or interruption leaves the transaction uncommitted. Existing destinations
/// must already satisfy the private ACL contract. This does not claim that a
/// namespace update survives sudden power loss.
///
/// # Errors
///
/// Returns an error if the parent is not private, the destination is
/// redirected or permissive, staging or sync fails, or atomic replacement
/// fails.
pub fn atomic_write_private_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    #[cfg(windows)]
    {
        windows::atomic_write_private_file(path, bytes)
    }

    #[cfg(unix)]
    {
        atomic_write_private_file_unix(path, bytes)
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = (path, bytes);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "private atomic-file backend is selected by Windows callers only",
        ))
    }
}

/// Reject redirecting path components at a security-sensitive boundary.
///
/// Windows checks the reparse attribute on every existing component, covering
/// symlinks, junctions, and mount points. It also rejects parent owners or ACLs
/// that let untrusted principals replace checked components, and identity-locks
/// the chain while validating it. Unix opens the nearest existing directory
/// authority and rejects a redirect at the requested or nearest-existing path;
/// callers retain directory capabilities across multi-step mutations.
///
/// # Errors
///
/// Returns an error if an existing security-sensitive path is redirected,
/// changes identity, or belongs to an untrusted parent chain.
pub fn verify_no_redirects(path: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        windows::verify_no_redirects(path)
    }

    #[cfg(unix)]
    {
        verify_no_redirects_unix(path)
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Ok(())
    }
}

#[cfg(unix)]
fn verify_no_redirects_unix(path: &Path) -> io::Result<()> {
    use nix::fcntl::{OFlag, openat};
    use nix::sys::stat::Mode;

    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("private path is redirected: {}", path.display()),
        )),
        Ok(metadata) if metadata.is_dir() => open_directory_no_follow_unix(path).map(drop),
        Ok(_) => {
            let parent = path.parent().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("private path has no parent: {}", path.display()),
                )
            })?;
            let name = path.file_name().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("private path has no file name: {}", path.display()),
                )
            })?;
            let directory = open_directory_no_follow_unix(parent)?;
            let flags = OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK;
            openat(&directory, name, flags, Mode::empty())
                .map(std::fs::File::from)
                .map(drop)
                .map_err(nix_io_error)
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            open_directory_no_follow_unix(path).map(drop)
        },
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn ensure_private_directory_unix(path: &Path) -> io::Result<()> {
    use nix::errno::Errno;
    use nix::fcntl::{OFlag, openat};
    use nix::sys::stat::{Mode, fchmod, mkdirat};

    let (mut directory, components) = unix_directory_walk(path)?;
    for component in components {
        let flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
        let next = match openat(&directory, component.as_os_str(), flags, Mode::empty()) {
            Ok(next) => next,
            Err(Errno::ENOENT) => {
                match mkdirat(
                    &directory,
                    component.as_os_str(),
                    Mode::from_bits_truncate(0o700),
                ) {
                    Ok(()) | Err(Errno::EEXIST) => {},
                    Err(error) => return Err(nix_io_error(error)),
                }
                openat(&directory, component.as_os_str(), flags, Mode::empty())
                    .map_err(nix_io_error)?
            },
            Err(error) => return Err(nix_io_error(error)),
        };
        directory = std::fs::File::from(next);
    }
    fchmod(&directory, Mode::from_bits_truncate(0o700)).map_err(nix_io_error)?;
    #[cfg(target_os = "macos")]
    macos_acl::restrict(&directory)?;
    validate_private_directory_unix(path)
}

#[cfg(unix)]
fn validate_private_directory_unix(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let directory = open_directory_no_follow_unix(path)?;
    let metadata = directory.metadata()?;
    if metadata.uid() != nix::unistd::getuid().as_raw() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "private directory is not owned by the current user: {}",
                path.display()
            ),
        ));
    }
    if metadata.permissions().mode() & 0o777 != 0o700 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("private directory is not owner-only: {}", path.display()),
        ));
    }
    #[cfg(target_os = "macos")]
    macos_acl::validate(&directory)?;
    Ok(())
}

#[cfg(unix)]
fn restrict_private_file_unix(path: &Path) -> io::Result<()> {
    use nix::sys::stat::{Mode, fchmod, fstat};

    let file = open_file_no_follow_unix(path)?;
    let metadata = fstat(&file).map_err(nix_io_error)?;
    if metadata.st_mode & 0o170_000 != 0o100_000 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("private path is not a regular file: {}", path.display()),
        ));
    }
    fchmod(&file, Mode::from_bits_truncate(0o600)).map_err(nix_io_error)?;
    file.sync_all()?;
    #[cfg(target_os = "macos")]
    macos_acl::restrict(&file)?;
    drop(file);
    validate_private_file_unix(path)
}

#[cfg(unix)]
fn validate_private_file_unix(path: &Path) -> io::Result<()> {
    use nix::sys::stat::fstat;

    let file = open_file_no_follow_unix(path)?;
    let metadata = fstat(&file).map_err(nix_io_error)?;
    if metadata.st_mode & 0o170_000 != 0o100_000 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("private path is not a regular file: {}", path.display()),
        ));
    }
    if metadata.st_uid != nix::unistd::getuid().as_raw() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "private file is not owned by the current user: {}",
                path.display()
            ),
        ));
    }
    if metadata.st_mode & 0o777 != 0o600 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("private file is not owner-only: {}", path.display()),
        ));
    }
    if metadata.st_nlink != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "private file has {} links; durable media must have exactly one",
                metadata.st_nlink
            ),
        ));
    }
    #[cfg(target_os = "macos")]
    macos_acl::validate(&file)?;
    Ok(())
}

#[cfg(unix)]
fn open_file_no_follow_unix(path: &Path) -> io::Result<std::fs::File> {
    use nix::fcntl::{OFlag, openat};
    use nix::sys::stat::Mode;

    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("private file has no parent: {}", path.display()),
        )
    })?;
    let name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("private file has no name: {}", path.display()),
        )
    })?;
    let directory = open_directory_no_follow_unix(parent)?;
    let flags = OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK;
    openat(&directory, name, flags, Mode::from_bits_truncate(0o600))
        .map(std::fs::File::from)
        .map_err(nix_io_error)
}

#[cfg(unix)]
fn atomic_write_private_file_unix(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("private atomic file has no parent: {}", path.display()),
        )
    })?;
    ensure_private_directory(parent)?;
    let temporary = parent.join(format!(".astrid-private-{}", uuid::Uuid::new_v4().simple()));
    let write = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()
    })();
    if let Err(error) = write {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    if let Err(error) = rename_with_write_through(&temporary, path) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    if let Ok(parent_handle) = open_directory_no_follow_unix(parent) {
        parent_handle.sync_all()?;
    }
    validate_private_file(path)
}

/// Open the requested directory itself, rejecting missing tails and redirects.
#[cfg(unix)]
pub(crate) fn open_existing_directory_no_follow(path: &Path) -> io::Result<std::fs::File> {
    let (directory, missing) = unix_directory_walk(path)?;
    if !missing.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("directory does not exist: {}", path.display()),
        ));
    }
    Ok(directory)
}

#[cfg(unix)]
fn open_directory_no_follow_unix(path: &Path) -> io::Result<std::fs::File> {
    let (directory, _) = unix_directory_walk(path)?;
    Ok(directory)
}

#[cfg(all(unix, test))]
pub(crate) use private_projection::walk_counter::{
    directory_walk_count, reset_directory_walk_count,
};

#[cfg(unix)]
fn unix_directory_walk(path: &Path) -> io::Result<(std::fs::File, Vec<std::ffi::OsString>)> {
    use nix::errno::Errno;
    use nix::fcntl::{OFlag, openat};
    use nix::sys::stat::Mode;
    use std::path::Component;

    #[cfg(test)]
    private_projection::walk_counter::record();

    let components = path.components().collect::<Vec<_>>();
    if components
        .iter()
        .any(|component| matches!(component, Component::ParentDir | Component::Prefix(_)))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("private directory contains traversal: {}", path.display()),
        ));
    }

    let absolute = normalize_unix_system_alias(if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    });
    let mut directory = if absolute
        .components()
        .next()
        .is_some_and(|component| matches!(component, Component::RootDir))
    {
        std::fs::File::open("/")
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("private directory has no Unix root: {}", path.display()),
        ));
    }?;
    let mut missing = Vec::new();
    for component in absolute
        .components()
        .filter_map(|component| match component {
            Component::Normal(name) => Some(name.to_os_string()),
            _ => None,
        })
    {
        if missing.is_empty() {
            let flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
            match openat(&directory, component.as_os_str(), flags, Mode::empty()) {
                Ok(next) => directory = std::fs::File::from(next),
                Err(Errno::ENOENT) => missing.push(component),
                Err(error) => return Err(nix_io_error(error)),
            }
        } else {
            missing.push(component);
        }
    }

    if directory.metadata()?.is_dir() {
        Ok((directory, missing))
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("private directory is not a directory: {}", path.display()),
        ))
    }
}

#[cfg(target_os = "macos")]
fn normalize_unix_system_alias(path: PathBuf) -> PathBuf {
    use std::os::unix::ffi::OsStrExt as _;

    let bytes = path.as_os_str().as_bytes();
    if bytes == b"/tmp" || bytes.starts_with(b"/tmp/") {
        return PathBuf::from("/private/tmp").join(path.strip_prefix("/tmp").expect("prefix"));
    }
    if bytes == b"/var" || bytes.starts_with(b"/var/") {
        return PathBuf::from("/private/var").join(path.strip_prefix("/var").expect("prefix"));
    }
    path
}

#[cfg(all(unix, not(target_os = "macos")))]
fn normalize_unix_system_alias(path: PathBuf) -> PathBuf {
    path
}

#[cfg(unix)]
fn nix_io_error(error: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(error as i32)
}

#[cfg(test)]
#[path = "platform_fs/tests.rs"]
mod tests;
