//! Internal platform filesystem boundary.
//!
//! Public Astrid path types stay in [`crate::dirs`]. This module owns the
//! operating-system mechanics needed to make those paths private and to
//! replace authenticated executables without exposing platform handles to the
//! rest of the workspace.

use std::collections::HashSet;
use std::io;
use std::path::{Component, Path, PathBuf};

#[cfg(windows)]
#[path = "platform_fs/windows.rs"]
mod windows;

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
        use std::os::unix::fs::PermissionsExt as _;

        std::fs::create_dir_all(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
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

    #[cfg(not(windows))]
    {
        let _ = path;
        Ok(())
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

    #[cfg(not(windows))]
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

    #[cfg(not(windows))]
    {
        std::fs::read_to_string(path)
    }
}

/// Atomically write one private file on Windows.
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

    #[cfg(not(windows))]
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
/// the chain while validating it. Existing Unix call sites retain their current
/// `symlink_metadata` and canonical-path checks.
///
/// # Errors
///
/// Returns an error if an existing Windows path component is a reparse point,
/// changes identity, or belongs to an untrusted parent chain.
pub fn verify_no_redirects(path: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        windows::verify_no_redirects(path)
    }

    #[cfg(not(windows))]
    {
        let _ = path;
        Ok(())
    }
}

/// Back up and replace a complete set of authenticated executables.
///
/// Staging always occurs beside the live files on the same volume. Unix keeps
/// the existing copy, `rename`, and rollback behavior. Windows flushes staged
/// bytes copied from identity-bound source handles, records a private recovery
/// journal under an OS-backed exclusive process lock, and performs each
/// same-directory name transition with
/// `SetFileInformationByHandle(FileRenameInfo)`. Each rename is atomic at the
/// individual name boundary; an interrupted or partially failed set is
/// restored from independent rollback copies. Successful updates retain
/// `<name>.bak`.
///
/// # Errors
///
/// Returns an error before mutation for invalid or missing inputs, or after
/// attempting journal-backed recovery when replacement fails. A recovery
/// failure leaves the journal and rollback copies in place for a later retry.
pub fn replace_executable_set(
    install_dir: &Path,
    extract_dir: &Path,
    names: &[&str],
) -> io::Result<()> {
    validate_replacement_inputs(install_dir, extract_dir, names)?;

    #[cfg(windows)]
    {
        windows::replace_executable_set(install_dir, extract_dir, names)
    }

    #[cfg(not(windows))]
    {
        replace_executable_set_by_rename(install_dir, extract_dir, names)
    }
}

fn validate_replacement_inputs(
    install_dir: &Path,
    extract_dir: &Path,
    names: &[&str],
) -> io::Result<()> {
    if names.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "executable replacement set must not be empty",
        ));
    }
    if !install_dir.is_dir() || !extract_dir.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "executable replacement directories must exist",
        ));
    }

    let mut unique = HashSet::with_capacity(names.len());
    for name in names {
        let mut components = Path::new(name).components();
        if !matches!(components.next(), Some(Component::Normal(_)))
            || components.next().is_some()
            || !unique.insert(*name)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid or duplicate executable name '{name}'"),
            ));
        }

        let source = extract_dir.join(name);
        let metadata = std::fs::symlink_metadata(&source).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("release archive is missing '{name}': {error}"),
            )
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("release executable is redirected or not regular: {name}"),
            ));
        }
    }
    Ok(())
}

#[cfg(not(windows))]
fn replace_executable_set_by_rename(
    install_dir: &Path,
    extract_dir: &Path,
    names: &[&str],
) -> io::Result<()> {
    let mut backups = Vec::new();
    for name in names {
        let live = install_dir.join(name);
        if live.exists() {
            let backup = install_dir.join(format!("{name}.bak"));
            std::fs::copy(&live, &backup)?;
            backups.push((live, backup));
        }
    }

    let mut staged = Vec::new();
    for name in names {
        let temporary = install_dir.join(format!(".{name}.new"));
        std::fs::copy(extract_dir.join(name), &temporary)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o755))?;
        }
        staged.push((temporary, install_dir.join(name)));
    }

    for (index, (temporary, live)) in staged.iter().enumerate() {
        if let Err(error) = std::fs::rename(temporary, live) {
            let mut rollback_errors = Vec::new();
            for (backup_live, backup) in &backups {
                if let Err(rollback_error) = std::fs::rename(backup, backup_live) {
                    rollback_errors.push(format!("{}: {rollback_error}", backup_live.display()));
                }
            }
            for (remaining, _) in &staged[index..] {
                let _ = std::fs::remove_file(remaining);
            }
            let detail = if rollback_errors.is_empty() {
                format!("failed to install {}", live.display())
            } else {
                format!(
                    "failed to install {}; rollback also failed ({}); restore *.bak manually",
                    live.display(),
                    rollback_errors.join("; ")
                )
            };
            return Err(io::Error::new(error.kind(), format!("{detail}: {error}")));
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "platform_fs/tests.rs"]
mod tests;
