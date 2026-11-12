//! Authenticated executable-set replacement through native filesystem operations.

use std::collections::HashSet;
use std::io;
use std::path::{Component, Path};

#[cfg(windows)]
use super::windows;

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
        let stage_result = (|| -> io::Result<()> {
            std::fs::copy(extract_dir.join(name), &temporary)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o755))?;
            }
            Ok(())
        })();
        if let Err(error) = stage_result {
            let _ = std::fs::remove_file(&temporary);
            for (staged_temporary, _) in &staged {
                let _ = std::fs::remove_file(staged_temporary);
            }
            return Err(io::Error::new(
                error.kind(),
                format!("failed to stage {}: {error}", temporary.display()),
            ));
        }
        staged.push((temporary, install_dir.join(name)));
    }

    for (index, (temporary, live)) in staged.iter().enumerate() {
        if let Err(error) = std::fs::rename(temporary, live) {
            let mut rollback_errors = Vec::new();
            for (_, installed_live) in &staged[..index] {
                if let Some((_, backup)) = backups
                    .iter()
                    .find(|(backup_live, _)| backup_live == installed_live)
                {
                    if let Err(rollback_error) = std::fs::rename(backup, installed_live) {
                        rollback_errors
                            .push(format!("{}: {rollback_error}", installed_live.display()));
                    }
                } else if let Err(rollback_error) = std::fs::remove_file(installed_live) {
                    rollback_errors.push(format!("{}: {rollback_error}", installed_live.display()));
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
mod tests;
