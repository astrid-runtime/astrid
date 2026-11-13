//! Read-only recognition of interrupted stopped-home recovery shapes.

use std::{fs, io};

use super::AstridHome;

/// Exact stopped-home residues that require volume-authoritative recovery.
/// Recognition grants neither identity provisioning nor host-content admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoppedProjectionRecovery {
    /// A replacement key left by an older installer, optionally mid-restore.
    RuntimeKey,
    /// The private sentinel parent or atomic staging file left mid-restore.
    Sentinel,
}

impl AstridHome {
    /// Recognize a strictly bounded unsentinelled stopped-home residue.
    ///
    /// This checks structure and private access only. Under the boot singleton,
    /// storage must validate durable authority before cleanup or restoration.
    ///
    /// # Errors
    /// Returns an error for unsafe access, redirects or malformed key residue.
    pub fn stopped_projection_recovery(&self) -> io::Result<Option<StoppedProjectionRecovery>> {
        recognize_projection(self)
    }
}

pub(super) fn recognize(home: &AstridHome) -> io::Result<bool> {
    Ok(matches!(
        recognize_projection(home)?,
        Some(StoppedProjectionRecovery::RuntimeKey)
    ))
}

pub(super) fn admit_stopped_read_only(home: &AstridHome) -> io::Result<bool> {
    Ok(home.root().try_exists()?
        && matches!(
            home.validate_fresh_root_entries()?,
            super::UnsentinelledRootState::StoppedVolume
                | super::UnsentinelledRootState::StoppedRecovery
        ))
}

fn recognize_projection(home: &AstridHome) -> io::Result<Option<StoppedProjectionRecovery>> {
    if home.layout_version()?.is_some() {
        return Ok(None);
    }
    let entries = match fs::read_dir(home.root()) {
        Ok(entries) => entries.collect::<Result<Vec<_>, _>>()?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let has_key = entries.iter().any(|entry| entry.file_name() == "keys");
    let has_sentinel_parent = entries.iter().any(|entry| entry.file_name() == "etc");
    if !matches!(entries.len(), 2..=4)
        || !entries
            .iter()
            .any(|entry| entry.file_name() == "astrid.volume")
        || !(has_key || has_sentinel_parent)
    {
        return Ok(None);
    }
    for entry in &entries {
        match entry.file_name().to_str() {
            Some("astrid.volume" | "keys") => {},
            Some("run") if only_boot_singleton(home)? => {},
            Some("etc") if only_sentinel_staging_directory(home)? => {},
            _ => return Ok(None),
        }
    }
    validate_recovery_root(home)?;
    crate::platform_fs::validate_private_file_metadata(&home.storage_volume_path())?;
    if has_key {
        return Ok(valid_key_residue(home)?.then_some(StoppedProjectionRecovery::RuntimeKey));
    }
    Ok(Some(StoppedProjectionRecovery::Sentinel))
}

/// Recognition grants no mutation authority. Older admission and an interrupted
/// repair can leave a same-owner 0755 root, but other users must not be able to
/// replace its private volume or residue entries.
pub(super) fn validate_recovery_root(home: &AstridHome) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        crate::platform_fs::verify_no_redirects(home.root())?;
        let metadata = fs::symlink_metadata(home.root())?;
        if !metadata.is_dir()
            || metadata.uid() != nix::unistd::getuid().as_raw()
            || metadata.mode() & 0o022 != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "stopped recovery root has unsafe ownership or writable access",
            ));
        }
        crate::platform_fs::validate_no_extended_acl(home.root())
    }
    #[cfg(not(unix))]
    crate::platform_fs::validate_private_directory(home.root())
}

fn valid_key_residue(home: &AstridHome) -> io::Result<bool> {
    let keys = home.keys_dir();
    crate::platform_fs::verify_no_redirects(&keys)?;
    let metadata = fs::symlink_metadata(&keys)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(invalid(
            "runtime-key recovery directory is redirected or not a directory",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // Older key creation used the process umask (commonly 0755). Reading
        // directory names confers no key authority; other users must never be
        // able to replace its entries, and the key itself remains private.
        if metadata.uid() != fs::metadata(home.root())?.uid() || metadata.mode() & 0o022 != 0 {
            return Err(invalid(
                "runtime-key recovery directory has unsafe ownership or access",
            ));
        }
    }
    #[cfg(not(unix))]
    crate::platform_fs::validate_private_directory(&keys)?;
    crate::platform_fs::validate_no_extended_acl(&keys)?;
    let children = fs::read_dir(&keys)?.collect::<Result<Vec<_>, _>>()?;
    if children.len() != 1 || children[0].file_name() != "runtime.key" {
        return Ok(false);
    }
    crate::platform_fs::validate_private_file(&home.runtime_key_path())?;
    if fs::symlink_metadata(home.runtime_key_path())?.len() != 32 {
        return Err(invalid(
            "runtime-key recovery sidecar must be a 32-byte signing key",
        ));
    }
    Ok(true)
}

fn only_sentinel_staging_directory(home: &AstridHome) -> io::Result<bool> {
    // Atomic sentinel projection creates this parent first. Recognition does
    // not authorize recovery: storage requires its same-root durable intent.
    let etc = home.root().join("etc");
    let metadata = fs::symlink_metadata(&etc)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(invalid(
            "stopped sentinel parent is redirected or not a directory",
        ));
    }
    crate::platform_fs::verify_no_redirects(&etc)?;
    let entries = fs::read_dir(&etc)?.collect::<Result<Vec<_>, _>>()?;
    // Arbitrary configuration is a surviving projection, not sentinel residue.
    // Leave its missing-receipt rejection to storage rather than interpreting
    // its permissions as authorization for stopped recovery.
    if entries
        .iter()
        .any(|entry| !crate::platform_fs::is_structural_private_staging_name(&entry.file_name()))
    {
        return Ok(false);
    }
    crate::platform_fs::validate_private_directory(&etc)
        .map_err(|error| invalid(&format!("invalid stopped sentinel directory: {error}")))?;
    for entry in entries {
        crate::platform_fs::validate_private_file(&entry.path())?;
    }
    Ok(true)
}

pub(super) fn only_boot_singleton(home: &AstridHome) -> io::Result<bool> {
    let run = home.root().join("run");
    if !run.try_exists()? {
        return Ok(false);
    }
    // Boot acquires this private singleton before storage restore. Accept
    // only that persistent lockfile, not an arbitrary surviving run projection.
    crate::platform_fs::verify_no_redirects(&run)?;
    let entries = fs::read_dir(&run)?.collect::<Result<Vec<_>, _>>()?;
    if entries.len() != 1 || entries[0].file_name() != "system.lock" {
        return Ok(false);
    }
    // Unknown shapes retain ordinary fresh-root rejection. Only the exact
    // singleton shape reaches private-access validation and can be omitted.
    crate::platform_fs::validate_private_directory(&run)?;
    crate::platform_fs::validate_private_file(&run.join("system.lock"))?;
    Ok(true)
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod singleton_retry_tests;
