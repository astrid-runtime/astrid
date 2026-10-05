//! Read-only recognition of a published stopped-install failure shape.

use std::{fs, io};

use super::AstridHome;

pub(super) fn recognize(home: &AstridHome) -> io::Result<bool> {
    if home.layout_version()?.is_some() {
        return Ok(false);
    }
    let entries = match fs::read_dir(home.root()) {
        Ok(entries) => entries.collect::<Result<Vec<_>, _>>()?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    if !matches!(entries.len(), 2..=4)
        || !entries
            .iter()
            .any(|entry| entry.file_name() == "astrid.volume")
        || !entries.iter().any(|entry| entry.file_name() == "keys")
    {
        return Ok(false);
    }
    for entry in &entries {
        match entry.file_name().to_str() {
            Some("astrid.volume" | "keys") => {},
            Some("run") if only_boot_singleton(home)? => {},
            Some("etc") if only_sentinel_staging_directory(home)? => {},
            _ => return Ok(false),
        }
    }
    crate::platform_fs::validate_private_directory(home.root())?;
    crate::platform_fs::validate_private_file(&home.storage_volume_path())?;
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
    crate::platform_fs::validate_private_directory(&etc)?;
    for entry in fs::read_dir(etc)? {
        let entry = entry?;
        if !crate::platform_fs::is_private_atomic_staging_name(&entry.file_name()) {
            return Ok(false);
        }
        crate::platform_fs::validate_private_file(&entry.path())?;
    }
    Ok(true)
}

fn only_boot_singleton(home: &AstridHome) -> io::Result<bool> {
    let run = home.root().join("run");
    if !run.try_exists()? {
        return Ok(false);
    }
    // Boot acquires this private singleton before storage restore. Accept
    // only that persistent lockfile, not an arbitrary surviving run projection.
    crate::platform_fs::validate_private_directory(&run)?;
    let entries = fs::read_dir(&run)?.collect::<Result<Vec<_>, _>>()?;
    if entries.len() != 1 || entries[0].file_name() != "system.lock" {
        return Ok(false);
    }
    crate::platform_fs::validate_private_file(&run.join("system.lock"))?;
    Ok(true)
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests;
