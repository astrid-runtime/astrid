//! Preserve obsolete native material without assigning it capsule authority.

use std::fs;
use std::io;
use std::path::Path;

use anyhow::{Context, bail};
use astrid_capsule::capsule::CapsuleId;
use astrid_core::dirs::AstridHome;
use astrid_core::identity::PrincipalUid;

use crate::authority::{
    authority_paths, read_installed_authority_bytes, retire_legacy_authority_receipt,
};

/// Called only after the UID-owned durable package has verified successfully,
/// under the kernel's home singleton. No preserved bytes become executable or
/// approved. Keeping the recovery directory before the move also means an I/O
/// error cannot cause `TempDir` cleanup to delete the user's source.
pub(super) fn preserve_native_package(
    home: &AstridHome,
    target: &Path,
    uid: PrincipalUid,
    id: &CapsuleId,
) -> anyhow::Result<()> {
    let paths = authority_paths(home, target)?;
    for path in [&paths.pending, &paths.previous] {
        match fs::symlink_metadata(path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {},
            Err(error) => return Err(error).context("inspect obsolete authority transaction"),
            Ok(_) => bail!("obsolete capsule {id} has an incomplete authority transaction"),
        }
    }
    astrid_core::platform_fs::verify_no_redirects(&paths.active)?;
    let receipt = read_installed_authority_bytes(home, target)?;
    let root = home.migrations_dir().join("superseded-native-capsules");
    astrid_core::platform_fs::ensure_private_directory(&root)?;
    let recovery = tempfile::Builder::new()
        .prefix(&format!("{uid}-{id}-"))
        .tempdir_in(&root)
        .context("create private obsolete capsule recovery directory")?
        .keep();
    astrid_core::platform_fs::ensure_private_directory(&recovery)?;
    if let Some(bytes) = &receipt {
        astrid_core::platform_fs::atomic_write_private_file(
            &recovery.join("authority.json"),
            bytes,
        )?;
    }
    // Persist the root's own directory entry before the helper moves source
    // into the recovery directory. Neither new directory may vanish on crash.
    #[cfg(unix)]
    sync_recovery_root(&home.migrations_dir())?;
    let destination = recovery.join("source");
    astrid_core::dirs::preserve_legacy_source_tree(target, &destination)
        .with_context(|| format!("preserve obsolete native capsule {id}"))?;
    #[cfg(test)]
    if FAIL_AFTER_PRESERVATION.with(|fault| fault.replace(false)) {
        bail!("injected interruption after native preservation");
    }
    if let Some(bytes) = &receipt {
        retire_legacy_authority_receipt(home, target, bytes)
            .with_context(|| format!("retire obsolete global receipt for {id}"))?;
    }
    tracing::warn!(capsule = %id, %uid, recovery = %recovery.display(),
        "preserved obsolete native capsule; verified durable package remains authoritative");
    Ok(())
}

#[cfg(unix)]
fn sync_recovery_root(path: &Path) -> io::Result<()> {
    fs::File::open(path)?.sync_all()
}

#[cfg(test)]
thread_local! {
    pub(super) static FAIL_AFTER_PRESERVATION: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
