//! Relocated layout-1 homes keep capsule-authority receipts hashed from a
//! previous absolute target path. Native migration retires only the receipt
//! for the current directory, so those leftovers would fail the cutover
//! barrier. Unique matches are rebound onto the current target; remaining
//! leftovers are quarantined with their original bytes.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use astrid_capsule::manifest::CapsuleManifest;
use astrid_core::dirs::AstridHome;

use super::{
    AUTHORITY_RECEIPT_DIR, AuthorityReceiptTransaction, InstalledAuthority, authority_paths,
    digest_manifest, read_installed_authority, sync_authority_directory,
};

const QUARANTINE_DIR: &str = "unmatched-legacy-capsule-authority";

/// Copy a uniquely matching leftover receipt onto the current native target.
///
/// The leftover file is left in place. Callers retire or quarantine it after
/// the durable package has been published.
pub(crate) fn rebind_relocated_legacy_authority_receipt(
    home: &AstridHome,
    target_dir: &Path,
    manifest: &CapsuleManifest,
    workspace_targets: &[PathBuf],
) -> anyhow::Result<()> {
    if read_installed_authority(home, target_dir)?.is_some() {
        return Ok(());
    }
    let Some(receipt) = unique_relocated_receipt(home, target_dir, manifest, workspace_targets)?
    else {
        return Ok(());
    };
    AuthorityReceiptTransaction::stage(home, target_dir, &receipt)?.commit()?;
    Ok(())
}

/// Active leftover receipts that are not workspace-portal targets.
pub(crate) fn unmatched_active_receipts(
    home: &AstridHome,
    workspace_targets: &[PathBuf],
) -> anyhow::Result<Vec<PathBuf>> {
    let status = super::legacy_authority_receipt_status(home, workspace_targets)?;
    if !status.pending.is_empty() {
        bail!(
            "cannot retire leftover capsule authority while pending transaction artifact exists at {}",
            status.pending[0].display()
        );
    }
    if !status.previous.is_empty() {
        bail!(
            "cannot retire leftover capsule authority while previous transaction artifact exists at {}",
            status.previous[0].display()
        );
    }
    Ok(status.unknown_active)
}

/// Parse a regular-file leftover receipt. Invalid JSON returns `Ok(None)`.
pub(crate) fn parse_legacy_authority_receipt(
    path: &Path,
) -> anyhow::Result<Option<(InstalledAuthority, Vec<u8>)>> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect leftover capsule authority {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!(
            "leftover capsule authority receipt is not a regular file: {}",
            path.display()
        );
    }
    astrid_core::platform_fs::verify_no_redirects(path).with_context(|| {
        format!(
            "verify leftover capsule authority receipt {}",
            path.display()
        )
    })?;
    let bytes = fs::read(path)
        .with_context(|| format!("read leftover capsule authority {}", path.display()))?;
    let Ok(receipt) = serde_json::from_slice::<InstalledAuthority>(&bytes) else {
        return Ok(None);
    };
    if receipt.schema_version != 1 {
        return Ok(None);
    }
    Ok(Some((receipt, bytes)))
}

/// Move one leftover receipt out of the live authority directory.
pub(crate) fn quarantine_legacy_authority_receipt(
    home: &AstridHome,
    path: &Path,
) -> anyhow::Result<PathBuf> {
    let bytes = fs::read(path)
        .with_context(|| format!("read leftover capsule authority {}", path.display()))?;
    let quarantine_root = home.migrations_dir().join(QUARANTINE_DIR);
    astrid_core::platform_fs::ensure_private_directory(&quarantine_root).with_context(|| {
        format!(
            "secure leftover authority quarantine {}",
            quarantine_root.display()
        )
    })?;
    let file_name = path.file_name().ok_or_else(|| {
        anyhow::anyhow!(
            "leftover capsule authority receipt has no file name: {}",
            path.display()
        )
    })?;
    let destination = unique_quarantine_path(&quarantine_root, file_name)?;
    fs::rename(path, &destination).with_context(|| {
        format!(
            "quarantine leftover capsule authority {} to {}",
            path.display(),
            destination.display()
        )
    })?;
    if let Some(parent) = path.parent() {
        sync_authority_directory(parent)?;
    }
    let preserved = fs::read(&destination).with_context(|| {
        format!(
            "read quarantined capsule authority {}",
            destination.display()
        )
    })?;
    if preserved != bytes {
        bail!(
            "quarantined capsule authority bytes changed: {}",
            destination.display()
        );
    }
    tracing::warn!(
        leftover = %path.display(),
        destination = %destination.display(),
        "quarantined unmatched leftover capsule authority receipt"
    );
    Ok(destination)
}

/// Unlink one leftover receipt after its durable ingest has been verified.
pub(crate) fn retire_unmatched_authority_receipt_file(
    path: &Path,
    expected_bytes: &[u8],
) -> anyhow::Result<()> {
    let metadata = fs::symlink_metadata(path).with_context(|| {
        format!(
            "leftover capsule authority receipt disappeared before retirement: {}",
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!(
            "leftover capsule authority receipt is not a regular file: {}",
            path.display()
        );
    }
    astrid_core::platform_fs::verify_no_redirects(path).with_context(|| {
        format!(
            "verify leftover capsule authority receipt {}",
            path.display()
        )
    })?;
    let actual = fs::read(path)
        .with_context(|| format!("read leftover capsule authority {}", path.display()))?;
    if actual != expected_bytes {
        bail!(
            "leftover capsule authority receipt changed before retirement: {}",
            path.display()
        );
    }
    fs::remove_file(path).with_context(|| {
        format!(
            "retire leftover capsule authority receipt {}",
            path.display()
        )
    })?;
    if let Some(parent) = path.parent() {
        sync_authority_directory(parent)?;
    }
    Ok(())
}

fn unique_relocated_receipt(
    home: &AstridHome,
    target_dir: &Path,
    manifest: &CapsuleManifest,
    workspace_targets: &[PathBuf],
) -> anyhow::Result<Option<InstalledAuthority>> {
    let current = authority_paths(home, target_dir)?.active;
    let mut permitted = BTreeSet::new();
    for target in workspace_targets {
        permitted.insert(authority_paths(home, target)?.active);
    }
    let manifest_bytes = fs::read(target_dir.join("Capsule.toml"))
        .context("failed to read installed capsule manifest")?;
    let manifest_digest = digest_manifest(&manifest_bytes);
    let mut matches = Vec::new();
    for path in active_receipt_files(home)? {
        if path == current || permitted.contains(&path) {
            continue;
        }
        let Some((receipt, _bytes)) = parse_legacy_authority_receipt(&path)? else {
            continue;
        };
        if receipt.capsule_id == manifest.package.name
            && receipt.version == manifest.package.version
            && receipt.manifest_digest == manifest_digest
        {
            matches.push(receipt);
        }
    }
    if matches.len() == 1 {
        Ok(Some(matches.remove(0)))
    } else {
        Ok(None)
    }
}

fn active_receipt_files(home: &AstridHome) -> anyhow::Result<Vec<PathBuf>> {
    let directory = home.etc_dir().join(AUTHORITY_RECEIPT_DIR);
    let metadata = match fs::symlink_metadata(&directory) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(error).with_context(|| format!("inspect {}", directory.display()));
        },
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!(
            "legacy capsule authority root is not a regular directory: {}",
            directory.display()
        );
    }
    astrid_core::platform_fs::verify_no_redirects(&directory).with_context(|| {
        format!(
            "verify legacy capsule authority root {}",
            directory.display()
        )
    })?;
    let mut paths = Vec::new();
    let mut entries = fs::read_dir(&directory)
        .with_context(|| format!("read legacy capsule authority root {}", directory.display()))?
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("read legacy capsule authority root {}", directory.display()))?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("inspect leftover capsule authority {}", path.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            bail!(
                "legacy capsule authority root contains a non-regular entry: {}",
                path.display()
            );
        }
        if path
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("json"))
        {
            paths.push(path);
        }
    }
    Ok(paths)
}

fn unique_quarantine_path(root: &Path, file_name: &std::ffi::OsStr) -> anyhow::Result<PathBuf> {
    let encoded = encoded_file_name(file_name);
    for index in 0_u32..1024 {
        let candidate = if index == 0 {
            root.join(&encoded)
        } else {
            root.join(format!("{encoded}-{index}"))
        };
        match fs::symlink_metadata(&candidate) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(candidate),
            Ok(_) => {},
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("inspect quarantine candidate {}", candidate.display())
                });
            },
        }
    }
    bail!("exhausted unique names for quarantined leftover capsule authority receipts")
}

fn encoded_file_name(name: &std::ffi::OsStr) -> String {
    const MAX_SAFE_NAME: usize = 80;
    match name.to_str() {
        Some(text)
            if !text.is_empty()
                && text.len() <= MAX_SAFE_NAME
                && text != "."
                && text != ".."
                && text
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.')) =>
        {
            text.to_owned()
        },
        _ => format!("invalid-{}", blake3::hash(&os_str_bytes(name)).to_hex()),
    }
}

fn os_str_bytes(name: &std::ffi::OsStr) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;
        name.as_bytes().to_vec()
    }
    #[cfg(not(unix))]
    {
        name.to_string_lossy().as_bytes().to_vec()
    }
}

#[cfg(test)]
#[path = "leftover_tests.rs"]
mod leftover_tests;
