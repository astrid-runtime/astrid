use std::collections::BTreeSet;
use std::path::PathBuf;

use anyhow::{Context, bail};
use astrid_core::dirs::AstridHome;

use super::{AUTHORITY_RECEIPT_DIR, authority_paths};

/// Status of the global legacy authority receipt directory.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LegacyAuthorityReceiptStatus {
    /// Active receipts that do not correspond to a permitted workspace portal.
    pub unknown_active: Vec<PathBuf>,
    /// Incomplete pending transaction artifacts.
    pub pending: Vec<PathBuf>,
    /// Stale previous-receipt transaction artifacts.
    pub previous: Vec<PathBuf>,
}

/// Inspect global legacy authority receipts without deleting any file.
///
/// `workspace_targets` identifies explicit project portals whose active
/// receipts are intentionally retained. Every other active receipt is an
/// unknown leftover and must block layout cutover. Pending/previous files
/// always block cutover, including under a workspace portal.
///
/// # Errors
///
/// Returns an error when the receipt directory or one of its entries is
/// redirected, special, or unreadable.
pub fn legacy_authority_receipt_status(
    home: &AstridHome,
    workspace_targets: &[PathBuf],
) -> anyhow::Result<LegacyAuthorityReceiptStatus> {
    let directory = home.etc_dir().join(AUTHORITY_RECEIPT_DIR);
    let metadata = match std::fs::symlink_metadata(&directory) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(LegacyAuthorityReceiptStatus::default());
        },
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

    let permitted = workspace_targets
        .iter()
        .map(|target| authority_paths(home, target).map(|paths| paths.active))
        .collect::<anyhow::Result<BTreeSet<_>>>()?;
    let mut status = LegacyAuthorityReceiptStatus::default();
    let mut entries = std::fs::read_dir(&directory)
        .with_context(|| format!("read legacy capsule authority root {}", directory.display()))?
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("read legacy capsule authority root {}", directory.display()))?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path)
            .with_context(|| format!("inspect legacy capsule authority {}", path.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            bail!(
                "legacy capsule authority root contains a non-regular entry: {}",
                path.display()
            );
        }
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            bail!(
                "legacy capsule authority entry has a non-UTF-8 name: {}",
                path.display()
            );
        };
        if name.ends_with(".pending") {
            status.pending.push(path);
        } else if name.ends_with(".previous") {
            status.previous.push(path);
        } else if !path
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("json"))
            || !permitted.contains(&path)
        {
            status.unknown_active.push(path);
        }
    }
    Ok(status)
}
