//! Unpack and install a `.capsule` archive (gzipped tar).
//!
//! The archive is staged into a tempdir and then handed off to
//! [`install_from_local_path`]. Entries are vetted for path-traversal
//! (`..`, absolute paths) and symlinks/hard-links are refused
//! outright — both could otherwise be used to write outside the
//! tempdir or have the runtime read from a location of the
//! attacker's choice.

use std::path::Path;

use anyhow::{Context, bail};
use astrid_core::dirs::AstridHome;

use crate::local::{InstallOptions, InstallOutput, install_from_local_path};

/// Unpack `archive_path` (a gzipped tar) into a tempdir, then install
/// from there.
///
/// # Errors
///
/// Returns an error on:
/// * a malformed archive,
/// * an entry whose path is absolute or contains `..`,
/// * any symlink or hard-link entry,
/// * any failure propagated from [`install_from_local_path`].
pub fn unpack_and_install(
    archive_path: &Path,
    home: &AstridHome,
    options: InstallOptions,
) -> anyhow::Result<InstallOutput> {
    let tmp_dir = tempfile::tempdir().context("failed to create temp dir for unpacking")?;
    let unpack_dir = tmp_dir.path();

    let tar_gz = std::fs::File::open(archive_path)
        .with_context(|| format!("Failed to open archive: {}", archive_path.display()))?;

    let tar = flate2::read::GzDecoder::new(tar_gz);
    let mut archive = tar::Archive::new(tar);

    for entry in archive
        .entries()
        .context("Failed to read archive entries")?
    {
        let mut entry = entry.context("Failed to read archive entry")?;
        let entry_path = entry.path().context("Invalid path in archive")?;

        if entry_path.is_absolute()
            || entry_path
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            bail!(
                "Malicious archive detected: invalid path '{}'",
                entry_path.display()
            );
        }

        let out_path = unpack_dir.join(&entry_path);
        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        if entry.header().entry_type().is_symlink() || entry.header().entry_type().is_hard_link() {
            bail!(
                "Malicious archive detected: symlinks are not allowed ('{}')",
                entry_path.display()
            );
        }

        entry
            .unpack(&out_path)
            .with_context(|| format!("Failed to unpack file: {}", out_path.display()))?;
    }

    install_from_local_path(unpack_dir, home, options)
}
