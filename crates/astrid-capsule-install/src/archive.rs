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
use astrid_capsule::capsule::CapsuleId;
use astrid_core::dirs::AstridHome;

use astrid_core::PrincipalId;

use crate::local::{
    InstallOptions, InstallOutput, install_from_local_path_checked_for_principal,
    install_from_local_path_for_principal,
};

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
    unpack_and_install_for_principal(
        archive_path,
        home,
        options,
        &crate::paths::install_principal(),
    )
}

/// Unpack and install a `.capsule` archive for an explicit principal.
pub fn unpack_and_install_for_principal(
    archive_path: &Path,
    home: &AstridHome,
    options: InstallOptions,
    target_principal: &PrincipalId,
) -> anyhow::Result<InstallOutput> {
    unpack_and_install_internal(archive_path, home, options, target_principal, None, None)
}

/// Unpack and install only when the archive manifest identity equals
/// `expected`. When `expected_version` is present, the manifest version must
/// match it too. The staged archive is inspected before install mutation.
///
/// # Errors
///
/// Returns an error for an unsafe or malformed archive, an identity or version
/// mismatch, or any failure propagated by the local installer.
pub fn unpack_and_install_checked_for_principal(
    archive_path: &Path,
    home: &AstridHome,
    options: InstallOptions,
    target_principal: &PrincipalId,
    expected: &CapsuleId,
    expected_version: Option<&str>,
) -> anyhow::Result<InstallOutput> {
    unpack_and_install_internal(
        archive_path,
        home,
        options,
        target_principal,
        Some(expected),
        expected_version,
    )
}

fn unpack_and_install_internal(
    archive_path: &Path,
    home: &AstridHome,
    options: InstallOptions,
    target_principal: &PrincipalId,
    expected: Option<&CapsuleId>,
    expected_version: Option<&str>,
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

    match expected {
        Some(expected) => install_from_local_path_checked_for_principal(
            unpack_dir,
            home,
            options,
            target_principal,
            expected,
            expected_version,
        ),
        None => install_from_local_path_for_principal(unpack_dir, home, options, target_principal),
    }
}
