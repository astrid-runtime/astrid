//! Immutable byte-backed capsule archive inspection.

use std::path::Path;

use anyhow::Context as _;
use astrid_capsule::manifest::CapsuleManifest;
use astrid_core::PrincipalId;
use astrid_core::dirs::{AstridHome, WorkspaceLayout};

use super::{InspectedArtifact, InstallInspection, digest_manifest, inspect_manifest};

pub(super) fn parse_archive_manifest(manifest_text: &str) -> anyhow::Result<CapsuleManifest> {
    let staged = tempfile::tempdir().context("failed to stage capsule manifest")?;
    let manifest_path = staged.path().join("Capsule.toml");
    std::fs::write(&manifest_path, manifest_text)?;
    astrid_capsule::discovery::load_manifest(&manifest_path)
        .context("failed to validate capsule manifest")
}

/// Read and fully validate the manifest embedded in capsule archive bytes.
///
/// # Errors
///
/// Fails when the archive or manifest is malformed or unsafe.
pub fn read_archive_manifest_bytes(archive: &[u8]) -> anyhow::Result<CapsuleManifest> {
    let manifest_text = astrid_build::artifact::read_archive_text_bytes(archive, "Capsule.toml")?;
    parse_archive_manifest(&manifest_text)
}

/// Inspect immutable capsule archive bytes using explicit workspace inputs.
///
/// # Errors
///
/// Fails on malformed or tampered provenance, invalid manifests, or unsafe
/// target resolution.
pub fn inspect_archive_bytes_for_principal_in_workspace(
    archive: &[u8],
    home: &AstridHome,
    target_principal: &PrincipalId,
    workspace: bool,
    workspace_root: Option<&Path>,
    workspace_layout: &WorkspaceLayout,
) -> anyhow::Result<InstallInspection> {
    let verification = astrid_build::artifact::verify_archive_bytes(archive)?;
    let manifest_text = astrid_build::artifact::read_archive_text_bytes(archive, "Capsule.toml")?;
    let manifest_digest = digest_manifest(manifest_text.as_bytes());
    let manifest = parse_archive_manifest(&manifest_text)
        .context("failed to inspect capsule manifest from immutable archive bytes")?;
    inspect_manifest(
        manifest,
        InspectedArtifact {
            verification,
            manifest_digest,
        },
        home,
        target_principal,
        workspace,
        workspace_root,
        workspace_layout,
    )
}
