//! Soft cross-capsule checks run at install time.
//!
//! Neither check blocks the install — both surface advisory
//! information the caller can render however it likes. The CLI logs
//! warnings; the gateway returns them as structured fields in the
//! admin response so a dashboard can display them.

use anyhow::Context;
use astrid_capsule::manifest::CapsuleManifest;
use astrid_core::dirs::WorkspaceLayout;
use std::path::Path;

use crate::meta::scan_installed_capsules_in_home_for_in_workspace;

/// An unsatisfied non-optional import surfaced by [`validate_imports`].
#[derive(Debug, Clone)]
pub struct MissingImport {
    /// Namespace half of the import.
    pub namespace: String,
    /// Interface name half of the import.
    pub interface: String,
    /// `SemVer` requirement the importer expressed (e.g. `^0.7`).
    pub requirement: String,
}

/// Check whether a newly installed capsule's required imports are
/// satisfied by other installed capsules' exports. Optional imports
/// are silently skipped. Returns the missing ones — the caller decides
/// whether to log, error, or render in a UI.
pub fn validate_imports(manifest: &CapsuleManifest) -> Vec<MissingImport> {
    validate_imports_with_layout(manifest, &WorkspaceLayout::default())
}

/// Validate imports using an explicit workspace layout.
pub fn validate_imports_with_layout(
    manifest: &CapsuleManifest,
    workspace_layout: &WorkspaceLayout,
) -> Vec<MissingImport> {
    let home = match astrid_core::dirs::AstridHome::resolve() {
        Ok(home) => home,
        Err(_) => return Vec::new(),
    };
    let workspace_root = std::env::current_dir().ok();
    validate_imports_in_workspace(
        manifest,
        &home,
        &crate::paths::install_principal(),
        workspace_root.as_deref(),
        workspace_layout,
    )
}

/// Validate imports using explicit home and workspace inputs.
pub fn validate_imports_in_workspace(
    manifest: &CapsuleManifest,
    home: &astrid_core::dirs::AstridHome,
    principal: &astrid_core::PrincipalId,
    workspace_root: Option<&Path>,
    workspace_layout: &WorkspaceLayout,
) -> Vec<MissingImport> {
    if !manifest.has_imports() {
        return Vec::new();
    }
    let Ok(all_capsules) = scan_installed_capsules_in_home_for_in_workspace(
        home,
        principal,
        workspace_root,
        workspace_layout,
    ) else {
        return Vec::new();
    };

    let mut missing = Vec::new();
    for (ns, name, req, optional) in manifest.import_tuples() {
        if optional {
            continue;
        }
        let satisfied = all_capsules.iter().any(|c| {
            c.name != manifest.package.name
                && c.meta.as_ref().is_some_and(|m| {
                    m.exports
                        .get(ns)
                        .and_then(|ifaces| ifaces.get(name))
                        .and_then(|v| semver::Version::parse(v).ok())
                        .is_some_and(|v| req.matches(&v))
                })
        });
        if !satisfied {
            missing.push(MissingImport {
                namespace: ns.to_string(),
                interface: name.to_string(),
                requirement: req.to_string(),
            });
        }
    }
    missing
}

/// A peer capsule that already exports the same `(namespace, interface)`
/// the newly installed capsule exports.
#[derive(Debug, Clone)]
pub struct ExportConflict {
    /// `"<namespace>/<interface>"`.
    pub interface: String,
    /// The capsule that already exports this interface.
    pub existing_capsule: String,
}

/// Detect capsules already exporting interfaces the new capsule also
/// exports. **Informational** — multiple providers coexisting (e.g.
/// two LLM provider capsules) is valid; the kernel's runtime
/// dispatcher decides who handles a given call. The caller may want
/// to log this for operator visibility.
pub fn check_export_conflicts(manifest: &CapsuleManifest) -> anyhow::Result<Vec<ExportConflict>> {
    check_export_conflicts_with_layout(manifest, &WorkspaceLayout::default())
}

/// Detect export conflicts using an explicit workspace layout.
pub fn check_export_conflicts_with_layout(
    manifest: &CapsuleManifest,
    workspace_layout: &WorkspaceLayout,
) -> anyhow::Result<Vec<ExportConflict>> {
    let home = astrid_core::dirs::AstridHome::resolve()
        .context("failed to resolve Astrid home directory")?;
    let workspace_root = std::env::current_dir().ok();
    check_export_conflicts_in_workspace(
        manifest,
        &home,
        &crate::paths::install_principal(),
        workspace_root.as_deref(),
        workspace_layout,
    )
}

/// Detect export conflicts using explicit home and workspace inputs.
pub fn check_export_conflicts_in_workspace(
    manifest: &CapsuleManifest,
    home: &astrid_core::dirs::AstridHome,
    principal: &astrid_core::PrincipalId,
    workspace_root: Option<&Path>,
    workspace_layout: &WorkspaceLayout,
) -> anyhow::Result<Vec<ExportConflict>> {
    if !manifest.has_exports() {
        return Ok(Vec::new());
    }

    let all_capsules = scan_installed_capsules_in_home_for_in_workspace(
        home,
        principal,
        workspace_root,
        workspace_layout,
    )
    .context("failed to scan installed capsules for export conflict check")?;

    let mut shared = Vec::new();
    for (ns, name, _ver) in manifest.export_triples() {
        for c in &all_capsules {
            if c.name == manifest.package.name {
                continue;
            }
            if let Some(ref meta) = c.meta
                && meta
                    .exports
                    .get(ns)
                    .and_then(|ifaces| ifaces.get(name))
                    .is_some()
            {
                shared.push(ExportConflict {
                    interface: format!("{ns}/{name}"),
                    existing_capsule: c.name.clone(),
                });
            }
        }
    }
    Ok(shared)
}
