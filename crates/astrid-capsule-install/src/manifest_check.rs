//! Soft cross-capsule checks run at install time.
//!
//! Neither check blocks the install — both surface advisory
//! information the caller can render however it likes. The CLI logs
//! warnings; the gateway returns them as structured fields in the
//! admin response so a dashboard can display them.

use anyhow::Context;
use astrid_capsule::manifest::CapsuleManifest;

use crate::meta::scan_installed_capsules;

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
    if !manifest.has_imports() {
        return Vec::new();
    }
    let Ok(all_capsules) = scan_installed_capsules() else {
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
    if !manifest.has_exports() {
        return Ok(Vec::new());
    }

    let all_capsules = scan_installed_capsules()
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
