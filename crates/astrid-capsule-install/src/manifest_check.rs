//! Soft cross-capsule checks run at install time.
//!
//! Neither check blocks the install — both surface advisory
//! information the caller can render however it likes. The CLI logs
//! warnings; the gateway returns them as structured fields in the
//! admin response so a dashboard can display them.

use anyhow::Context;
use astrid_capsule::manifest::CapsuleManifest;
use astrid_core::dirs::WorkspaceLayout;
use astrid_core::identity::PrincipalUid;
use astrid_storage::{RuntimePrincipalStore, StateOwner};
use std::path::Path;

use crate::meta::scan_installed_capsules_in_home_for_in_workspace;
use crate::storage::read_verified_durable_package_for_owner;

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
    let Ok(home) = astrid_core::dirs::AstridHome::resolve() else {
        return Vec::new();
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

/// Validate imports against the immutable UID-owned capsule registry.
///
/// Native principal-home directories are not consulted. Every peer is read
/// from one verified durable package snapshot, so a missing or malformed
/// registry package fails closed rather than producing an incomplete warning.
///
/// # Errors
///
/// Returns an error when the registry cannot be listed or a package fails
/// archive/metadata/authority verification.
pub fn validate_imports_in_storage(
    manifest: &CapsuleManifest,
    store: &RuntimePrincipalStore,
    uid: PrincipalUid,
) -> anyhow::Result<Vec<MissingImport>> {
    if !manifest.has_imports() {
        return Ok(Vec::new());
    }
    let peers = durable_capsule_metadata(store, uid)?;
    Ok(missing_imports_from_metadata(manifest, &peers))
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

/// Detect export conflicts against the immutable UID-owned capsule registry.
///
/// # Errors
///
/// Returns an error when the registry cannot be listed or a package fails
/// archive/metadata/authority verification.
pub fn check_export_conflicts_in_storage(
    manifest: &CapsuleManifest,
    store: &RuntimePrincipalStore,
    uid: PrincipalUid,
) -> anyhow::Result<Vec<ExportConflict>> {
    if !manifest.has_exports() {
        return Ok(Vec::new());
    }
    let peers = durable_capsule_metadata(store, uid)?;
    Ok(export_conflicts_from_metadata(manifest, &peers))
}

fn durable_capsule_metadata(
    store: &RuntimePrincipalStore,
    uid: PrincipalUid,
) -> anyhow::Result<Vec<(String, crate::meta::CapsuleMeta)>> {
    let owner = StateOwner::Principal(uid);
    let summaries = store
        .capsules()
        .list(&owner)
        .context("list durable capsules for manifest check")?;
    summaries
        .into_iter()
        .map(|summary| {
            let id = summary.id().to_owned();
            let package =
                read_verified_durable_package_for_owner(store, &owner, &id)?.ok_or_else(|| {
                    anyhow::anyhow!("durable capsule {id} disappeared during manifest check")
                })?;
            Ok((id, package.metadata().clone()))
        })
        .collect()
}

fn missing_imports_from_metadata(
    manifest: &CapsuleManifest,
    peers: &[(String, crate::meta::CapsuleMeta)],
) -> Vec<MissingImport> {
    manifest
        .import_tuples()
        .filter_map(|(ns, name, req, optional)| {
            if optional {
                return None;
            }
            let satisfied = peers.iter().any(|(id, meta)| {
                id != &manifest.package.name
                    && meta
                        .exports
                        .get(ns)
                        .and_then(|ifaces| ifaces.get(name))
                        .and_then(|version| semver::Version::parse(version).ok())
                        .is_some_and(|version| req.matches(&version))
            });
            (!satisfied).then(|| MissingImport {
                namespace: ns.to_owned(),
                interface: name.to_owned(),
                requirement: req.to_string(),
            })
        })
        .collect()
}

fn export_conflicts_from_metadata(
    manifest: &CapsuleManifest,
    peers: &[(String, crate::meta::CapsuleMeta)],
) -> Vec<ExportConflict> {
    manifest
        .export_triples()
        .flat_map(|(ns, name, _version)| {
            peers.iter().filter_map(move |(id, meta)| {
                if id == &manifest.package.name
                    || meta
                        .exports
                        .get(ns)
                        .and_then(|ifaces| ifaces.get(name))
                        .is_none()
                {
                    return None;
                }
                Some(ExportConflict {
                    interface: format!("{ns}/{name}"),
                    existing_capsule: id.clone(),
                })
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use astrid_build::artifact;
    use astrid_capsule::manifest::CapabilitiesDef;
    use astrid_core::PrincipalId;
    use astrid_core::dirs::AstridHome;
    use astrid_core::identity::PrincipalUid;
    use astrid_storage::{
        CapsuleInstallExpectation, CapsulePackage, KvQuotaResolver, PrincipalDirectory,
        RuntimePrincipalStore, StateOwner, open_runtime_principal_store_with_directory,
    };
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use tar::Builder;

    use super::*;
    use crate::authority::{AuthoritySource, InstalledAuthority, digest_manifest};
    use crate::meta::CapsuleMeta;

    fn package_with_export(id: &str) -> CapsulePackage {
        let manifest = format!("[package]\nname = \"{id}\"\nversion = \"1.0.0\"\n\n");
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        {
            let mut archive = Builder::new(&mut encoder);
            let mut header = tar::Header::new_gnu();
            header.set_size(manifest.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            archive
                .append_data(&mut header, "Capsule.toml", manifest.as_bytes())
                .unwrap();
            archive.finish().unwrap();
        }
        let archive = encoder.finish().unwrap();
        let verification = artifact::verify_archive_bytes(&archive).unwrap();
        let authority = InstalledAuthority {
            schema_version: 1,
            source: AuthoritySource::OperatorDistribution,
            capsule_id: id.to_owned(),
            version: "1.0.0".to_owned(),
            content_digest: verification.content_digest().to_owned(),
            manifest_digest: digest_manifest(manifest.as_bytes()),
            signer: None,
            signature: None,
            approved_capabilities: CapabilitiesDef::default(),
            wasm_hash_pinned: false,
            approved_wasm_hash: None,
        };
        let mut exports = HashMap::new();
        exports.insert(
            "astrid".to_owned(),
            HashMap::from([(String::from("session"), String::from("1.2.0"))]),
        );
        let metadata = CapsuleMeta {
            version: "1.0.0".to_owned(),
            exports,
            ..Default::default()
        };
        CapsulePackage::new(
            archive,
            serde_json::to_vec(&metadata).unwrap(),
            serde_json::to_vec(&authority).unwrap(),
        )
    }

    fn test_store() -> (tempfile::TempDir, Arc<RuntimePrincipalStore>, PrincipalUid) {
        let root = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(root.path());
        let principal = PrincipalId::new("alice").unwrap();
        let uid = PrincipalUid::from_bytes([0x31; 32]);
        let directory = PrincipalDirectory::default();
        directory.register(principal, uid).unwrap();
        let quota: Arc<dyn KvQuotaResolver<StateOwner>> =
            Arc::new(|_owner: &StateOwner| Ok(Some(u64::MAX)));
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let store = Arc::new(
            runtime
                .block_on(open_runtime_principal_store_with_directory(
                    &home, quota, directory,
                ))
                .unwrap(),
        );
        (root, store, uid)
    }

    #[test]
    fn storage_manifest_checks_use_registry_when_native_home_is_empty() {
        let (_root, store, uid) = test_store();
        let owner = StateOwner::Principal(uid);
        store
            .capsules()
            .install(
                &owner,
                "provider",
                &package_with_export("provider"),
                CapsuleInstallExpectation::Absent,
            )
            .unwrap();
        let candidate: CapsuleManifest = toml::from_str(&(
            "[package]\nname = \"consumer\"\nversion = \"1.0.0\"\n\n"
                .to_owned()
                + "[imports.astrid]\nsession = \"^1.0\"\n\n[exports.astrid]\nsession = \"1.3.0\"\n"
        ))
        .unwrap();
        assert!(
            validate_imports_in_storage(&candidate, &store, uid)
                .unwrap()
                .is_empty()
        );
        let conflicts = check_export_conflicts_in_storage(&candidate, &store, uid).unwrap();
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].existing_capsule, "provider");
    }
}
