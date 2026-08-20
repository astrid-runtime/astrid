//! Bounded legacy capsule and control-state migration helpers.

use std::fs;
use std::io;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, bail};
use astrid_build::artifact;
use astrid_core::PrincipalId;
use astrid_storage::{
    CapsuleInstallExpectation, CapsulePackage, RuntimePrincipalStore, StateOwner,
};

use crate::authority::{
    LegacyAuthorityReceiptStatus, legacy_authority_receipt_status, read_installed_authority,
    read_installed_authority_bytes, rebind_relocated_legacy_authority_receipt,
    retire_legacy_authority_receipt, verify_installed_authority,
};
use crate::meta::CapsuleMeta;

use super::{canonical_legacy_archive, read_dir_sorted, read_verified_durable_package_for_owner};

/// One exact legacy authority receipt retired after its durable package was
/// read back and verified.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LegacyCapsuleAuthorityReceipt {
    /// Immutable owner UID that owned the native capsule source.
    pub uid: astrid_core::identity::PrincipalUid,
    /// Capsule identifier covered by the receipt.
    pub capsule_id: String,
    /// BLAKE3 digest of the exact serialized authority receipt bytes.
    pub authority_digest: String,
}

/// Immutable report returned by a complete native capsule migration pass.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LegacyCapsuleMigrationReport {
    /// Exact per-package authority receipts retired by the pass.
    pub retired_authorities: Vec<LegacyCapsuleAuthorityReceipt>,
}

impl LegacyCapsuleMigrationReport {
    /// Return a canonical, source-bound destination proof for the migration
    /// ledger. The per-package rows are sorted before hashing so aliases and
    /// directory iteration order cannot change the receipt.
    #[must_use]
    pub fn canonical_proof(&self, source_digest: &str) -> String {
        let mut rows = self.retired_authorities.clone();
        rows.sort();
        let mut canonical = String::new();
        for row in &rows {
            canonical.push_str(&row.uid.to_string());
            canonical.push('\t');
            canonical.push_str(&row.capsule_id);
            canonical.push('\t');
            canonical.push_str(&row.authority_digest);
            canonical.push('\n');
        }
        let digest = blake3::hash(canonical.as_bytes()).to_hex();
        format!(
            "verified-capsule-authority-v1:source-digest={source_digest}:count={}:rows-digest={digest}",
            rows.len()
        )
    }
}

/// Migrate legacy native `.local/capsules` packages for one principal.
pub fn migrate_native_capsules(
    store: &Arc<RuntimePrincipalStore>,
    home: &astrid_core::dirs::AstridHome,
    principal: &PrincipalId,
) -> anyhow::Result<Vec<String>> {
    Ok(migrate_native_capsules_with_report(store, home, principal)?
        .retired_authorities
        .into_iter()
        .map(|receipt| receipt.capsule_id)
        .collect())
}

/// Migrate one principal's native capsule packages and return the exact
/// authority receipts retired by the pass.
#[allow(
    clippy::too_many_lines,
    reason = "migration keeps its ordered readback and retirement fence together"
)]
pub fn migrate_native_capsules_with_report(
    store: &Arc<RuntimePrincipalStore>,
    home: &astrid_core::dirs::AstridHome,
    principal: &PrincipalId,
) -> anyhow::Result<LegacyCapsuleMigrationReport> {
    let uid = store
        .principal_directory()
        .uid_for(principal)
        .with_context(|| format!("resolve durable uid for principal {principal}"))?;
    let native = home.principal_home(principal).capsules_dir();
    let metadata = match fs::symlink_metadata(&native) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(LegacyCapsuleMigrationReport::default());
        },
        Err(error) => return Err(error).with_context(|| format!("inspect {}", native.display())),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!(
            "legacy capsule directory is not a regular directory: {}",
            native.display()
        );
    }
    astrid_core::platform_fs::verify_no_redirects(&native)
        .with_context(|| format!("verify legacy capsule root {}", native.display()))?;
    let mut children = read_dir_sorted(&native)?;
    let mut report = LegacyCapsuleMigrationReport::default();
    let registry = store.capsules();
    let owner = StateOwner::Principal(uid);
    for (target, target_metadata) in children.drain(..) {
        if target_metadata.file_type().is_symlink() || !target_metadata.is_dir() {
            bail!(
                "legacy capsule entry is not a regular directory: {}",
                target.display()
            );
        }
        let id = target
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| anyhow::anyhow!("legacy capsule entry has a non-UTF-8 name"))?;
        let manifest = astrid_capsule::discovery::load_manifest(&target.join("Capsule.toml"))
            .with_context(|| format!("read legacy capsule manifest {id}"))?;
        if manifest.package.name != id {
            bail!(
                "legacy capsule directory {id} does not match manifest id {}",
                manifest.package.name
            );
        }
        let meta_bytes = fs::read(target.join("meta.json"))
            .with_context(|| format!("read legacy capsule metadata {id}"))?;
        let meta: CapsuleMeta = serde_json::from_slice(&meta_bytes)
            .with_context(|| format!("decode legacy capsule metadata {id}"))?;
        if meta.version != manifest.package.version {
            bail!("legacy capsule metadata version differs for {id}");
        }
        // Released pre-authority installs are admitted only through the
        // existing one-time verifier. It pins their exact manifest,
        // capabilities, and executable before any durable publication.
        // Relocated homes keep receipts hashed from a previous absolute
        // path; rebind a unique leftover onto this target first.
        rebind_relocated_legacy_authority_receipt(home, &target, &manifest)
            .with_context(|| format!("rebind relocated leftover authority for {id}"))?;
        verify_installed_authority(home, &target, &manifest)
            .with_context(|| format!("verify legacy capsule authority {id}"))?;
        let authority = read_installed_authority(home, &target)?.ok_or_else(|| {
            anyhow::anyhow!("legacy capsule {id} authority verification produced no receipt")
        })?;
        if authority.capsule_id != id || authority.version != manifest.package.version {
            bail!("legacy capsule authority identity differs for {id}");
        }
        let source_authority_bytes = read_installed_authority_bytes(home, &target)?
            .ok_or_else(|| anyhow::anyhow!("legacy capsule {id} authority receipt disappeared"))?;
        let archive = canonical_legacy_archive(home, &target, &meta, &manifest)?;
        let verification = artifact::verify_archive_bytes(&archive)
            .with_context(|| format!("verify canonical legacy capsule archive {id}"))?;
        let mut durable_authority = authority;
        verification
            .content_digest()
            .clone_into(&mut durable_authority.content_digest);
        let durable_authority_bytes = serde_json::to_vec_pretty(&durable_authority)
            .with_context(|| format!("serialize durable legacy capsule authority {id}"))?;
        let package = CapsulePackage::new(archive, meta_bytes, durable_authority_bytes);
        let expectation = match registry.get_snapshot(&owner, id)? {
            None => CapsuleInstallExpectation::Absent,
            Some(snapshot) if snapshot.package() == &package => {
                CapsuleInstallExpectation::Generation(snapshot.generation())
            },
            Some(_) => bail!("durable capsule {id} conflicts with legacy native content"),
        };
        registry.install(&owner, id, &package, expectation)?;
        let readback = registry
            .get_snapshot(&owner, id)?
            .ok_or_else(|| anyhow::anyhow!("durable capsule {id} disappeared after publish"))?;
        if readback.package() != &package {
            bail!("durable capsule {id} failed byte-for-byte readback");
        }
        read_verified_durable_package_for_owner(store, &owner, id)?.ok_or_else(|| {
            anyhow::anyhow!("durable capsule {id} failed authoritative verification")
        })?;
        astrid_core::platform_fs::verify_no_redirects(&target)
            .with_context(|| format!("verify legacy capsule {id} before retirement"))?;
        let final_archive = canonical_legacy_archive(home, &target, &meta, &manifest)?;
        if final_archive != package.archive {
            bail!("legacy capsule {id} changed before retirement");
        }
        if fs::read(target.join("meta.json"))? != package.metadata {
            bail!("legacy capsule {id} metadata changed before retirement");
        }
        if read_installed_authority_bytes(home, &target)?.as_deref()
            != Some(source_authority_bytes.as_slice())
        {
            bail!("legacy capsule {id} authority changed before retirement");
        }
        astrid_core::platform_fs::verify_no_redirects(&target)
            .with_context(|| format!("verify legacy capsule {id} retirement boundary"))?;
        astrid_core::dirs::retire_legacy_source_tree(&target)
            .with_context(|| format!("retire migrated legacy capsule {id}"))?;
        retire_legacy_authority_receipt(home, &target, &source_authority_bytes)
            .with_context(|| format!("retire migrated legacy capsule {id} authority"))?;
        report
            .retired_authorities
            .push(LegacyCapsuleAuthorityReceipt {
                uid,
                capsule_id: id.to_owned(),
                authority_digest: blake3::hash(&package.authority).to_hex().to_string(),
            });
    }
    Ok(report)
}

/// Inspect global legacy authority receipts after capsule migration.
///
/// Native principal receipts are retired by [`migrate_native_capsules`].
/// Explicit workspace portal receipts may remain and must be listed in
/// `workspace_targets`; every other active, pending, or previous receipt is
/// returned for the boot barrier to reject.
pub fn legacy_capsule_authority_status(
    home: &astrid_core::dirs::AstridHome,
    workspace_targets: &[std::path::PathBuf],
) -> anyhow::Result<LegacyAuthorityReceiptStatus> {
    legacy_authority_receipt_status(home, workspace_targets)
}

/// Import legacy capsule directories for every currently admitted principal.
pub fn migrate_all_native_capsules(
    store: &Arc<RuntimePrincipalStore>,
    home: &astrid_core::dirs::AstridHome,
    directory: &astrid_storage::PrincipalDirectory,
) -> anyhow::Result<Vec<(astrid_core::identity::PrincipalUid, Vec<String>)>> {
    let report = migrate_all_native_capsules_with_report(store, home, directory)?;
    let mut migrated =
        std::collections::BTreeMap::<astrid_core::identity::PrincipalUid, Vec<String>>::new();
    for receipt in report.retired_authorities {
        migrated
            .entry(receipt.uid)
            .or_default()
            .push(receipt.capsule_id);
    }
    Ok(migrated.into_iter().collect())
}

/// Import legacy capsule directories for every admitted principal and return
/// a canonical authority-retirement proof for the barrier ledger.
pub fn migrate_all_native_capsules_with_report(
    store: &Arc<RuntimePrincipalStore>,
    home: &astrid_core::dirs::AstridHome,
    directory: &astrid_storage::PrincipalDirectory,
) -> anyhow::Result<LegacyCapsuleMigrationReport> {
    const MAX_PRINCIPALS_PER_PASS: usize = 4096;
    let bindings = directory.bindings();
    if bindings.len() > MAX_PRINCIPALS_PER_PASS {
        bail!(
            "legacy capsule migration exceeds the bounded principal limit ({MAX_PRINCIPALS_PER_PASS})"
        );
    }
    let mut report = LegacyCapsuleMigrationReport::default();
    for (alias, _uid) in bindings {
        let principal_report = migrate_native_capsules_with_report(store, home, &alias)?;
        report
            .retired_authorities
            .extend(principal_report.retired_authorities);
    }
    report.retired_authorities.sort();
    Ok(report)
}

/// Receipt status for one admitted principal's legacy env/secret boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegacyEnvSecretImportStatus {
    /// Stable owner identity checked by the status report.
    pub uid: astrid_core::identity::PrincipalUid,
    /// Alias used only to inspect the released-home source paths.
    pub alias: PrincipalId,
    /// Whether the legacy per-principal env directory still has entries.
    pub native_env_present: bool,
    /// Whether the legacy per-principal secret root still has entries.
    pub native_secret_present: bool,
    /// Durable capsule scopes that do not carry a completed import receipt.
    pub unreceipted_capsules: Vec<String>,
}

/// Inspect legacy env/secret retirement completeness for every admitted UID.
pub async fn legacy_env_secret_import_status(
    store: &RuntimePrincipalStore,
    home: &astrid_core::dirs::AstridHome,
    directory: &astrid_storage::PrincipalDirectory,
) -> anyhow::Result<Vec<LegacyEnvSecretImportStatus>> {
    const MAX_PRINCIPALS_PER_PASS: usize = 4096;
    let bindings = directory.bindings();
    if bindings.len() > MAX_PRINCIPALS_PER_PASS {
        bail!(
            "legacy env/secret status exceeds the bounded principal limit ({MAX_PRINCIPALS_PER_PASS})"
        );
    }
    let mut statuses = Vec::with_capacity(bindings.len());
    for (alias, uid) in bindings {
        let principal_home = home.principal_home(&alias);
        astrid_core::platform_fs::verify_no_redirects(principal_home.root())
            .with_context(|| format!("verify legacy principal root for {alias}"))?;
        let native_env_present = legacy_entries_present(&principal_home.env_dir())?;
        let native_secret_present =
            legacy_entries_present(&home.secrets_dir().join(alias.as_str()))?;
        let owner = StateOwner::Principal(uid);
        let mut unreceipted_capsules = Vec::new();
        for summary in store.capsules().list(&owner)? {
            let scope = astrid_storage::env::principal_env_store(store.kv(), uid, summary.id())?;
            if scope
                .get(astrid_storage::env::LEGACY_IMPORT_MARKER_KEY)
                .await?
                .is_none()
            {
                unreceipted_capsules.push(summary.id().to_owned());
            }
        }
        statuses.push(LegacyEnvSecretImportStatus {
            uid,
            alias,
            native_env_present,
            native_secret_present,
            unreceipted_capsules,
        });
    }
    Ok(statuses)
}

fn legacy_entries_present(path: &Path) -> anyhow::Result<bool> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error).with_context(|| format!("inspect {}", path.display())),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!(
            "legacy env/secret path is not a regular directory: {}",
            path.display()
        );
    }
    let mut entries = fs::read_dir(path).with_context(|| format!("read {}", path.display()))?;
    Ok(entries.next().transpose()?.is_some())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use astrid_core::identity::PrincipalUid;
    use astrid_storage::{
        KvQuotaResolver, PrincipalDirectory, StateOwner,
        open_runtime_principal_store_with_directory,
    };

    use super::*;

    #[test]
    fn migrates_released_capsule_without_authority_receipt() {
        let temp = tempfile::tempdir().unwrap();
        let home = astrid_core::dirs::AstridHome::from_path(temp.path().join("home"));
        home.ensure().unwrap();
        let principal = PrincipalId::default();
        let uid = PrincipalUid::from_bytes([0x31; 32]);
        let directory = PrincipalDirectory::default();
        directory.register(principal.clone(), uid).unwrap();
        let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|owner: &StateOwner| {
            Ok(match owner {
                StateOwner::System => None,
                StateOwner::Principal(_) | StateOwner::Fleet(_) => Some(u64::MAX),
            })
        });
        let store = Arc::new(
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(open_runtime_principal_store_with_directory(
                    &home, quota, directory,
                ))
                .unwrap(),
        );
        store
            .principal_directory()
            .register(principal.clone(), uid)
            .unwrap();
        let target = home
            .principal_home(&principal)
            .capsules_dir()
            .join("released-capsule");
        astrid_core::platform_fs::ensure_private_directory(&target).unwrap();
        fs::write(
            target.join("Capsule.toml"),
            "[package]\nname = \"released-capsule\"\nversion = \"1.0.0\"\n",
        )
        .unwrap();
        let metadata = CapsuleMeta {
            version: "1.0.0".to_owned(),
            ..CapsuleMeta::default()
        };
        fs::write(
            target.join("meta.json"),
            serde_json::to_vec_pretty(&metadata).unwrap(),
        )
        .unwrap();
        assert!(read_installed_authority(&home, &target).unwrap().is_none());

        let report = migrate_native_capsules_with_report(&store, &home, &principal).unwrap();

        assert_eq!(report.retired_authorities.len(), 1);
        assert_eq!(report.retired_authorities[0].uid, uid);
        assert_eq!(report.retired_authorities[0].capsule_id, "released-capsule");
        assert!(!target.exists());
        assert!(read_installed_authority(&home, &target).unwrap().is_none());
        let durable = read_verified_durable_package_for_owner(
            &store,
            &StateOwner::Principal(uid),
            "released-capsule",
        )
        .unwrap()
        .expect("released capsule should be durable after migration");
        assert_eq!(
            durable.authority().source,
            crate::authority::AuthoritySource::LegacyMigration
        );
    }

    fn explicit_receipt(
        capsule_id: &str,
        content_digest: &str,
        manifest_digest: &str,
    ) -> crate::authority::InstalledAuthority {
        use crate::authority::{
            ArtifactProvenance, AuthorityDecision, InstallInspection, authorize_install,
        };
        authorize_install(
            &InstallInspection {
                capsule_id: astrid_capsule::capsule::CapsuleId::new(capsule_id).unwrap(),
                version: "1.0.0".into(),
                content_digest: content_digest.into(),
                provenance: ArtifactProvenance::Unsigned,
                capability_expansions: Vec::new(),
                manifest_digest: manifest_digest.into(),
                requested_capabilities: astrid_capsule::manifest::CapabilitiesDef::default(),
            },
            &AuthorityDecision::ExplicitApproval {
                content_digest: content_digest.into(),
            },
        )
        .unwrap()
    }

    fn test_store(
        home: &astrid_core::dirs::AstridHome,
        directory: PrincipalDirectory,
    ) -> Arc<astrid_storage::RuntimePrincipalStore> {
        let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|owner: &StateOwner| {
            Ok(match owner {
                StateOwner::System => None,
                StateOwner::Principal(_) | StateOwner::Fleet(_) => Some(u64::MAX),
            })
        });
        Arc::new(
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(open_runtime_principal_store_with_directory(
                    home, quota, directory,
                ))
                .unwrap(),
        )
    }

    #[test]
    fn relocated_path_hashed_receipts_are_ingested_or_quarantined() {
        use crate::authority::{
            AuthorityReceiptTransaction, AuthoritySource, authority_paths, digest_manifest,
            legacy_authority_receipt_status,
        };
        use crate::retire_unmatched_legacy_authority_receipts;

        let temp = tempfile::tempdir().unwrap();
        let home = astrid_core::dirs::AstridHome::from_path(temp.path().join("home"));
        home.ensure().unwrap();
        let principal = PrincipalId::default();
        let uid = PrincipalUid::from_bytes([0x31; 32]);
        let directory = PrincipalDirectory::default();
        directory.register(principal.clone(), uid).unwrap();
        let store = test_store(&home, directory.clone());
        store
            .principal_directory()
            .register(principal.clone(), uid)
            .unwrap();

        let current = home
            .principal_home(&principal)
            .capsules_dir()
            .join("released-capsule");
        astrid_core::platform_fs::ensure_private_directory(&current).unwrap();
        let manifest_body = "[package]\nname = \"released-capsule\"\nversion = \"1.0.0\"\n";
        fs::write(current.join("Capsule.toml"), manifest_body).unwrap();
        let metadata = CapsuleMeta {
            version: "1.0.0".to_owned(),
            ..CapsuleMeta::default()
        };
        fs::write(
            current.join("meta.json"),
            serde_json::to_vec_pretty(&metadata).unwrap(),
        )
        .unwrap();
        let native_authority = explicit_receipt(
            "released-capsule",
            "abc",
            &digest_manifest(manifest_body.as_bytes()),
        );
        AuthorityReceiptTransaction::stage(
            &home,
            &temp.path().join("previous-prefix/released-capsule"),
            &native_authority,
        )
        .unwrap()
        .commit()
        .unwrap();

        let ghost_target = temp.path().join("previous-prefix/ghost-capsule");
        let ghost_authority = explicit_receipt("ghost-capsule", "def", "ghost-manifest");
        AuthorityReceiptTransaction::stage(&home, &ghost_target, &ghost_authority)
            .unwrap()
            .commit()
            .unwrap();
        let ghost_bytes = fs::read(authority_paths(&home, &ghost_target).unwrap().active).unwrap();

        let report = migrate_native_capsules_with_report(&store, &home, &principal).unwrap();
        assert_eq!(report.retired_authorities.len(), 1);
        assert_eq!(report.retired_authorities[0].capsule_id, "released-capsule");
        retire_unmatched_legacy_authority_receipts(&store, &home, &directory, &[]).unwrap();

        let status = legacy_authority_receipt_status(&home, &[]).unwrap();
        assert!(status.unknown_active.is_empty() && status.pending.is_empty());
        let durable = read_verified_durable_package_for_owner(
            &store,
            &StateOwner::Principal(uid),
            "released-capsule",
        )
        .unwrap()
        .expect("native capsule must be durable");
        assert_eq!(
            durable.authority().source,
            AuthoritySource::ExplicitApproval
        );
        let quarantine = home
            .migrations_dir()
            .join("unmatched-legacy-capsule-authority");
        let quarantined = fs::read_dir(&quarantine)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
            .collect::<Vec<_>>();
        assert_eq!(quarantined.len(), 1);
        assert_eq!(fs::read(&quarantined[0]).unwrap(), ghost_bytes);
    }
}
