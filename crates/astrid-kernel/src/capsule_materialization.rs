//! Durable capsule publication binding and canonical projection repair.

use std::path::Path;

use super::{BoundMaterialization, Kernel, authenticated_ancestor_directories};

impl Kernel {
    /// Verify every projected byte against one immutable package snapshot.
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    pub(crate) fn verify_published_materialization(
        &self,
        dir: &Path,
        principal: &astrid_core::principal::PrincipalId,
        manifest: &astrid_capsule_types::manifest::CapsuleManifest,
        snapshot: &astrid_storage::CapsulePackageSnapshot,
    ) -> anyhow::Result<()> {
        self.validate_published_cache_path(dir, principal, manifest, snapshot)?;
        let uid = self
            .principal_directory
            .uid_for(principal)
            .map_err(|error| anyhow::anyhow!("resolve capsule cache owner UID: {error}"))?;
        let verified = astrid_capsule_install::read_verified_durable_package_for_owner(
            self.principal_store
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("durable capsule registry is unavailable"))?,
            &astrid_storage::StateOwner::Principal(uid),
            manifest.package.name.as_str(),
        )?
        .ok_or_else(|| anyhow::anyhow!("materialized capsule is absent from durable registry"))?;
        if verified.snapshot() != snapshot {
            anyhow::bail!("materialized capsule snapshot differs from the caller's publication");
        }
        if verified.manifest().package.name != manifest.package.name
            || verified.manifest().package.version != manifest.package.version
        {
            anyhow::bail!("materialized capsule manifest differs from durable registry");
        }
        let manifest_bytes = Self::read_projection_file_nofollow(&dir.join("Capsule.toml"))
            .map_err(|error| anyhow::anyhow!("read materialized capsule manifest: {error:#}"))?;
        if manifest_bytes != verified.manifest_bytes() {
            anyhow::bail!("durable capsule manifest bytes do not match materialization");
        }
        let metadata_bytes = Self::read_projection_file_nofollow(&dir.join("meta.json"))
            .map_err(|error| anyhow::anyhow!("read materialized capsule metadata: {error:#}"))?;
        if metadata_bytes != verified.metadata_bytes() {
            anyhow::bail!("durable capsule metadata does not match materialization");
        }
        let authority_bytes = Self::read_projection_file_nofollow(&dir.join("authority.json"))
            .map_err(|error| anyhow::anyhow!("read materialized capsule authority: {error:#}"))?;
        if authority_bytes != verified.snapshot().package().authority {
            anyhow::bail!("durable capsule authority bytes do not match materialization");
        }
        let mut expected_files = verified
            .archive_entries()
            .map(|(path, bytes)| (path.to_owned(), bytes.to_vec()))
            .collect::<std::collections::BTreeMap<_, _>>();
        expected_files.insert(
            "Capsule.toml".to_owned(),
            verified.manifest_bytes().to_vec(),
        );
        expected_files.insert("meta.json".to_owned(), verified.metadata_bytes().to_vec());
        expected_files.insert(
            "authority.json".to_owned(),
            verified.snapshot().package().authority.clone(),
        );
        let actual = Self::inventory_projection_files(dir)?;
        if actual.files
            != expected_files
                .keys()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>()
        {
            anyhow::bail!("materialized capsule file inventory differs from durable package");
        }
        let mut expected_directories = expected_files
            .keys()
            .flat_map(|relative| authenticated_ancestor_directories(relative))
            .collect::<std::collections::BTreeSet<_>>();
        let archive_directories = verified
            .archive_directories()
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        expected_directories.extend(archive_directories.iter().cloned());
        expected_directories.extend(
            archive_directories
                .iter()
                .map(String::as_str)
                .flat_map(authenticated_ancestor_directories),
        );
        if actual.directories != expected_directories {
            anyhow::bail!("materialized capsule directory inventory differs from durable package");
        }
        for (relative, expected) in &expected_files {
            let materialized =
                Self::read_projection_file_nofollow(&dir.join(relative)).map_err(|error| {
                    anyhow::anyhow!("read materialized capsule member {relative}: {error}")
                })?;
            if materialized != *expected {
                anyhow::bail!(
                    "materialized capsule member {relative} differs from durable archive"
                );
            }
        }
        let expansions = manifest
            .capabilities
            .expansions_from(&verified.authority().approved_capabilities);
        if !expansions.is_empty() {
            anyhow::bail!("materialized capsule manifest exceeds durable authority approval");
        }
        Ok(())
    }

    /// Bind durable activation or authorize the explicit workspace portal.
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    pub(crate) fn capture_bound_materialization(
        &self,
        dir: &Path,
        principal: &astrid_core::principal::PrincipalId,
        manifest: &astrid_capsule_types::manifest::CapsuleManifest,
        operation: &str,
    ) -> anyhow::Result<Option<BoundMaterialization>> {
        let snapshot = self.published_capsule_snapshot(principal, manifest)?;
        if let Some(snapshot) = snapshot {
            let runtime_dir = self.published_cache_target(principal, manifest, &snapshot)?;
            let bound_manifest = self.repair_published_materialization(
                &runtime_dir,
                principal,
                manifest,
                &snapshot,
            )?;
            return Ok(Some(BoundMaterialization {
                snapshot,
                runtime_dir,
                manifest: bound_manifest,
            }));
        }
        if !self.verify_registry_materialization(dir, principal, manifest)? {
            if self.principal_store.is_some()
                && !dir.starts_with(self.workspace_selection.state_dir())
            {
                anyhow::bail!(
                    "capsule {operation} '{}' is outside the explicit workspace portal and \
                     has no durable registry authority",
                    manifest.package.name
                );
            }
            self.verify_installed_authority_for_runtime(dir, manifest).map_err(|error| {
                anyhow::anyhow!(
                    "capsule {operation} '{}' exceeds or cannot prove its installed authority: {error:#}",
                    manifest.package.name
                )
            })?;
        }
        Ok(None)
    }

    /// Repair a stale or missing cache generation from one exact snapshot.
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    pub(crate) fn ensure_published_materialization(
        &self,
        target: &Path,
        principal: &astrid_core::principal::PrincipalId,
        manifest: &astrid_capsule_types::manifest::CapsuleManifest,
        snapshot: &astrid_storage::CapsulePackageSnapshot,
    ) -> anyhow::Result<astrid_capsule_types::manifest::CapsuleManifest> {
        self.repair_published_materialization(target, principal, manifest, snapshot)
    }

    /// Replace a canonical stale projection without trusting the old manifest.
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    pub(crate) fn repair_published_materialization(
        &self,
        target: &Path,
        principal: &astrid_core::principal::PrincipalId,
        discovery_manifest: &astrid_capsule_types::manifest::CapsuleManifest,
        snapshot: &astrid_storage::CapsulePackageSnapshot,
    ) -> anyhow::Result<astrid_capsule_types::manifest::CapsuleManifest> {
        self.validate_published_cache_path(target, principal, discovery_manifest, snapshot)?;
        let target_metadata = match std::fs::symlink_metadata(target) {
            Ok(metadata) => Some(metadata),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(anyhow::anyhow!("inspect capsule materialization: {error}")),
        };
        if let Some(metadata) = target_metadata {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                anyhow::bail!("capsule materialization target is redirected or not a directory");
            }
            if let Ok(bound_manifest) =
                astrid_capsule::discovery::load_manifest(&target.join("Capsule.toml"))
                && self
                    .verify_published_materialization(target, principal, &bound_manifest, snapshot)
                    .is_ok()
            {
                return Ok(bound_manifest);
            }
            astrid_core::platform_fs::verify_no_redirects(target).map_err(|error| {
                anyhow::anyhow!("capsule materialization target is redirected: {error}")
            })?;
            std::fs::remove_dir_all(target).map_err(|error| {
                anyhow::anyhow!("remove stale capsule materialization: {error}")
            })?;
        }
        astrid_capsule_install::materialize_capsule_package(snapshot.package(), target)
            .map_err(|error| anyhow::anyhow!("materialize durable capsule package: {error:#}"))?;
        let bound_manifest = astrid_capsule::discovery::load_manifest(&target.join("Capsule.toml"))
            .map_err(|error| anyhow::anyhow!(error))?;
        self.verify_published_materialization(target, principal, &bound_manifest, snapshot)?;
        Ok(bound_manifest)
    }

    /// Recheck the immutable publication after taking activation locks.
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    pub(crate) fn confirm_published_materialization(
        &self,
        dir: &Path,
        principal: &astrid_core::principal::PrincipalId,
        manifest: &astrid_capsule_types::manifest::CapsuleManifest,
        snapshot: &astrid_storage::CapsulePackageSnapshot,
    ) -> anyhow::Result<()> {
        let current = self.published_capsule_snapshot(principal, manifest)?;
        if current.as_ref() != Some(snapshot) {
            anyhow::bail!(
                "capsule '{}' changed while activation was in progress",
                manifest.package.name
            );
        }
        self.verify_published_materialization(dir, principal, manifest, snapshot)
    }
}
