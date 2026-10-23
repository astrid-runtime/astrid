//! Private independent projections copied from disposable matching bytes.
//!
//! A source projection supplies storage blocks, never owner authority. No new
//! artifact cache survives this operation; every published owner keeps its own
//! inode and exact durable sidecars.

#[cfg(target_os = "macos")]
use crate::Kernel;
#[cfg(target_os = "macos")]
use astrid_capsule_types::manifest::CapsuleManifest;
#[cfg(target_os = "macos")]
use astrid_core::PrincipalId;
#[cfg(target_os = "macos")]
use astrid_storage::CapsulePackageSnapshot;
#[cfg(target_os = "macos")]
use std::path::Path;

#[cfg(target_os = "macos")]
impl Kernel {
    pub(super) fn copy_published_projection(
        &self,
        target: &Path,
        principal: &PrincipalId,
        manifest: &CapsuleManifest,
        snapshot: &CapsulePackageSnapshot,
    ) -> anyhow::Result<Option<CapsuleManifest>> {
        let default = PrincipalId::default();
        if *principal == default {
            return Ok(None);
        }
        let source = self.published_cache_target(&default, manifest, snapshot)?;
        if !source.try_exists()? {
            return Ok(None);
        }
        astrid_core::platform_fs::verify_no_redirects(&source)?;
        let uid = self.principal_directory.uid_for(principal)?;
        let verified = astrid_capsule_install::read_verified_durable_package_for_owner(
            self.principal_store
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("durable registry is unavailable"))?,
            &astrid_storage::StateOwner::Principal(uid),
            manifest.package.name.as_str(),
        )?
        .ok_or_else(|| anyhow::anyhow!("target capsule package disappeared"))?;
        if verified.snapshot() != snapshot {
            anyhow::bail!("target capsule generation changed before projection copy");
        }
        let parent = target
            .parent()
            .ok_or_else(|| anyhow::anyhow!("projection has no parent"))?;
        astrid_core::platform_fs::ensure_private_directory(parent)?;
        let temporary = tempfile::tempdir_in(parent)?;
        let staged = temporary.path().join("projection");
        copy_members(&source, &staged, &verified)?;
        let bound_manifest = astrid_capsule::discovery::load_manifest(&staged.join("Capsule.toml"))
            .map_err(|error| anyhow::anyhow!(error))?;
        // Exact target-owner snapshot, inventory and every byte are checked.
        // The source's package version, metadata and authority confer nothing.
        self.verify_materialization_bytes(&staged, principal, &bound_manifest, snapshot)?;
        self.validate_published_cache_path(target, principal, &bound_manifest, snapshot)?;
        if target.try_exists()? {
            anyhow::bail!("projection appeared during private copy");
        }
        std::fs::rename(&staged, target)?;
        Ok(Some(bound_manifest))
    }
}

#[cfg(target_os = "macos")]
fn copy_members(
    source: &Path,
    destination: &Path,
    verified: &astrid_capsule_install::VerifiedDurableCapsulePackage,
) -> anyhow::Result<()> {
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::create_dir(destination)?;
    for relative in verified.archive_directories() {
        std::fs::create_dir_all(destination.join(relative))?;
    }
    for (relative, bytes) in verified.archive_entries() {
        // These exact sidecars are always written from the target snapshot.
        if matches!(relative, "meta.json" | "authority.json") {
            continue;
        }
        let path = source.join(relative);
        astrid_core::platform_fs::verify_no_redirects(&path)?;
        let opened = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC | nix::libc::O_NONBLOCK)
            .open(&path)?;
        let output = destination.join(relative);
        if let Some(parent) = output.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if !astrid_core::platform_fs::try_clone_file(&opened, &output)? {
            std::fs::write(&output, bytes)?;
        }
    }
    std::fs::write(destination.join("meta.json"), verified.metadata_bytes())?;
    std::fs::write(
        destination.join("authority.json"),
        &verified.snapshot().package().authority,
    )?;
    Ok(())
}

#[cfg(all(test, target_os = "macos"))]
mod tests;
