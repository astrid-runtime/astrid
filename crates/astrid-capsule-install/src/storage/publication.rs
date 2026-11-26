//! Publish directory and archive packages to the immutable owner's registry.

use std::fs;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, bail};
use astrid_build::artifact;
use astrid_core::PrincipalId;
use astrid_storage::{CapsulePackage, CapsulePackageGeneration, RuntimePrincipalStore, StateOwner};

use super::{
    authority_capsule_id, canonical_capsule_archive, expectation, manifest_identity,
    materialize_capsule_package, read_verified_durable_package,
};
use crate::authority::InstalledAuthority;
use crate::meta::CapsuleMeta;

/// Publish one source directory into the target principal's durable registry.
///
/// The source tree is canonicalized to a deterministic gzip/tar archive. The
/// package is committed as one content batch; a failed publication therefore
/// leaves the prior package authoritative. Existing durable content is used as
/// the expected generation for upgrades, so a stale installer receives a
/// conflict instead of silently overwriting a concurrent update.
pub fn publish_directory_package(
    store: &Arc<RuntimePrincipalStore>,
    principal: &PrincipalId,
    source_dir: &Path,
    target_dir: &Path,
    meta: &CapsuleMeta,
    authority: &InstalledAuthority,
    expected_generation: Option<CapsulePackageGeneration>,
) -> anyhow::Result<()> {
    let uid = store
        .principal_directory()
        .uid_for(principal)
        .with_context(|| format!("resolve durable uid for principal {principal}"))?;
    publish_directory_package_for_uid(
        store,
        uid,
        source_dir,
        target_dir,
        meta,
        authority,
        expected_generation,
    )
}

pub(crate) fn publish_directory_package_for_uid(
    store: &Arc<RuntimePrincipalStore>,
    uid: astrid_core::identity::PrincipalUid,
    source_dir: &Path,
    target_dir: &Path,
    meta: &CapsuleMeta,
    authority: &InstalledAuthority,
    expected_generation: Option<CapsulePackageGeneration>,
) -> anyhow::Result<()> {
    let (manifest_id, manifest_version) = manifest_identity(source_dir)?;
    if authority.capsule_id != manifest_id
        || authority.version != manifest_version
        || meta.version != authority.version
    {
        bail!("capsule metadata/authority does not match source manifest");
    }
    let archive = canonical_capsule_archive(source_dir)?;
    let verification = artifact::verify_archive_bytes(&archive)
        .context("verify canonical durable capsule archive")?;
    let mut durable_authority = authority.clone();
    // Directory approval binds the complete checked source tree, while the
    // durable package intentionally omits build/VCS/cache material. Rebind the
    // receipt to the deterministic package produced by that trusted transform;
    // the manifest/capability/WASM pins remain unchanged and are verified
    // again below before publication succeeds.
    verification
        .content_digest()
        .clone_into(&mut durable_authority.content_digest);
    let metadata = fs::read(target_dir.join("meta.json")).with_context(|| {
        format!(
            "read generated capsule metadata from {}",
            target_dir.display()
        )
    })?;
    let authority = serde_json::to_vec_pretty(&durable_authority)
        .context("serialize installed capsule authority receipt")?;
    let registry = store.capsules();
    let owner = StateOwner::Principal(uid);
    let id = authority_capsule_id(&authority)?;
    let expected = expectation::install_expectation(
        registry.get_snapshot(&owner, &id)?.as_ref(),
        expected_generation,
    );
    let package = CapsulePackage::new(archive, metadata, authority);
    let materialization = tempfile::Builder::new()
        .prefix(".capsule-materialization-")
        .tempdir_in(
            target_dir
                .parent()
                .ok_or_else(|| anyhow::anyhow!("capsule target has no parent"))?,
        )
        .context("stage verified durable capsule materialization")?;
    let staged_target = materialization.path().join("package");
    materialize_capsule_package(&package, &staged_target)
        .context("stage verified durable capsule package")?;

    // Storage-backed installs initially assemble a lifecycle workspace that
    // intentionally omits the WASM component. Replace it with the complete
    // verified package before publication so an immediately triggered live
    // reload sees the same bytes that a restart would rematerialize.
    let previous_target = materialization.path().join("previous");
    fs::rename(target_dir, &previous_target)
        .context("stage incomplete capsule install cache for replacement")?;
    if let Err(error) = fs::rename(&staged_target, target_dir) {
        let _ = fs::rename(&previous_target, target_dir);
        return Err(error).context("publish verified capsule materialization");
    }

    registry
        .install(&owner, &id, &package, expected)
        .with_context(|| format!("publish durable capsule package {id} for {uid}"))?;
    read_verified_durable_package(store, uid, &id)?
        .ok_or_else(|| anyhow::anyhow!("durable capsule {id} disappeared after publish"))?;
    Ok(())
}

/// Publish a package when the caller already has canonical bytes.
///
/// This is used by archive migration and by tests that have no source
/// directory to materialize. The caller must provide the immutable principal
/// UID, so alias reuse cannot redirect the package to a different owner.
pub fn publish_package(
    store: &Arc<RuntimePrincipalStore>,
    uid: astrid_core::identity::PrincipalUid,
    id: &str,
    package: &CapsulePackage,
) -> anyhow::Result<()> {
    publish_package_with_expected_generation(store, uid, id, package, None)
}

/// Publish a package, fail-closing when `expected_generation` no longer matches.
pub fn publish_package_with_expected_generation(
    store: &Arc<RuntimePrincipalStore>,
    uid: astrid_core::identity::PrincipalUid,
    id: &str,
    package: &CapsulePackage,
    expected_generation: Option<CapsulePackageGeneration>,
) -> anyhow::Result<()> {
    let owner = StateOwner::Principal(uid);
    let registry = store.capsules();
    let expected = expectation::install_expectation(
        registry.get_snapshot(&owner, id)?.as_ref(),
        expected_generation,
    );
    registry.install(&owner, id, package, expected)?;
    read_verified_durable_package(store, uid, id)?
        .ok_or_else(|| anyhow::anyhow!("durable capsule {id} disappeared after publish"))?;
    Ok(())
}
