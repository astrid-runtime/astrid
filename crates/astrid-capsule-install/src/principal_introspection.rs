//! Typed installed-capsule introspection over the authoritative registry.
//!
//! Installed package metadata is owner-scoped Astrid content. This module
//! intentionally has no native-home mirror or recursive filesystem copy API:
//! callers receive verified archive/metadata/authority bytes and can render
//! their own read-only view without making a host directory authoritative.

use std::sync::Arc;

use crate::storage::{VerifiedDurableCapsulePackage, read_verified_durable_package};
use anyhow::Context;
use astrid_core::identity::PrincipalUid;
use astrid_package_service::ValidatedArtifact;
use astrid_storage::{RuntimePrincipalStore, StateOwner};

/// One package snapshot suitable for read-only introspection.
#[derive(Clone, Debug)]
pub struct DurableCapsuleIntrospection {
    /// Canonical capsule identifier.
    pub id: String,
    /// Verified archive/metadata/authority bytes from one durable snapshot.
    pub package: VerifiedDurableCapsulePackage,
    /// Canonical package-service artifact evidence for those exact bytes.
    pub artifact: ValidatedArtifact,
}

/// List every installed package for an immutable principal UID.
///
/// The UID must already be admitted by the runtime principal directory, and
/// aliases are resolved by the kernel before calling this function. Registry
/// discovery is prefix-scoped; malformed, partial, or stale package sets fail
/// closed.
///
/// # Errors
///
/// Returns an error when the owner content graph is unavailable, a reserved
/// package path is malformed, or a package disappears during readback.
pub fn list_durable_capsule_packages(
    store: &Arc<RuntimePrincipalStore>,
    uid: PrincipalUid,
) -> anyhow::Result<Vec<DurableCapsuleIntrospection>> {
    ensure_admitted_principal(store, uid)?;
    let owner = StateOwner::Principal(uid);
    let registry = store.capsules();
    registry
        .list(&owner)?
        .into_iter()
        .map(|summary| {
            let id = summary.id().to_owned();
            let package = read_verified_durable_package(store, uid, &id)?
                .ok_or_else(|| anyhow::anyhow!("capsule {id} disappeared during introspection"))?;
            anyhow::ensure!(
                package.snapshot().matches_summary(&id, &summary),
                "capsule {id} changed between summary and package readback"
            );
            let artifact = validated_artifact(&package)?;
            Ok(DurableCapsuleIntrospection {
                id,
                package,
                artifact,
            })
        })
        .collect()
}

/// Read one installed package by immutable UID and canonical identifier.
///
/// # Errors
///
/// Returns an error when the identifier is invalid, the package is absent or
/// malformed, or the owner content graph cannot be verified.
pub fn read_durable_capsule_package(
    store: &Arc<RuntimePrincipalStore>,
    uid: PrincipalUid,
    id: &str,
) -> anyhow::Result<DurableCapsuleIntrospection> {
    ensure_admitted_principal(store, uid)?;
    let package = read_verified_durable_package(store, uid, id)?
        .with_context(|| format!("durable capsule {id} is not installed"))?;
    let artifact = validated_artifact(&package)?;
    Ok(DurableCapsuleIntrospection {
        id: id.to_owned(),
        package,
        artifact,
    })
}

/// Read one package only when it is still the exact named generation.
///
/// # Errors
///
/// Returns an error when the UID is unadmitted, the package is absent or
/// malformed, or its current snapshot is no longer the expected generation.
pub fn read_durable_capsule_package_for_generation(
    store: &Arc<RuntimePrincipalStore>,
    uid: PrincipalUid,
    id: &str,
    expected: astrid_storage::CapsulePackageGeneration,
) -> anyhow::Result<DurableCapsuleIntrospection> {
    let introspection = read_durable_capsule_package(store, uid, id)?;
    anyhow::ensure!(
        introspection.package.snapshot().generation() == expected,
        "durable capsule {id} is no longer at the expected package generation"
    );
    Ok(introspection)
}

fn ensure_admitted_principal(
    store: &RuntimePrincipalStore,
    uid: PrincipalUid,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        store.principal_directory().contains_uid(uid),
        "principal UID {uid} is not an admitted durable identity"
    );
    Ok(())
}

fn validated_artifact(
    package: &VerifiedDurableCapsulePackage,
) -> anyhow::Result<ValidatedArtifact> {
    let artifact_digest = *blake3::hash(package.archive()).as_bytes();
    let manifest_digest = *blake3::hash(package.manifest_bytes()).as_bytes();
    let content_root: [u8; 32] = hex::decode(&package.authority().content_digest)
        .context("decode durable capsule content digest")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("durable capsule content digest is not 32 bytes"))?;
    let artifact_size = u64::try_from(package.archive().len())
        .context("durable capsule archive exceeds package-service bounds")?;
    let artifact_size = core::num::NonZeroU64::new(artifact_size)
        .ok_or_else(|| anyhow::anyhow!("durable capsule archive is empty"))?;
    ValidatedArtifact::new(
        astrid_package_service::ArtifactIdentity::from_bytes(artifact_digest)?,
        astrid_package_service::ManifestIdentity::from_bytes(manifest_digest)?,
        artifact_size,
        content_root,
    )
    .context("construct canonical package-service artifact evidence")
}

#[cfg(test)]
mod tests {
    use super::*;

    use astrid_build::artifact;
    use astrid_core::PrincipalId;
    use astrid_core::dirs::AstridHome;
    use astrid_storage::{
        CapsuleInstallExpectation, CapsulePackage, KvQuotaResolver, PrincipalDirectory, StateOwner,
        open_runtime_principal_store_with_directory,
    };
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use tar::Builder;

    use crate::authority::{AuthoritySource, InstalledAuthority, digest_manifest};
    use crate::meta::CapsuleMeta;

    fn uid(byte: u8) -> PrincipalUid {
        PrincipalUid::from_bytes([byte; 32])
    }

    fn package(id: &str, version: &str) -> CapsulePackage {
        let manifest = format!("[package]\nname = \"{id}\"\nversion = \"{version}\"\n");
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
            version: version.to_owned(),
            content_digest: verification.content_digest().to_owned(),
            manifest_digest: digest_manifest(manifest.as_bytes()),
            signer: None,
            signature: None,
            approved_capabilities: astrid_capsule::manifest::CapabilitiesDef::default(),
            wasm_hash_pinned: false,
            approved_wasm_hash: None,
        };
        let metadata = CapsuleMeta {
            version: version.to_owned(),
            ..Default::default()
        };
        CapsulePackage::new(
            archive,
            serde_json::to_vec(&metadata).unwrap(),
            serde_json::to_vec(&authority).unwrap(),
        )
    }

    fn unlimited_quota() -> Arc<dyn KvQuotaResolver<StateOwner>> {
        Arc::new(|owner: &StateOwner| {
            Ok(match owner {
                StateOwner::System => None,
                StateOwner::Principal(_) | StateOwner::Fleet(_) | StateOwner::User(_) => {
                    Some(u64::MAX)
                },
            })
        })
    }

    async fn store_with_uid(uid: PrincipalUid) -> (tempfile::TempDir, Arc<RuntimePrincipalStore>) {
        let root = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(root.path());
        let directory = PrincipalDirectory::default();
        directory
            .register(PrincipalId::new("owner").unwrap(), uid)
            .unwrap();
        let store = Arc::new(
            open_runtime_principal_store_with_directory(&home, unlimited_quota(), directory)
                .await
                .unwrap(),
        );
        store
            .principal_directory()
            .register(PrincipalId::new("owner").unwrap(), uid)
            .unwrap();
        (root, store)
    }

    fn invalid_package() -> CapsulePackage {
        CapsulePackage::new(
            b"not-a-capsule".to_vec(),
            br#"{"version":"1.0.0"}"#.to_vec(),
            br#"{"capsule_id":"demo-cap"}"#.to_vec(),
        )
    }

    #[tokio::test]
    async fn lists_and_reads_only_admitted_principal_packages() {
        let owner_uid = uid(1);
        let foreign_uid = uid(2);
        let (_root, store) = store_with_uid(owner_uid).await;
        let owner = StateOwner::Principal(owner_uid);
        store
            .capsules()
            .install(
                &owner,
                "demo-cap",
                &package("demo-cap", "1.0.0"),
                CapsuleInstallExpectation::Absent,
            )
            .unwrap();

        let listed = list_durable_capsule_packages(&store, owner_uid).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, "demo-cap");
        assert_eq!(listed[0].package.manifest().package.name, "demo-cap");
        assert_eq!(
            listed[0].artifact.content_root(),
            &hex::decode(&listed[0].package.authority().content_digest).unwrap()[..]
        );
        let read = read_durable_capsule_package(&store, owner_uid, "demo-cap").unwrap();
        assert_eq!(
            read.package.snapshot().generation(),
            listed[0].package.snapshot().generation()
        );
        assert!(
            !store_with_uid(foreign_uid)
                .await
                .1
                .principal_directory()
                .contains_uid(owner_uid)
        );
        assert!(list_durable_capsule_packages(&store, foreign_uid).is_err());
        assert!(read_durable_capsule_package(&store, foreign_uid, "demo-cap").is_err());
    }

    #[tokio::test]
    async fn stale_generation_is_rejected_but_current_snapshot_reads() {
        let owner_uid = uid(3);
        let (_root, store) = store_with_uid(owner_uid).await;
        let owner = StateOwner::Principal(owner_uid);
        let registry = store.capsules();
        registry
            .install(
                &owner,
                "demo-cap",
                &package("demo-cap", "1.0.0"),
                CapsuleInstallExpectation::Absent,
            )
            .unwrap();
        let first = read_durable_capsule_package(&store, owner_uid, "demo-cap")
            .unwrap()
            .package
            .snapshot()
            .generation();
        registry
            .install(
                &owner,
                "demo-cap",
                &package("demo-cap", "1.1.0"),
                CapsuleInstallExpectation::Any,
            )
            .unwrap();
        let current = read_durable_capsule_package(&store, owner_uid, "demo-cap")
            .unwrap()
            .package
            .snapshot()
            .generation();
        assert_ne!(first, current);
        let error =
            read_durable_capsule_package_for_generation(&store, owner_uid, "demo-cap", first)
                .unwrap_err();
        assert!(error.to_string().contains("expected package generation"));
        read_durable_capsule_package_for_generation(&store, owner_uid, "demo-cap", current)
            .unwrap();
    }

    #[tokio::test]
    async fn tampered_and_partial_catalog_sets_fail_closed() {
        let owner_uid = uid(4);
        let (_root, store) = store_with_uid(owner_uid).await;
        let owner = StateOwner::Principal(owner_uid);
        store
            .capsules()
            .install(
                &owner,
                "broken",
                &invalid_package(),
                CapsuleInstallExpectation::Absent,
            )
            .unwrap();
        assert!(read_durable_capsule_package(&store, owner_uid, "broken").is_err());
        assert!(list_durable_capsule_packages(&store, owner_uid).is_err());

        let name = astrid_storage::ContentName::new("capsules/partial/package.capsule").unwrap();
        store
            .content()
            .put(&owner, &name, b"orphan archive")
            .unwrap();
        assert!(list_durable_capsule_packages(&store, owner_uid).is_err());
    }
}
