//! Caller-scoped durable installed-capsule identity query.

use astrid_core::kernel_api::{
    InstalledCapsuleGeneration, InstalledCapsuleIdentity, KernelResponse,
};
use astrid_storage::StateOwner;

/// Read one complete durable package identity for the authenticated caller.
///
/// The owner is resolved exclusively from `caller`; the request never carries
/// a principal selector. A malformed or partially published package fails
/// closed, so the CLI cannot mistake it for a completed installation.
pub(super) fn handle(
    kernel: &crate::Kernel,
    caller: &astrid_core::PrincipalId,
    id: &str,
) -> KernelResponse {
    let capsule_id = match astrid_capsule_types::CapsuleId::new(id.to_owned()) {
        Ok(id) => id,
        Err(error) => {
            return KernelResponse::Error(format!("invalid capsule id '{id}': {error}"));
        },
    };
    let Some(store) = kernel.principal_store.as_ref() else {
        return KernelResponse::Error("durable capsule registry is unavailable".to_owned());
    };
    let owner_uid = match kernel.principal_directory.uid_for(caller) {
        Ok(uid) => uid,
        Err(error) => {
            return KernelResponse::Error(format!("resolve caller principal {caller}: {error}"));
        },
    };
    let owner = StateOwner::Principal(owner_uid);
    let snapshot = match store.capsules().get_snapshot(&owner, capsule_id.as_str()) {
        Ok(Some(snapshot)) => snapshot,
        Ok(None) => return KernelResponse::InstalledCapsuleIdentity(None),
        Err(error) => {
            return KernelResponse::Error(format!(
                "read durable capsule identity for {}: {error}",
                capsule_id.as_str()
            ));
        },
    };

    // The registry shape check rejects partial fixed-file sets. Verify the
    // archive, metadata, authority, and cross-field identity as well so
    // malformed complete-looking bytes are never completion proof.
    let verified = match astrid_capsule_install::read_verified_durable_package_for_owner(
        store,
        &owner,
        capsule_id.as_str(),
    ) {
        Ok(Some(package)) => package,
        Ok(None) => {
            return KernelResponse::Error(
                "durable capsule disappeared during identity read".to_owned(),
            );
        },
        Err(error) => {
            return KernelResponse::Error(format!(
                "verify durable capsule identity for {}: {error}",
                capsule_id.as_str()
            ));
        },
    };
    if verified.snapshot().generation() != snapshot.generation() {
        return KernelResponse::Error(format!(
            "durable capsule {} changed during identity read",
            capsule_id.as_str()
        ));
    }
    let generation = snapshot.generation();
    let identity = InstalledCapsuleIdentity {
        id: capsule_id.to_string(),
        generation: InstalledCapsuleGeneration {
            archive: hex::encode(generation.archive().as_bytes()),
            metadata: hex::encode(generation.metadata().as_bytes()),
            authority: hex::encode(generation.authority().as_bytes()),
        },
        archive_digest: blake3::hash(&snapshot.package().archive)
            .to_hex()
            .to_string(),
    };
    KernelResponse::InstalledCapsuleIdentity(Some(identity))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use astrid_capsule_install::{
        AuthorityDecision, CapsuleMeta, authorize_install, canonical_capsule_archive,
        inspect_directory_for_principal_in_workspace, publish_package,
    };
    use astrid_core::PrincipalId;
    use astrid_core::dirs::{AstridHome, WorkspaceLayout};
    use astrid_core::profile::PrincipalProfile;
    use astrid_storage::{CapsuleInstallExpectation, CapsulePackage, ContentName};

    async fn seed_principal(
        kernel: &crate::Kernel,
        home: &AstridHome,
        name: &str,
        uid: [u8; 32],
    ) -> PrincipalId {
        let principal = PrincipalId::new(name).expect("valid test principal");
        kernel
            .identity_store
            .create_principal(principal.clone(), uid)
            .await
            .expect("create test principal identity");
        PrincipalProfile::default()
            .save_to_path(&PrincipalProfile::path_for(home, &principal))
            .expect("save test principal profile");
        principal
    }

    fn package_for(
        kernel: &crate::Kernel,
        principal: &PrincipalId,
        id: &str,
    ) -> anyhow::Result<CapsulePackage> {
        let source = tempfile::tempdir()?;
        let manifest = format!("[package]\nname = \"{id}\"\nversion = \"1.0.0\"\n");
        std::fs::write(source.path().join("Capsule.toml"), manifest)?;
        let inspection = inspect_directory_for_principal_in_workspace(
            source.path(),
            &kernel.astrid_home,
            principal,
            false,
            None,
            &WorkspaceLayout::default(),
        )?;
        let authority = authorize_install(
            &inspection,
            &AuthorityDecision::ExplicitApproval {
                content_digest: inspection.content_digest.clone(),
            },
        )?;
        let archive = canonical_capsule_archive(source.path())?;
        let metadata = CapsuleMeta {
            version: inspection.version,
            ..Default::default()
        };
        let package = CapsulePackage::new(
            archive,
            serde_json::to_vec(&metadata)?,
            serde_json::to_vec(&authority)?,
        );
        let uid = kernel.principal_directory.uid_for(principal)?;
        let store = Arc::new(
            kernel
                .principal_store
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("test kernel has no durable store"))?
                .clone(),
        );
        publish_package(&store, uid, id, &package)?;
        Ok(package)
    }

    fn identity_response(response: KernelResponse) -> Option<InstalledCapsuleIdentity> {
        match response {
            KernelResponse::InstalledCapsuleIdentity(identity) => identity,
            other => panic!("unexpected installed identity response: {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn missing_identity_returns_explicit_absence() {
        let directory = tempfile::tempdir().expect("test home");
        let home = AstridHome::from_path(directory.path());
        let kernel = crate::test_kernel_with_home(home).await;

        assert!(
            identity_response(handle(&kernel, &PrincipalId::default(), "missing-capsule",))
                .is_none()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn malformed_and_partial_packages_fail_closed() {
        let directory = tempfile::tempdir().expect("test home");
        let home = AstridHome::from_path(directory.path());
        let kernel = crate::test_kernel_with_home(home).await;
        let principal = PrincipalId::default();
        let uid = kernel
            .principal_directory
            .uid_for(&principal)
            .expect("default principal UID");
        let owner = StateOwner::Principal(uid);
        let store = Arc::new(
            kernel
                .principal_store
                .as_ref()
                .expect("test kernel durable store")
                .clone(),
        );

        // The fixed files are present but their metadata/authority bytes are
        // not valid package records. This must never become completion proof.
        let source = tempfile::tempdir().expect("malformed source");
        std::fs::write(
            source.path().join("Capsule.toml"),
            "[package]\nname = \"malformed-capsule\"\nversion = \"1.0.0\"\n",
        )
        .expect("write malformed manifest");
        let archive = canonical_capsule_archive(source.path()).expect("canonical archive");
        let malformed = CapsulePackage::new(archive, b"{}".to_vec(), b"{}".to_vec());
        store
            .capsules()
            .install(
                &owner,
                "malformed-capsule",
                &malformed,
                CapsuleInstallExpectation::Absent,
            )
            .expect("publish malformed fixed files");
        assert!(matches!(
            handle(&kernel, &principal, "malformed-capsule"),
            KernelResponse::Error(_)
        ));

        // A package with one fixed file removed is a partial publication. The
        // registry rejects the snapshot before any identity can be returned.
        let _ = package_for(&kernel, &principal, "partial-capsule").expect("publish package");
        let authority_name = ContentName::new("capsules/partial-capsule/authority.json")
            .expect("authority content name");
        store
            .content()
            .delete(&owner, &authority_name)
            .expect("remove one fixed package file");
        assert!(matches!(
            handle(&kernel, &principal, "partial-capsule"),
            KernelResponse::Error(_)
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn identity_is_scoped_to_authenticated_caller_principal() {
        let directory = tempfile::tempdir().expect("test home");
        let home = AstridHome::from_path(directory.path());
        let kernel = crate::test_kernel_with_home(home.clone()).await;
        let principal_a = seed_principal(&kernel, &home, "identity-a", [0xA1; 32]).await;
        let principal_b = seed_principal(&kernel, &home, "identity-b", [0xB1; 32]).await;
        let _ = package_for(&kernel, &principal_a, "scoped-capsule").expect("publish package");

        assert!(identity_response(handle(&kernel, &principal_b, "scoped-capsule")).is_none());
        assert!(identity_response(handle(&kernel, &principal_a, "scoped-capsule")).is_some());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn returned_identity_binds_id_generation_and_archive_digest() {
        let directory = tempfile::tempdir().expect("test home");
        let home = AstridHome::from_path(directory.path());
        let kernel = crate::test_kernel_with_home(home).await;
        let principal = PrincipalId::default();
        let package =
            package_for(&kernel, &principal, "identity-capsule").expect("publish package");
        let identity = identity_response(handle(&kernel, &principal, "identity-capsule"))
            .expect("complete package identity");
        let uid = kernel
            .principal_directory
            .uid_for(&principal)
            .expect("default principal UID");
        let snapshot = kernel
            .principal_store
            .as_ref()
            .expect("test kernel durable store")
            .capsules()
            .get_snapshot(&StateOwner::Principal(uid), "identity-capsule")
            .expect("read package snapshot")
            .expect("package snapshot");
        let generation = snapshot.generation();

        assert_eq!(identity.id, "identity-capsule");
        assert_eq!(
            identity.archive_digest,
            blake3::hash(&package.archive).to_hex().to_string()
        );
        assert_eq!(
            identity.generation,
            InstalledCapsuleGeneration {
                archive: hex::encode(generation.archive().as_bytes()),
                metadata: hex::encode(generation.metadata().as_bytes()),
                authority: hex::encode(generation.authority().as_bytes()),
            }
        );
    }
}
