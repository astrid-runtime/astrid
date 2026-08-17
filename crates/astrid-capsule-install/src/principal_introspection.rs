//! Typed installed-capsule introspection over the authoritative registry.
//!
//! Installed package metadata is owner-scoped Astrid content. This module
//! intentionally has no native-home mirror or recursive filesystem copy API:
//! callers receive verified archive/metadata/authority bytes and can render
//! their own read-only view without making a host directory authoritative.

use std::sync::Arc;

use anyhow::Context;
use astrid_core::identity::PrincipalUid;
use astrid_storage::{CapsulePackageSnapshot, RuntimePrincipalStore, StateOwner};

/// One package snapshot suitable for read-only introspection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DurableCapsuleIntrospection {
    /// Canonical capsule identifier.
    pub id: String,
    /// Verified package bytes and exact generation token.
    pub snapshot: CapsulePackageSnapshot,
}

/// List every installed package for an immutable principal UID.
///
/// The UID is the authority boundary; aliases are resolved by the kernel
/// before calling this function. Registry discovery is prefix-scoped and
/// malformed/partial package sets fail closed.
///
/// # Errors
///
/// Returns an error when the owner content graph is unavailable, a reserved
/// package path is malformed, or a package disappears during readback.
pub fn list_durable_capsule_packages(
    store: &Arc<RuntimePrincipalStore>,
    uid: PrincipalUid,
) -> anyhow::Result<Vec<DurableCapsuleIntrospection>> {
    let owner = StateOwner::Principal(uid);
    let registry = store.capsules();
    registry
        .list(&owner)?
        .into_iter()
        .map(|summary| {
            let id = summary.id().to_owned();
            let snapshot = registry
                .get_snapshot(&owner, &id)?
                .ok_or_else(|| anyhow::anyhow!("capsule {id} disappeared during introspection"))?;
            Ok(DurableCapsuleIntrospection { id, snapshot })
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
    let owner = StateOwner::Principal(uid);
    let snapshot = store
        .capsules()
        .get_snapshot(&owner, id)?
        .with_context(|| format!("durable capsule {id} is not installed"))?;
    Ok(DurableCapsuleIntrospection {
        id: id.to_owned(),
        snapshot,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use astrid_core::dirs::AstridHome;
    use astrid_storage::{
        CapsuleInstallExpectation, CapsulePackage, KvQuotaResolver, open_runtime_principal_store,
    };

    fn unlimited_quota() -> Arc<dyn KvQuotaResolver<StateOwner>> {
        Arc::new(|owner: &StateOwner| {
            Ok(match owner {
                StateOwner::System => None,
                StateOwner::Principal(_) | StateOwner::Fleet(_) => Some(u64::MAX),
            })
        })
    }

    fn uid(byte: u8) -> PrincipalUid {
        PrincipalUid::from_bytes([byte; 32])
    }

    #[tokio::test]
    async fn reads_metadata_from_storage_without_native_home_mirror() {
        let directory = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(directory.path());
        let store = Arc::new(
            open_runtime_principal_store(&home, unlimited_quota())
                .await
                .unwrap(),
        );
        let owner = StateOwner::Principal(uid(1));
        store
            .capsules()
            .install(
                &owner,
                "demo-cap",
                &CapsulePackage::new(
                    b"archive".to_vec(),
                    br#"{"version":"1.0.0"}"#.to_vec(),
                    br#"{"capsule_id":"demo-cap"}"#.to_vec(),
                ),
                CapsuleInstallExpectation::Absent,
            )
            .unwrap();
        let result = read_durable_capsule_package(&store, uid(1), "demo-cap").unwrap();
        assert_eq!(result.id, "demo-cap");
        assert_eq!(
            result.snapshot.package().metadata,
            br#"{"version":"1.0.0"}"#
        );
        assert!(
            !home
                .principal_home(&astrid_core::PrincipalId::default())
                .capsules_dir()
                .exists()
        );
        assert!(
            list_durable_capsule_packages(&store, uid(2))
                .unwrap()
                .is_empty()
        );
    }
}
