use crate::engine::DurableEnginePolicy;
use crate::storage_model::{
    ObjectClass, ObjectFormatVersion, ObjectIdentity, ObjectKind, ObjectRecord,
};
use crate::volume::HostedFileVolume;

use super::{
    Blake3ObjectIdentityV1, RuntimeEngine, RuntimeStateOwnerCodecV2, open_runtime_principal_store,
};
use std::sync::Arc;

use super::{KvQuotaResolver, RecoveryLimits, StateOwner};
use astrid_core::dirs::AstridHome;

fn unlimited_quota() -> Arc<dyn KvQuotaResolver<StateOwner>> {
    Arc::new(|owner: &StateOwner| {
        Ok(match owner {
            StateOwner::System => None,
            StateOwner::Principal(_) | StateOwner::Fleet(_) | StateOwner::User(_) => Some(u64::MAX),
        })
    })
}

fn seed_predecessor_volume(home: &AstridHome, records: &[ObjectRecord]) {
    let path = home.storage_volume_path();
    let volume = HostedFileVolume::open(&path).expect("seed volume");
    let engine = RuntimeEngine::open_volume(
        volume.clone(),
        Blake3ObjectIdentityV1,
        RuntimeStateOwnerCodecV2,
        RecoveryLimits::process_addressable(),
        DurableEnginePolicy::default(),
    )
    .expect("seed volume engine");
    for record in records {
        engine
            .persist_standalone_object(record)
            .expect("seed volume object");
    }
    engine.close().expect("close seeded volume engine");
    super::volume_migration::write_cutover_receipt(volume.as_ref(), &[])
        .expect("write seeded cutover receipt");
}

#[tokio::test]
async fn existing_pre_user_volume_prepares_and_reopens_idempotently() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    home.ensure().unwrap();

    let prior_spec = super::format_migration_tests::pre_user_owner_format_spec_record();
    let catalog_spec = super::bootstrap::content_catalog_format_specification().unwrap();
    seed_predecessor_volume(&home, &[prior_spec.clone(), catalog_spec.clone()]);

    let current_spec = super::bootstrap::format_specification().unwrap();
    let current_spec_id = Blake3ObjectIdentityV1.identify(&current_spec);
    let prior_spec_id = Blake3ObjectIdentityV1.identify(&prior_spec);
    let first = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .expect("first predecessor-volume reopen");
    assert_eq!(
        first.engine.object(current_spec_id).unwrap(),
        Some(current_spec.clone())
    );
    assert_eq!(
        first.engine.object(prior_spec_id).unwrap(),
        Some(prior_spec)
    );
    first.engine.close().unwrap();
    drop(first);

    let second = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .expect("second predecessor-volume reopen");
    assert_eq!(
        second.engine.object(current_spec_id).unwrap(),
        Some(current_spec)
    );
    second.engine.close().unwrap();
}

#[tokio::test]
async fn existing_volume_with_only_an_unrecognized_spec_fails_closed() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    home.ensure().unwrap();
    let unknown_spec = ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        b"unrecognized volume format specification".to_vec(),
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let catalog_spec = super::bootstrap::content_catalog_format_specification().unwrap();
    seed_predecessor_volume(&home, &[unknown_spec, catalog_spec]);

    let Err(error) = open_runtime_principal_store(&home, unlimited_quota()).await else {
        panic!("unrecognized predecessor volume must fail closed");
    };
    assert!(
        error
            .to_string()
            .contains("missing its prior format-v1 specification"),
        "{error}"
    );
}

#[tokio::test]
async fn promotes_released_volume_path_before_opening() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    home.ensure().unwrap();

    let store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    drop(store);

    let canonical = home.storage_volume_path();
    let legacy = home.legacy_storage_volume_path();
    std::fs::rename(&canonical, &legacy).unwrap();
    assert!(!canonical.exists());
    assert!(legacy.is_file());

    let reopened = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    drop(reopened);

    assert!(canonical.is_file());
    assert!(!legacy.exists());
}

#[test]
fn rejects_conflicting_canonical_and_legacy_volume_paths() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    home.ensure().unwrap();

    std::fs::write(home.storage_volume_path(), b"canonical").unwrap();
    std::fs::write(home.legacy_storage_volume_path(), b"legacy").unwrap();

    let error = super::volume_migration::existing_volume_available(&home).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("both canonical and legacy volumes")
    );
    assert!(home.storage_volume_path().is_file());
    assert!(home.legacy_storage_volume_path().is_file());
}

#[test]
fn rejects_non_regular_canonical_volume_without_promoting() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    home.ensure().unwrap();
    std::fs::create_dir(home.storage_volume_path()).unwrap();

    let error = super::volume_migration::existing_volume_available(&home).unwrap_err();

    assert!(error.to_string().contains("not a regular file"));
    assert!(home.storage_volume_path().is_dir());
    assert!(!home.legacy_storage_volume_path().exists());
}

#[test]
fn rejects_non_regular_legacy_volume_without_promoting() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    home.ensure().unwrap();
    std::fs::create_dir(home.legacy_storage_volume_path()).unwrap();

    let error = super::volume_migration::existing_volume_available(&home).unwrap_err();

    assert!(error.to_string().contains("not a regular file"));
    assert!(!home.storage_volume_path().exists());
    assert!(home.legacy_storage_volume_path().is_dir());
}

#[cfg(unix)]
#[test]
fn rejects_symlink_canonical_volume_without_promoting() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    home.ensure().unwrap();
    let target = directory.path().join("canonical-target");
    std::fs::write(&target, b"not a volume").unwrap();
    symlink(&target, home.storage_volume_path()).unwrap();

    let error = super::volume_migration::existing_volume_available(&home).unwrap_err();

    assert!(error.to_string().contains("redirected"));
    assert!(
        std::fs::symlink_metadata(home.storage_volume_path())
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert!(!home.legacy_storage_volume_path().exists());
}

#[cfg(unix)]
#[test]
fn rejects_symlink_legacy_volume_without_promoting() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    home.ensure().unwrap();
    let target = directory.path().join("legacy-target");
    std::fs::write(&target, b"not a volume").unwrap();
    symlink(&target, home.legacy_storage_volume_path()).unwrap();

    let error = super::volume_migration::existing_volume_available(&home).unwrap_err();

    assert!(error.to_string().contains("redirected"));
    assert!(!home.storage_volume_path().exists());
    assert!(
        std::fs::symlink_metadata(home.legacy_storage_volume_path())
            .unwrap()
            .file_type()
            .is_symlink()
    );
}
