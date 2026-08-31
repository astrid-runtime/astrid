use crate::engine::DurableEnginePolicy;
use crate::engine::RootTransaction;
use crate::engine::{ObjectCacheConfig, TransactionWalPolicy};
use crate::storage_model::{
    ObjectClass, ObjectFormatVersion, ObjectIdentity, ObjectKind, ObjectRecord,
};
use crate::volume::{AstridVolume, HostedFileVolume, VolumeRegion};

use super::{
    Blake3ObjectIdentityV1, DurableEngine, RuntimeStateOwnerCodecV2, StateOwnerCodecV2,
    open_runtime_principal_store,
};
use std::num::NonZeroU64;
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
    let engine = DurableEngine::open_volume(
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
async fn legacy_user_volume_is_rejected_before_promotion() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    home.ensure().unwrap();
    let canonical = home.storage_volume_path();
    let volume = HostedFileVolume::open(&canonical).unwrap();
    let engine = DurableEngine::open_volume(
        volume.clone(),
        Blake3ObjectIdentityV1,
        StateOwnerCodecV2,
        RecoveryLimits::process_addressable(),
        DurableEnginePolicy::default(),
    )
    .unwrap();
    let commit = ObjectRecord::new(
        ObjectKind::Commit,
        ObjectFormatVersion::V1,
        b"canonical user volume commit".to_vec(),
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let commit_id = Blake3ObjectIdentityV1.identify(&commit);
    engine
        .commit(RootTransaction::new(
            StateOwner::User(astrid_core::UserUid::from_bytes([17; 32])),
            None,
            commit_id,
            vec![(commit_id, commit)],
        ))
        .unwrap();
    super::volume_migration::write_cutover_receipt(volume.as_ref(), &[]).unwrap();
    engine.close().unwrap();
    drop(volume);

    let legacy = home.legacy_storage_volume_path();
    std::fs::rename(&canonical, &legacy).unwrap();
    let legacy_before = std::fs::read(&legacy).unwrap();

    let Err(error) = open_runtime_principal_store(&home, unlimited_quota()).await else {
        panic!("legacy canonical User volume must fail before promotion");
    };
    assert!(
        error
            .to_string()
            .contains("explicit user StateOwner; mutation is refused"),
        "{error}"
    );
    assert_eq!(std::fs::read(&legacy).unwrap(), legacy_before);
    assert!(!canonical.exists());
}

#[tokio::test]
async fn legacy_user_wal_is_rejected_before_promotion() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    home.ensure().unwrap();
    let canonical = home.storage_volume_path();
    let policy = DurableEnginePolicy::new(
        crate::engine::GroupCommitPolicy::immediate(),
        crate::engine::RecoveryRetryPolicy::immediate(),
        ObjectCacheConfig::<StateOwner>::disabled(),
    )
    .with_transaction_wal(TransactionWalPolicy::enabled(
        NonZeroU64::new(u64::MAX).unwrap(),
    ));
    let volume = HostedFileVolume::open(&canonical).unwrap();
    let engine = DurableEngine::open_volume(
        volume.clone(),
        Blake3ObjectIdentityV1,
        StateOwnerCodecV2,
        RecoveryLimits::process_addressable(),
        policy,
    )
    .unwrap();
    let commit = ObjectRecord::new(
        ObjectKind::Commit,
        ObjectFormatVersion::V1,
        b"canonical user WAL volume commit".to_vec(),
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let commit_id = Blake3ObjectIdentityV1.identify(&commit);
    engine
        .commit(RootTransaction::new(
            StateOwner::User(astrid_core::UserUid::from_bytes([29; 32])),
            None,
            commit_id,
            vec![(commit_id, commit)],
        ))
        .unwrap();
    drop(engine);
    drop(volume);

    let volume = HostedFileVolume::open(&canonical).unwrap();
    let roots = VolumeRegion::new("roots.journal").unwrap();
    volume.set_region_len(&roots, 0).unwrap();
    volume.sync().unwrap();
    drop(volume);

    let legacy = home.legacy_storage_volume_path();
    std::fs::rename(&canonical, &legacy).unwrap();
    let legacy_before = std::fs::read(&legacy).unwrap();
    let Err(error) = open_runtime_principal_store(&home, unlimited_quota()).await else {
        panic!("legacy canonical User WAL must fail before promotion");
    };
    assert!(
        error
            .to_string()
            .contains("user-owned WAL transaction; mutation is refused"),
        "{error}"
    );
    assert_eq!(std::fs::read(&legacy).unwrap(), legacy_before);
    assert!(!canonical.exists());
}

#[tokio::test]
async fn legacy_malformed_root_cannot_hide_later_user() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    home.ensure().unwrap();
    let canonical = home.storage_volume_path();
    let volume = HostedFileVolume::open(&canonical).unwrap();
    let engine = DurableEngine::open_volume(
        volume.clone(),
        Blake3ObjectIdentityV1,
        StateOwnerCodecV2,
        RecoveryLimits::process_addressable(),
        DurableEnginePolicy::default(),
    )
    .unwrap();
    for owner in [
        StateOwner::Principal(astrid_core::PrincipalUid::from_bytes([41; 32])),
        StateOwner::User(astrid_core::UserUid::from_bytes([42; 32])),
    ] {
        let commit = ObjectRecord::new(
            ObjectKind::Commit,
            ObjectFormatVersion::V1,
            b"mixed root owner".to_vec(),
            Vec::new(),
            0,
            ObjectClass::Metadata,
        )
        .unwrap();
        let commit_id = Blake3ObjectIdentityV1.identify(&commit);
        engine
            .commit(RootTransaction::new(
                owner,
                None,
                commit_id,
                vec![(commit_id, commit)],
            ))
            .unwrap();
    }
    engine.close().unwrap();

    let roots = VolumeRegion::new("roots.journal").unwrap();
    volume.write_region_at(&roots, 8, &[0]).unwrap();
    super::volume_migration::write_cutover_receipt(volume.as_ref(), &[]).unwrap();
    drop(volume);

    let legacy = home.legacy_storage_volume_path();
    std::fs::rename(&canonical, &legacy).unwrap();
    let before = std::fs::read(&legacy).unwrap();
    let Err(error) = open_runtime_principal_store(&home, unlimited_quota()).await else {
        panic!("mixed legacy volume must fail closed before promotion");
    };
    assert!(
        error
            .to_string()
            .contains("explicit user StateOwner; mutation is refused"),
        "{error}"
    );
    assert_eq!(std::fs::read(&legacy).unwrap(), before);
    assert!(!canonical.exists());
}

#[tokio::test]
async fn legacy_malformed_wal_cannot_hide_later_user() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    home.ensure().unwrap();
    let canonical = home.storage_volume_path();
    let policy = DurableEnginePolicy::new(
        crate::engine::GroupCommitPolicy::immediate(),
        crate::engine::RecoveryRetryPolicy::immediate(),
        ObjectCacheConfig::<StateOwner>::disabled(),
    )
    .with_transaction_wal(TransactionWalPolicy::enabled(
        NonZeroU64::new(u64::MAX).unwrap(),
    ));
    let volume = HostedFileVolume::open(&canonical).unwrap();
    let engine = DurableEngine::open_volume(
        volume.clone(),
        Blake3ObjectIdentityV1,
        StateOwnerCodecV2,
        RecoveryLimits::process_addressable(),
        policy,
    )
    .unwrap();
    for owner in [
        StateOwner::Principal(astrid_core::PrincipalUid::from_bytes([43; 32])),
        StateOwner::User(astrid_core::UserUid::from_bytes([44; 32])),
    ] {
        let commit = ObjectRecord::new(
            ObjectKind::Commit,
            ObjectFormatVersion::V1,
            b"mixed WAL owner".to_vec(),
            Vec::new(),
            0,
            ObjectClass::Metadata,
        )
        .unwrap();
        let commit_id = Blake3ObjectIdentityV1.identify(&commit);
        engine
            .commit(RootTransaction::new(
                owner,
                None,
                commit_id,
                vec![(commit_id, commit)],
            ))
            .unwrap();
    }
    drop(engine);

    let wal = VolumeRegion::new("transactions.wal").unwrap();
    volume.write_region_at(&wal, 20, &[0]).unwrap();
    let roots = VolumeRegion::new("roots.journal").unwrap();
    volume.set_region_len(&roots, 0).unwrap();
    volume.sync().unwrap();
    drop(volume);

    let legacy = home.legacy_storage_volume_path();
    std::fs::rename(&canonical, &legacy).unwrap();
    let before = std::fs::read(&legacy).unwrap();
    let Err(error) = open_runtime_principal_store(&home, unlimited_quota()).await else {
        panic!("mixed legacy WAL must fail closed before promotion");
    };
    assert!(
        error
            .to_string()
            .contains("user-owned WAL transaction; mutation is refused"),
        "{error}"
    );
    assert_eq!(std::fs::read(&legacy).unwrap(), before);
    assert!(!canonical.exists());
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
    // The no-replace promotion intentionally retains the locked source name.
    // This prevents a raced replacement from ever being selected for unlink.
    assert!(legacy.is_file());
    assert_eq!(
        std::fs::read(&canonical).unwrap(),
        std::fs::read(&legacy).unwrap()
    );
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

#[test]
fn user_in_reclaim_artifact_is_never_promoted_or_deleted() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    home.ensure().unwrap();

    let active_path = home.storage_volume_path();
    let previous_path = std::path::PathBuf::from(format!("{}.previous", active_path.display()));
    drop(HostedFileVolume::open(&active_path).unwrap());

    let volume = HostedFileVolume::open(&previous_path).unwrap();
    let engine = DurableEngine::open_volume(
        volume.clone(),
        Blake3ObjectIdentityV1,
        StateOwnerCodecV2,
        RecoveryLimits::process_addressable(),
        DurableEnginePolicy::default(),
    )
    .unwrap();
    let commit = ObjectRecord::new(
        ObjectKind::Commit,
        ObjectFormatVersion::V1,
        b"user reclaim artifact".to_vec(),
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let commit_id = Blake3ObjectIdentityV1.identify(&commit);
    engine
        .commit(RootTransaction::new(
            StateOwner::User(astrid_core::UserUid::from_bytes([61; 32])),
            None,
            commit_id,
            vec![(commit_id, commit)],
        ))
        .unwrap();
    engine.close().unwrap();
    drop(volume);

    let active_before = std::fs::read(&active_path).unwrap();
    let previous_before = std::fs::read(&previous_path).unwrap();
    let error =
        super::volume_migration::open_existing(&home, DurableEnginePolicy::default()).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("explicit user StateOwner; mutation is refused"),
        "{error}"
    );
    assert_eq!(std::fs::read(&active_path).unwrap(), active_before);
    assert_eq!(std::fs::read(&previous_path).unwrap(), previous_before);
}
