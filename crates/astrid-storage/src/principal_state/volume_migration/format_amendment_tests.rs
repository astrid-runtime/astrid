//! Amendments must cover already-volume-backed installations, not only cutover.
use std::sync::Arc;

use super::*;
use crate::KvStore;
use crate::principal_state::{RuntimeStore, StateOwnerResolver, bootstrap};
use crate::storage_model::{ObjectClass, ObjectFormatVersion, ObjectKind, ObjectRecord};

fn seed_volume(home: &AstridHome, specification: &ObjectRecord) -> RuntimeEngine {
    let volume = HostedFileVolume::open(home.storage_volume_path()).unwrap();
    let engine = RuntimeEngine::open_volume(
        volume.clone(),
        Blake3ObjectIdentityV1,
        StateOwnerCodecV2,
        RecoveryLimits::process_addressable(),
        DurableEnginePolicy::default(),
    )
    .unwrap();
    let (spec_id, _) = engine.persist_standalone_object(specification).unwrap();
    let catalog = bootstrap::content_catalog_format_specification().unwrap();
    let (catalog_id, _) = engine.persist_standalone_object(&catalog).unwrap();
    engine
        .ensure_direct_representation_catalogue(spec_id, &[spec_id, catalog_id])
        .unwrap();
    write_cutover_receipt(volume.as_ref(), &[]).unwrap();
    engine
}

#[tokio::test]
async fn existing_volume_amends_prior_profile_preserving_history_and_exact_values() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let prior = crate::principal_state::format_migration_tests::pre_chunked_specification();
    let engine = Arc::new(seed_volume(&home, &prior));
    let kv = RuntimeStore::from_engine(
        engine.clone(),
        StateOwnerResolver::new(crate::principal_state::PrincipalDirectory::default()),
    );
    kv.set(
        "system:identity",
        "retained",
        b"before-volume-amendment".to_vec(),
    )
    .await
    .unwrap();
    let before = engine.root(&StateOwner::System).unwrap().unwrap();
    let retained_commit = engine.object(before.commit).unwrap().unwrap();
    drop(kv);
    engine.close().unwrap();
    drop(engine);
    let store = crate::principal_state::open_runtime_principal_store(
        &home,
        Arc::new(|_: &StateOwner| Ok(None)),
    )
    .await
    .unwrap();
    // Runtime projection admission can advance the System root; the old
    // commit and its value must survive the format amendment byte-for-byte.
    assert_eq!(
        store.engine.object(before.commit).unwrap(),
        Some(retained_commit)
    );
    assert_eq!(
        store.kv().get("system:identity", "retained").await.unwrap(),
        Some(b"before-volume-amendment".to_vec())
    );
    let large = vec![0x5a; 512 * 1024];
    store
        .kv()
        .set("system:identity", "chunked", large.clone())
        .await
        .unwrap();
    store.engine.close().unwrap();
    drop(store);
    let reopened = crate::principal_state::open_runtime_principal_store(
        &home,
        Arc::new(|_: &StateOwner| Ok(None)),
    )
    .await
    .unwrap();
    assert_eq!(
        reopened
            .kv()
            .get("system:identity", "chunked")
            .await
            .unwrap(),
        Some(large)
    );
    assert_eq!(
        reopened
            .kv()
            .get("system:identity", "retained")
            .await
            .unwrap(),
        Some(b"before-volume-amendment".to_vec())
    );
    reopened.engine.close().unwrap();
}

#[tokio::test]
async fn unrelated_supported_evidence_does_not_authorize_unknown_volume_profile() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let unknown = ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        b"unknown physical specification".to_vec(),
        vec![],
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let engine = seed_volume(&home, &unknown);
    let prior = crate::principal_state::format_migration_tests::pre_chunked_specification();
    engine.persist_standalone_object(&prior).unwrap();
    engine.close().unwrap();
    drop(engine);
    let result = crate::principal_state::open_runtime_principal_store(
        &home,
        Arc::new(|_: &StateOwner| Ok(None)),
    )
    .await;
    let Err(error) = result else {
        panic!("unknown volume profile was admitted")
    };
    assert!(error.to_string().contains("unsupported format"), "{error}");
    let volume = HostedFileVolume::open(home.storage_volume_path()).unwrap();
    let recovered = RuntimeEngine::open_volume(
        volume,
        Blake3ObjectIdentityV1,
        StateOwnerCodecV2,
        RecoveryLimits::process_addressable(),
        DurableEnginePolicy::default(),
    )
    .unwrap();
    let current = bootstrap::format_specification().unwrap();
    assert!(
        recovered
            .object(recovered.identify(&current))
            .unwrap()
            .is_none(),
        "rejected upgrade must not insert a new bootstrap"
    );
    recovered.close().unwrap();
}

#[tokio::test]
async fn volume_without_profile_cannot_recreate_a_missing_current_bootstrap() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let volume = HostedFileVolume::open(home.storage_volume_path()).unwrap();
    let engine = RuntimeEngine::open_volume(
        volume.clone(),
        Blake3ObjectIdentityV1,
        StateOwnerCodecV2,
        RecoveryLimits::process_addressable(),
        DurableEnginePolicy::default(),
    )
    .unwrap();
    write_cutover_receipt(volume.as_ref(), &[]).unwrap();
    engine.close().unwrap();
    drop(engine);
    drop(volume);
    let result = crate::principal_state::open_runtime_principal_store(
        &home,
        Arc::new(|_: &StateOwner| Ok(None)),
    )
    .await;
    let Err(error) = result else {
        panic!("missing volume bootstrap was recreated")
    };
    assert!(
        error
            .to_string()
            .contains("missing its in-band format specification"),
        "{error}"
    );
}

#[tokio::test]
async fn bootstrap_amendment_preserves_every_principal_root_and_prior_profile() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let prior = crate::principal_state::format_migration_tests::pre_chunked_specification();
    let engine = Arc::new(seed_volume(&home, &prior));
    let kv = RuntimeStore::from_engine(
        engine.clone(),
        StateOwnerResolver::new(crate::principal_state::PrincipalDirectory::default()),
    );
    kv.set(
        "system:identity",
        "retained",
        b"root-must-not-change".to_vec(),
    )
    .await
    .unwrap();
    drop(kv);
    let before = engine.roots().unwrap();
    let profile = engine.direct_representation_specification().unwrap();
    for _ in 0..2 {
        crate::principal_state::format_amendment::prepare_volume_format_specification(&engine)
            .unwrap();
        assert_eq!(engine.roots().unwrap(), before);
        assert_eq!(
            engine.direct_representation_specification().unwrap(),
            profile
        );
    }
    engine.close().unwrap();
}
