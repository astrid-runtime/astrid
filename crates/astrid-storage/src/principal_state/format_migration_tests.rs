//! Selection coverage for known in-place format-1 RÚNATAL amendments.

use crate::engine::{PrincipalCodec, RecoveryLimits};
use crate::storage_model::{ObjectId, ObjectIdentity};

use super::bootstrap;
use super::format_amendment::{
    DestinationFormat, PRE_BOTTOM_K_SKETCH_FORMAT_SPEC_ID, PRE_CHUNKED_KV_FORMAT_SPEC_ID,
    PRE_COMPACTION_FORMAT_SPEC_ID, PRE_DENSE_RADIX_FORMAT_SPEC_ID,
    PRE_FASTCDC_FREEZE_FORMAT_SPEC_ID, PRE_FLEET_OWNER_FORMAT_SPEC_ID,
    PRE_GC_OUTBOX_FORMAT_SPEC_ID, PRE_KV_TRANSITION_FORMAT_SPEC_ID,
    PRE_MECHANICAL_AUDIT_FORMAT_SPEC_ID, PRE_PHYSICAL_CATALOGUE_FORMAT_SPEC_ID,
    PRE_RESERVED_REPRESENTATION_TAG_FORMAT_SPEC_ID, PRE_RUNATAL_NAMING_FORMAT_SPEC_ID,
    PRE_SHA384_ATTESTATION_FORMAT_SPEC_ID, PRE_UID_RETIREMENT_FORMAT_SPEC_ID,
    PRE_WORKSPACE_BRANCH_FORMAT_SPEC_ID, STORE_METADATA_FILE, format_spec_record,
    legacy_store_metadata, pre_fleet_owner_store_metadata, pre_representation_store_metadata,
    prepare_catalog_specification, prepare_destination, prepare_format_specification,
    previous_store_metadata, representation_bootstrap_objects, store_metadata,
};
use super::{
    Blake3ObjectIdentityV1, RuntimeEngine, StateOwnerCodecV1, StateOwnerCodecV2, StateOwnerV1,
};
use astrid_core::dirs::AstridHome;
use astrid_core::identity::PrincipalUid;

#[test]
fn owner_codec_v1_remains_frozen_without_a_fleet_tag() {
    let codec = StateOwnerCodecV1;
    let principal = PrincipalUid::from_bytes([9; 32]);
    for owner in [StateOwnerV1::System, StateOwnerV1::Principal(principal)] {
        let encoded = codec.encode(&owner);
        assert_eq!(codec.decode(&encoded), Some(owner));
    }
    assert_eq!(codec.decode(&[2; 33]), None);
}

#[test]
fn new_destination_is_created_with_the_private_directory_contract() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("principal-store");
    let format = bootstrap::format_specification().unwrap();
    let format_id = Blake3ObjectIdentityV1.identify(&format);
    let catalog = bootstrap::content_catalog_format_specification().unwrap();
    let catalog_id = Blake3ObjectIdentityV1.identify(&catalog);

    assert_eq!(
        prepare_destination(&path, &store_metadata(format_id, catalog_id), catalog_id).unwrap(),
        DestinationFormat::New,
    );
    #[cfg(windows)]
    astrid_core::platform_fs::ensure_private_directory(&path).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::symlink_metadata(&path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700,
        );
    }
}

pub(super) fn seed_current_directory_store(home: &AstridHome) {
    let path = home.principal_store_path();
    let format = bootstrap::format_specification().unwrap();
    let format_id = Blake3ObjectIdentityV1.identify(&format);
    let catalog = bootstrap::content_catalog_format_specification().unwrap();
    let catalog_id = Blake3ObjectIdentityV1.identify(&catalog);
    let metadata = store_metadata(format_id, catalog_id);
    let destination = prepare_destination(&path, &metadata, catalog_id).unwrap();
    let engine = RuntimeEngine::open(
        &path,
        Blake3ObjectIdentityV1,
        StateOwnerCodecV2,
        RecoveryLimits::process_addressable(),
    )
    .unwrap();
    prepare_format_specification(&engine, destination, &format, format_id).unwrap();
    prepare_catalog_specification(&engine, destination, &catalog, catalog_id).unwrap();
    engine
        .ensure_direct_representation_catalogue(
            format_id,
            &representation_bootstrap_objects(format_id, catalog_id),
        )
        .unwrap();
    engine.close().unwrap();
    std::fs::write(path.join(STORE_METADATA_FILE), metadata).unwrap();
    std::fs::write(
        path.join(super::migrations::MIGRATION_MARKER_FILE),
        super::migrations::KV_TRANSITION_CHECKPOINT_MARKER,
    )
    .unwrap();
}

#[test]
fn completed_prior_v1_stores_are_selected_for_runatal_amendment() {
    for prior in [
        PRE_COMPACTION_FORMAT_SPEC_ID,
        PRE_GC_OUTBOX_FORMAT_SPEC_ID,
        PRE_RUNATAL_NAMING_FORMAT_SPEC_ID,
        PRE_FASTCDC_FREEZE_FORMAT_SPEC_ID,
        PRE_SHA384_ATTESTATION_FORMAT_SPEC_ID,
    ] {
        assert_prior_format_is_selected(prior, false);
    }
    assert_prior_format_is_selected(PRE_FASTCDC_FREEZE_FORMAT_SPEC_ID, true);
    assert_prior_format_is_selected(PRE_KV_TRANSITION_FORMAT_SPEC_ID, true);
    assert_prior_current_projection_is_selected(PRE_BOTTOM_K_SKETCH_FORMAT_SPEC_ID);
    assert_prior_current_projection_is_selected(PRE_MECHANICAL_AUDIT_FORMAT_SPEC_ID);
    assert_prior_current_projection_is_selected(PRE_DENSE_RADIX_FORMAT_SPEC_ID);
    assert_pre_fleet_owner_format_is_selected();
    assert_pre_representation_format_is_selected(PRE_PHYSICAL_CATALOGUE_FORMAT_SPEC_ID);
    // The published profile immediately before ObjectKind::WorkspaceBranch
    // remains an in-place predecessor.  Opening it selects the amendment
    // path rather than silently treating an unknown kind as Derived.
    assert_prior_format_is_selected(PRE_WORKSPACE_BRANCH_FORMAT_SPEC_ID, false);
    assert_prior_current_projection_is_selected(PRE_RESERVED_REPRESENTATION_TAG_FORMAT_SPEC_ID);
    assert_prior_current_projection_is_selected(PRE_CHUNKED_KV_FORMAT_SPEC_ID);
    assert_prior_current_projection_is_selected(PRE_UID_RETIREMENT_FORMAT_SPEC_ID);
}

fn assert_pre_fleet_owner_format_is_selected() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    seed_current_directory_store(&home);

    let store_path = home.principal_store_path();
    let catalog_spec = bootstrap::content_catalog_format_specification().unwrap();
    let catalog_spec_id = Blake3ObjectIdentityV1.identify(&catalog_spec);
    std::fs::write(
        store_path.join(STORE_METADATA_FILE),
        pre_fleet_owner_store_metadata(PRE_FLEET_OWNER_FORMAT_SPEC_ID, catalog_spec_id),
    )
    .unwrap();
    let current_spec_id = Blake3ObjectIdentityV1.identify(&format_spec_record().unwrap());
    assert_eq!(
        prepare_destination(
            &store_path,
            &store_metadata(current_spec_id, catalog_spec_id),
            catalog_spec_id,
        )
        .unwrap(),
        DestinationFormat::PriorV1 {
            format_spec: PRE_FLEET_OWNER_FORMAT_SPEC_ID,
            catalog_spec_was_declared: true,
        }
    );
}

#[tokio::test]
async fn pre_fleet_active_catalogue_survives_full_runtime_open() {
    use crate::storage_model::{ObjectClass, ObjectFormatVersion, ObjectKind, ObjectRecord};
    use std::sync::Arc;

    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    super::runtime_tests::seed_legacy_layout(&home);
    let path = home.principal_store_path();
    let prior = ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        include_bytes!("../../tests/fixtures/principal-store-pre-fleet-v1.txt").to_vec(),
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let prior_id = Blake3ObjectIdentityV1.identify(&prior);
    assert_eq!(
        prior_id, PRE_FLEET_OWNER_FORMAT_SPEC_ID,
        "fixture must be the real predecessor"
    );
    let catalog = bootstrap::content_catalog_format_specification().unwrap();
    let catalog_id = Blake3ObjectIdentityV1.identify(&catalog);
    let engine = RuntimeEngine::open(
        &path,
        Blake3ObjectIdentityV1,
        StateOwnerCodecV2,
        RecoveryLimits::process_addressable(),
    )
    .unwrap();
    engine.persist_standalone_object(&prior).unwrap();
    engine.persist_standalone_object(&catalog).unwrap();
    let engine = Arc::new(engine);
    let legacy_kv = super::RuntimeStore::from_engine(
        Arc::clone(&engine),
        super::StateOwnerResolver::new(super::PrincipalDirectory::default()),
    );
    crate::KvStore::set(
        &legacy_kv,
        "system:identity",
        "catalogue-upgrade",
        b"retained-state".to_vec(),
    )
    .await
    .unwrap();
    drop(legacy_kv);
    engine
        .ensure_direct_representation_catalogue(prior_id, &[prior_id, catalog_id])
        .unwrap();
    engine.close().unwrap();
    drop(engine);
    std::fs::write(
        path.join(STORE_METADATA_FILE),
        pre_fleet_owner_store_metadata(prior_id, catalog_id),
    )
    .unwrap();
    std::fs::write(
        path.join(super::migrations::MIGRATION_MARKER_FILE),
        super::migrations::KV_TRANSITION_CHECKPOINT_MARKER,
    )
    .unwrap();

    let store =
        super::open_runtime_principal_store(&home, Arc::new(|_: &super::StateOwner| Ok(None)))
            .await
            .expect("recognized predecessor with its original active catalogue must migrate");
    assert_eq!(
        store
            .kv()
            .get("system:identity", "catalogue-upgrade")
            .await
            .unwrap(),
        Some(b"retained-state".to_vec())
    );
    store.engine.close().unwrap();
    drop(store);
    let reopened =
        super::open_runtime_principal_store(&home, Arc::new(|_: &super::StateOwner| Ok(None)))
            .await
            .expect("migrated store must reopen");
    assert_eq!(
        reopened
            .kv()
            .get("system:identity", "catalogue-upgrade")
            .await
            .unwrap(),
        Some(b"retained-state".to_vec())
    );
    reopened.engine.close().unwrap();
    drop(reopened);
}

fn assert_pre_representation_format_is_selected(prior: ObjectId) {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    seed_current_directory_store(&home);

    let store_path = home.principal_store_path();
    let catalog_spec = bootstrap::content_catalog_format_specification().unwrap();
    let catalog_spec_id = Blake3ObjectIdentityV1.identify(&catalog_spec);
    std::fs::write(
        store_path.join(STORE_METADATA_FILE),
        pre_representation_store_metadata(prior, catalog_spec_id),
    )
    .unwrap();
    let current_spec_id = Blake3ObjectIdentityV1.identify(&format_spec_record().unwrap());
    assert_eq!(
        prepare_destination(
            &store_path,
            &store_metadata(current_spec_id, catalog_spec_id),
            catalog_spec_id,
        )
        .unwrap(),
        DestinationFormat::PriorV1 {
            format_spec: prior,
            catalog_spec_was_declared: true,
        }
    );
}

fn assert_prior_current_projection_is_selected(prior: ObjectId) {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    seed_current_directory_store(&home);

    let store_path = home.principal_store_path();
    let catalog_spec = bootstrap::content_catalog_format_specification().unwrap();
    let catalog_spec_id = Blake3ObjectIdentityV1.identify(&catalog_spec);
    std::fs::write(
        store_path.join(STORE_METADATA_FILE),
        store_metadata(prior, catalog_spec_id),
    )
    .unwrap();
    let current_spec_id = Blake3ObjectIdentityV1.identify(&format_spec_record().unwrap());
    assert_eq!(
        prepare_destination(
            &store_path,
            &store_metadata(current_spec_id, catalog_spec_id),
            catalog_spec_id,
        )
        .unwrap(),
        DestinationFormat::PriorV1 {
            format_spec: prior,
            catalog_spec_was_declared: true,
        }
    );
}

fn assert_prior_format_is_selected(prior: ObjectId, catalog_aware: bool) {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    seed_current_directory_store(&home);

    let store_path = home.principal_store_path();
    let catalog_spec = bootstrap::content_catalog_format_specification().unwrap();
    let catalog_spec_id = Blake3ObjectIdentityV1.identify(&catalog_spec);
    std::fs::write(
        store_path.join(STORE_METADATA_FILE),
        if catalog_aware {
            previous_store_metadata(prior, catalog_spec_id)
        } else {
            legacy_store_metadata(prior)
        },
    )
    .unwrap();
    let current_spec = format_spec_record().unwrap();
    let current_spec_id = Blake3ObjectIdentityV1.identify(&current_spec);
    let current_metadata = store_metadata(current_spec_id, catalog_spec_id);
    assert_eq!(
        prepare_destination(&store_path, &current_metadata, catalog_spec_id,).unwrap(),
        DestinationFormat::PriorV1 {
            format_spec: prior,
            catalog_spec_was_declared: catalog_aware,
        }
    );
}

#[test]
fn current_format_identity_without_catalog_metadata_fails_closed() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    seed_current_directory_store(&home);

    let store_path = home.principal_store_path();
    let current_spec = format_spec_record().unwrap();
    let current_spec_id = Blake3ObjectIdentityV1.identify(&current_spec);
    let catalog_spec_id = Blake3ObjectIdentityV1
        .identify(&bootstrap::content_catalog_format_specification().unwrap());
    std::fs::write(
        store_path.join(STORE_METADATA_FILE),
        legacy_store_metadata(current_spec_id),
    )
    .unwrap();

    let error = prepare_destination(
        &store_path,
        &store_metadata(current_spec_id, catalog_spec_id),
        catalog_spec_id,
    )
    .unwrap_err();
    assert!(
        error.to_string().contains("selects an unsupported format"),
        "{error}"
    );
}

#[tokio::test]
async fn pre_chunked_kv_catalogue_upgrade_preserves_root_and_accepts_large_values() {
    use crate::KvStore;
    use std::sync::Arc;

    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    super::runtime_tests::seed_legacy_layout(&home);
    let path = home.principal_store_path();
    let prior = pre_chunked_specification();
    let prior_id = Blake3ObjectIdentityV1.identify(&prior);
    assert_eq!(prior_id, PRE_CHUNKED_KV_FORMAT_SPEC_ID);
    let catalog = bootstrap::content_catalog_format_specification().unwrap();
    let catalog_id = Blake3ObjectIdentityV1.identify(&catalog);
    let engine = Arc::new(
        RuntimeEngine::open(
            &path,
            Blake3ObjectIdentityV1,
            StateOwnerCodecV2,
            RecoveryLimits::process_addressable(),
        )
        .unwrap(),
    );
    engine.persist_standalone_object(&prior).unwrap();
    engine.persist_standalone_object(&catalog).unwrap();
    let kv = super::RuntimeStore::from_engine(
        engine.clone(),
        super::StateOwnerResolver::new(super::PrincipalDirectory::default()),
    );
    kv.set("system:identity", "retained", b"before-amendment".to_vec())
        .await
        .unwrap();
    drop(kv);
    let before = engine.root(&super::StateOwner::System).unwrap();
    engine
        .ensure_direct_representation_catalogue(prior_id, &[prior_id, catalog_id])
        .unwrap();
    engine.close().unwrap();
    drop(engine);
    std::fs::write(
        path.join(STORE_METADATA_FILE),
        store_metadata(prior_id, catalog_id),
    )
    .unwrap();
    std::fs::write(
        path.join(super::migrations::MIGRATION_MARKER_FILE),
        super::migrations::KV_TRANSITION_CHECKPOINT_MARKER,
    )
    .unwrap();
    let store =
        super::open_runtime_principal_store(&home, Arc::new(|_: &super::StateOwner| Ok(None)))
            .await
            .unwrap();
    assert_eq!(
        store.engine.root(&super::StateOwner::System).unwrap(),
        before
    );
    assert_eq!(
        store.kv().get("system:identity", "retained").await.unwrap(),
        Some(b"before-amendment".to_vec())
    );
    let large = vec![0x55; 512 * 1024];
    store
        .kv()
        .set("system:identity", "large", large.clone())
        .await
        .unwrap();
    store.engine.close().unwrap();
    drop(store);
    let reopened =
        super::open_runtime_principal_store(&home, Arc::new(|_: &super::StateOwner| Ok(None)))
            .await
            .unwrap();
    assert_eq!(
        reopened.kv().get("system:identity", "large").await.unwrap(),
        Some(large)
    );
    assert_eq!(
        reopened
            .kv()
            .get("system:identity", "retained")
            .await
            .unwrap(),
        Some(b"before-amendment".to_vec())
    );
    reopened.engine.close().unwrap();
}

#[tokio::test]
async fn pre_uid_retirement_catalogue_upgrade_preserves_root() {
    use crate::KvStore;
    use std::sync::Arc;

    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    super::runtime_tests::seed_legacy_layout(&home);
    let path = home.principal_store_path();
    let prior = pre_uid_retirement_specification();
    let prior_id = Blake3ObjectIdentityV1.identify(&prior);
    assert_eq!(prior_id, PRE_UID_RETIREMENT_FORMAT_SPEC_ID);
    let catalog = bootstrap::content_catalog_format_specification().unwrap();
    let catalog_id = Blake3ObjectIdentityV1.identify(&catalog);
    let engine = Arc::new(
        RuntimeEngine::open(
            &path,
            Blake3ObjectIdentityV1,
            StateOwnerCodecV2,
            RecoveryLimits::process_addressable(),
        )
        .unwrap(),
    );
    engine.persist_standalone_object(&prior).unwrap();
    engine.persist_standalone_object(&catalog).unwrap();
    let kv = super::RuntimeStore::from_engine(
        engine.clone(),
        super::StateOwnerResolver::new(super::PrincipalDirectory::default()),
    );
    kv.set(
        "system:identity",
        "retained",
        b"before-uid-amendment".to_vec(),
    )
    .await
    .unwrap();
    drop(kv);
    let before = engine.root(&super::StateOwner::System).unwrap();
    engine
        .ensure_direct_representation_catalogue(prior_id, &[prior_id, catalog_id])
        .unwrap();
    engine.close().unwrap();
    drop(engine);
    std::fs::write(
        path.join(STORE_METADATA_FILE),
        store_metadata(prior_id, catalog_id),
    )
    .unwrap();
    std::fs::write(
        path.join(super::migrations::MIGRATION_MARKER_FILE),
        super::migrations::KV_TRANSITION_CHECKPOINT_MARKER,
    )
    .unwrap();
    let store =
        super::open_runtime_principal_store(&home, Arc::new(|_: &super::StateOwner| Ok(None)))
            .await
            .unwrap();
    assert_eq!(
        store.engine.root(&super::StateOwner::System).unwrap(),
        before
    );
    assert_eq!(
        store.kv().get("system:identity", "retained").await.unwrap(),
        Some(b"before-uid-amendment".to_vec())
    );
    store.engine.close().unwrap();
}

#[test]
fn pre_uid_retirement_missing_catalog_rejects_before_successor_admission() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    super::runtime_tests::seed_legacy_layout(&home);
    let engine = RuntimeEngine::open(
        home.principal_store_path(),
        Blake3ObjectIdentityV1,
        StateOwnerCodecV2,
        RecoveryLimits::process_addressable(),
    )
    .unwrap();
    let prior = pre_uid_retirement_specification();
    let prior_id = Blake3ObjectIdentityV1.identify(&prior);
    engine.persist_standalone_object(&prior).unwrap();
    let catalog = bootstrap::content_catalog_format_specification().unwrap();
    let catalog_id = Blake3ObjectIdentityV1.identify(&catalog);
    let missing = prepare_catalog_specification(
        &engine,
        DestinationFormat::PriorV1 {
            format_spec: prior_id,
            catalog_spec_was_declared: true,
        },
        &catalog,
        catalog_id,
    )
    .unwrap_err();
    assert!(
        missing
            .to_string()
            .contains("missing its content catalog specification"),
        "{missing}"
    );
    let current = format_spec_record().unwrap();
    assert!(
        engine
            .object(Blake3ObjectIdentityV1.identify(&current))
            .unwrap()
            .is_none(),
        "rejected upgrade must not insert successor format evidence"
    );
    engine.close().unwrap();
}

pub(super) fn pre_uid_retirement_specification() -> crate::storage_model::ObjectRecord {
    use crate::storage_model::{ObjectClass, ObjectFormatVersion, ObjectKind, ObjectRecord};
    // Reconstruct the published predecessor from the amended grammar without
    // duplicating Section 13. The HEAD specification ended immediately after
    // the representation-index guarantees.
    let text = std::str::from_utf8(super::format_amendment::STORE_FORMAT_SPEC).unwrap();
    let (before, _) = text
        .split_once("13. IMMUTABLE PRINCIPAL RETIREMENT AND WORKSPACE DIRECTORY")
        .unwrap();
    let prior_text = format!("{before}END OF ASTRID PRINCIPAL STORE FORMAT 1\n");
    ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        prior_text.as_bytes().to_vec(),
        vec![],
        0,
        ObjectClass::Metadata,
    )
    .unwrap()
}

pub(super) fn pre_chunked_specification() -> crate::storage_model::ObjectRecord {
    use crate::storage_model::{ObjectClass, ObjectFormatVersion, ObjectKind, ObjectRecord};
    // Reconstruct the published predecessor from the amended grammar and
    // bind it to its real identity without duplicating the full specification.
    // Strip Section 13 first so the 7.1.2 rewind targets the pre-retirement text.
    let pre_uid = pre_uid_retirement_specification();
    let text = std::str::from_utf8(pre_uid.canonical_bytes()).unwrap();
    let (before, amendment) = text.split_once("7.1.2 Chunked KV spilled values").unwrap();
    let (_, after) = amendment
        .split_once("7.2 Content DAG, object format version 1")
        .unwrap();
    let prior_text = format!("{before}7.2 Content DAG, object format version 1{after}").replace(
        "target is a version-4 opaque or version-5 chunked Data KvLeaf\n              representing value_length bytes, as defined in section 7.1.2",
        "target is a version-4 Data KvLeaf of value_length bytes",
    );
    ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        prior_text.as_bytes().to_vec(),
        vec![],
        0,
        ObjectClass::Metadata,
    )
    .unwrap()
}
