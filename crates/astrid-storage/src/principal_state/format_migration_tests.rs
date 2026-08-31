//! Selection coverage for known in-place format-1 RÚNATAL amendments.

use crate::engine::{PrincipalCodec, RecoveryLimits};
use crate::storage_model::{ObjectId, ObjectIdentity};

use super::bootstrap;
use super::format_amendment::{
    DestinationFormat, PRE_BOTTOM_K_SKETCH_FORMAT_SPEC_ID, PRE_COMPACTION_FORMAT_SPEC_ID,
    PRE_DENSE_RADIX_FORMAT_SPEC_ID, PRE_FASTCDC_FREEZE_FORMAT_SPEC_ID,
    PRE_FLEET_OWNER_FORMAT_SPEC_ID, PRE_GC_OUTBOX_FORMAT_SPEC_ID, PRE_KV_TRANSITION_FORMAT_SPEC_ID,
    PRE_MECHANICAL_AUDIT_FORMAT_SPEC_ID, PRE_PHYSICAL_CATALOGUE_FORMAT_SPEC_ID,
    PRE_RESERVED_REPRESENTATION_TAG_FORMAT_SPEC_ID, PRE_RUNATAL_NAMING_FORMAT_SPEC_ID,
    PRE_SHA384_ATTESTATION_FORMAT_SPEC_ID, PRE_WORKSPACE_BRANCH_FORMAT_SPEC_ID,
    STORE_METADATA_FILE, format_spec_record, legacy_store_metadata, pre_fleet_owner_store_metadata,
    pre_representation_store_metadata, prepare_catalog_specification, prepare_destination,
    prepare_format_specification, previous_store_metadata, representation_bootstrap_objects,
    store_metadata,
};
use super::{
    Blake3ObjectIdentityV1, RuntimeEngine, RuntimeStateOwnerCodecV2, StateOwnerCodecV1,
    StateOwnerV1,
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
        RuntimeStateOwnerCodecV2,
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
