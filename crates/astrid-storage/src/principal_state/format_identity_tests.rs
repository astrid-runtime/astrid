use super::runtime_tests::*;
use super::*;
use super::{
    DestinationFormat, PRE_DERIVATION_FORMAT_SPEC_ID, STORE_FORMAT_SPEC, STORE_METADATA_FILE,
    atomic_write, bootstrap, legacy_store_metadata, object_id_hex, persist_format_specification,
    prepare_catalog_specification, prepare_destination, prepare_format_specification,
    store_metadata,
};
use crate::storage_model::{
    ObjectFormatVersion, ObjectKind, ProfileKind, ReconstructionBounds, RepresentationProfile,
};

#[test]
fn owner_codec_round_trips_only_canonical_values() {
    let codec = StateOwnerCodecV2;
    let owners = [
        StateOwner::System,
        test_owner("alice"),
        StateOwner::Fleet(astrid_core::FleetUid::from_bytes([7; 32])),
    ];
    for owner in owners {
        let encoded = codec.encode(&owner);
        assert_eq!(codec.decode(&encoded), Some(owner));
    }
    assert_eq!(codec.decode(&[]), None);
    assert_eq!(codec.decode(&[0, 0]), None);
    assert_eq!(codec.decode(&[1]), None);
    assert_eq!(codec.decode(&[1, b':']), None);
}

#[test]
fn object_identity_v1_has_a_stable_golden_vector() {
    let record = ObjectRecord::new(
        ObjectKind::KvLeaf,
        ObjectFormatVersion::V1,
        b"hello".to_vec(),
        Vec::new(),
        0,
        ObjectClass::Data,
    )
    .unwrap();
    assert_eq!(
        Blake3ObjectIdentityV1.identify(&record).as_bytes(),
        &[
            14, 77, 237, 193, 155, 81, 194, 119, 35, 35, 59, 81, 40, 49, 0, 31, 232, 131, 137, 111,
            27, 237, 250, 91, 151, 7, 135, 21, 99, 27, 128, 55,
        ]
    );
}

#[test]
fn physical_identity_v1_matches_the_runatal_golden_vector() {
    let profile = RepresentationProfile::new_builtin(
        ProfileKind::DirectCanonical,
        ReconstructionBounds::new(
            8,
            32,
            8 * 1024 * 1024,
            16 * 1024 * 1024,
            1_000_000,
            32 * 1024 * 1024,
            5_000_000,
        )
        .unwrap(),
        ObjectId::new([1; 32]),
    )
    .unwrap()
    .encode()
    .unwrap();
    assert_eq!(
        Blake3PhysicalIdentityV1.identify("astrid-representation-profile-v1\0", &profile),
        [
            0x59, 0xc0, 0x99, 0x24, 0xb3, 0xb0, 0x72, 0x12, 0xc4, 0xbc, 0x10, 0x35, 0x35, 0xcf,
            0xbb, 0xe1, 0x0d, 0xee, 0xe3, 0x1d, 0x1b, 0x15, 0x7d, 0x21, 0x53, 0x8b, 0x17, 0x75,
            0x95, 0x23, 0x58, 0x04,
        ]
    );
}

#[test]
fn format_specification_has_a_tagged_metadata_identity() {
    let record = bootstrap::format_specification().unwrap();
    let id = Blake3ObjectIdentityV1.identify(&record);
    let catalog_id = Blake3ObjectIdentityV1
        .identify(&bootstrap::content_catalog_format_specification().unwrap());
    let metadata = String::from_utf8(store_metadata(id, catalog_id)).unwrap();

    assert_eq!(record.kind(), ObjectKind::Evidence);
    assert_eq!(record.canonical_bytes(), STORE_FORMAT_SPEC);
    assert!(record.references().is_empty());
    assert_eq!(
        object_id_hex(id),
        "ac3e1ab1e82be24dae7cdef949698dd54d2407bc7f39fb30709dc36677eea61d"
    );
    assert_eq!(
        object_id_hex(catalog_id),
        "8f3999b066b666396259c4a92f9de7c5b8e67df9d38a69fb4fb824968b56ecdb"
    );
    assert_eq!(
        metadata,
        "format=astrid-principal-store-v1\n\
         identity=blake3-object-identity-v1\n\
         identity-wire=tagged-identity-v1\n\
         format-spec-object=1:1:32:ac3e1ab1e82be24dae7cdef949698dd54d2407bc7f39fb30709dc36677eea61d\n\
         content-catalog-spec-object=1:1:32:8f3999b066b666396259c4a92f9de7c5b8e67df9d38a69fb4fb824968b56ecdb\n\
         representations=authoritative-direct-v1\n\
         principal-codec=state-owner-v2\n\
         projection=kv-transition-bplus-v4\n"
    );
}

#[test]
fn pre_derivation_v1_runatal_upgrade_is_idempotent_and_preserves_history() {
    let directory = tempfile::tempdir().unwrap();
    let store_path = directory.path().join("principal-store");
    std::fs::create_dir_all(&store_path).unwrap();
    let engine = RuntimeEngine::open(
        &store_path,
        Blake3ObjectIdentityV1,
        StateOwnerCodecV2,
        RecoveryLimits::process_addressable(),
    )
    .unwrap();
    let legacy_spec = ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        b"pre-derivation format 1 specification".to_vec(),
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let (legacy_spec_id, _) = engine.persist_standalone_object(&legacy_spec).unwrap();
    let current_spec = bootstrap::format_specification().unwrap();
    let current_spec_id = Blake3ObjectIdentityV1.identify(&current_spec);
    let catalog_spec = bootstrap::content_catalog_format_specification().unwrap();
    let catalog_spec_id = Blake3ObjectIdentityV1.identify(&catalog_spec);
    let current_metadata = store_metadata(current_spec_id, catalog_spec_id);
    atomic_write(
        &store_path.join(STORE_METADATA_FILE),
        &legacy_store_metadata(legacy_spec_id),
    )
    .unwrap();

    // Simulate a crash after the successor RÚNATAL object became durable
    // but before store.meta changed.
    persist_format_specification(&engine, &current_spec).unwrap();
    prepare_format_specification(
        &engine,
        DestinationFormat::PriorV1 {
            format_spec: legacy_spec_id,
            catalog_spec_was_declared: false,
        },
        &current_spec,
        current_spec_id,
    )
    .unwrap();
    prepare_catalog_specification(
        &engine,
        DestinationFormat::PriorV1 {
            format_spec: legacy_spec_id,
            catalog_spec_was_declared: false,
        },
        &catalog_spec,
        catalog_spec_id,
    )
    .unwrap();
    atomic_write(&store_path.join(STORE_METADATA_FILE), &current_metadata).unwrap();

    assert_eq!(
        std::fs::read(store_path.join(STORE_METADATA_FILE)).unwrap(),
        current_metadata
    );
    assert_eq!(engine.object(legacy_spec_id).unwrap(), Some(legacy_spec));
    assert_eq!(
        engine.object(current_spec_id).unwrap(),
        Some(current_spec.clone())
    );
    prepare_format_specification(
        &engine,
        DestinationFormat::Current,
        &current_spec,
        current_spec_id,
    )
    .unwrap();
    prepare_catalog_specification(
        &engine,
        DestinationFormat::Current,
        &catalog_spec,
        catalog_spec_id,
    )
    .unwrap();
    engine.close().unwrap();
}

#[test]
fn prior_metadata_that_declared_a_catalog_specification_requires_it() {
    let directory = tempfile::tempdir().unwrap();
    let engine = RuntimeEngine::open(
        directory.path(),
        Blake3ObjectIdentityV1,
        StateOwnerCodecV2,
        RecoveryLimits::process_addressable(),
    )
    .unwrap();
    let catalog_spec = bootstrap::content_catalog_format_specification().unwrap();
    let catalog_spec_id = Blake3ObjectIdentityV1.identify(&catalog_spec);
    let destination = DestinationFormat::PriorV1 {
        format_spec: PRE_DERIVATION_FORMAT_SPEC_ID,
        catalog_spec_was_declared: true,
    };

    let error = prepare_catalog_specification(&engine, destination, &catalog_spec, catalog_spec_id)
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("completed principal store is missing its content catalog specification"),
        "{error}"
    );
}

#[tokio::test]
async fn completed_pre_derivation_v1_store_is_selected_for_runatal_amendment() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    super::format_migration_tests::seed_current_directory_store(&home);

    let store_path = home.principal_store_path();
    std::fs::write(
        store_path.join(STORE_METADATA_FILE),
        legacy_store_metadata(PRE_DERIVATION_FORMAT_SPEC_ID),
    )
    .unwrap();
    let current_spec = bootstrap::format_specification().unwrap();
    let current_spec_id = Blake3ObjectIdentityV1.identify(&current_spec);
    let catalog_spec = bootstrap::content_catalog_format_specification().unwrap();
    let current_metadata = store_metadata(
        current_spec_id,
        Blake3ObjectIdentityV1.identify(&catalog_spec),
    );
    assert_eq!(
        prepare_destination(
            &store_path,
            &current_metadata,
            Blake3ObjectIdentityV1.identify(&catalog_spec),
        )
        .unwrap(),
        DestinationFormat::PriorV1 {
            format_spec: PRE_DERIVATION_FORMAT_SPEC_ID,
            catalog_spec_was_declared: false,
        }
    );
}
