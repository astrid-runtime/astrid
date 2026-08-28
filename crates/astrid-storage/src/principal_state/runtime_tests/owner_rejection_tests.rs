use super::*;

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
    let user = astrid_core::UserUid::from_bytes([11; 32]);
    let mut user_bytes = vec![3];
    user_bytes.extend_from_slice(user.as_bytes());
    assert_eq!(codec.encode_checked(&StateOwner::User(user)), None);
    assert!(codec.encode(&StateOwner::User(user)).is_empty());
    assert_eq!(codec.decode(&user_bytes), None);
    assert_eq!(codec.decode(&[]), None);
    assert_eq!(codec.decode(&[0, 0]), None);
    assert_eq!(codec.decode(&[1]), None);
    assert_eq!(codec.decode(&[1, b':']), None);
}

#[tokio::test]
async fn user_owner_writes_and_staging_reject_before_durable_mutation() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let user = astrid_core::UserUid::from_bytes([11; 32]);
    let owner = StateOwner::User(user);
    let name = ContentName::new("workspace/user.bin").unwrap();
    let home_tree_before = filesystem_snapshot(directory.path());

    assert!(store.engine.root(&owner).unwrap().is_none());
    let content_error = store
        .content()
        .put(&owner, &name, b"throwaway")
        .unwrap_err();
    assert!(matches!(
        content_error,
        PrincipalContentError::QuotaPolicy(StorageError::Internal(_))
    ));
    assert!(store.engine.root(&owner).unwrap().is_none());

    let staging_root = home.content_staging_path();
    let staging_before = filesystem_snapshot(&staging_root);
    let staging_error = store
        .staging()
        .begin(owner, name.clone(), ChunkingProfile::ASTRID_V1)
        .unwrap_err();
    assert!(staging_error.to_string().contains("user StateOwner"));
    assert_eq!(filesystem_snapshot(&staging_root), staging_before);

    drop(store);
    let reopened = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    assert!(reopened.engine.root(&owner).unwrap().is_none());
    assert_eq!(reopened.content().read(&owner, &name).unwrap(), None);
    assert!(reopened.staging().ready().unwrap().is_empty());
    assert_eq!(
        filesystem_snapshot(directory.path()),
        home_tree_before,
        "rejected user operations changed durable home bytes"
    );
}

#[test]
fn direct_engine_user_commit_rejects_without_durable_mutation() {
    let directory = tempfile::tempdir().unwrap();
    let owner = StateOwner::User(astrid_core::UserUid::from_bytes([11; 32]));
    let engine = RuntimeEngine::open(
        directory.path(),
        Blake3ObjectIdentityV1,
        StateOwnerCodecV2,
        RecoveryLimits::process_addressable(),
    )
    .unwrap();
    let roots_path = directory.path().join("roots.journal");
    let roots_before = std::fs::read(&roots_path).unwrap();
    let tree_before = filesystem_snapshot(directory.path());

    let commit = ObjectRecord::new(
        ObjectKind::Commit,
        ObjectFormatVersion::new(3).unwrap(),
        Vec::new(),
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let commit_id = Blake3ObjectIdentityV1.identify(&commit);
    let error = engine
        .commit(RootTransaction::new(owner, None, commit_id, Vec::new()))
        .unwrap_err();
    assert!(matches!(error, DurableError::UnsupportedPrincipal));
    assert_eq!(std::fs::read(&roots_path).unwrap(), roots_before);
    assert_eq!(filesystem_snapshot(directory.path()), tree_before);
    assert_eq!(engine.root(&owner).unwrap(), None);

    engine.close().unwrap();
    drop(engine);
    let reopened = RuntimeEngine::open(
        directory.path(),
        Blake3ObjectIdentityV1,
        StateOwnerCodecV2,
        RecoveryLimits::process_addressable(),
    )
    .unwrap();
    assert_eq!(reopened.root(&owner).unwrap(), None);
    assert_eq!(
        std::fs::read(&roots_path).unwrap(),
        roots_before,
        "reopening changed the roots journal"
    );
    reopened.close().unwrap();
}

#[test]
fn quota_less_user_streaming_rejects_without_arena_or_root_mutation() {
    let directory = tempfile::tempdir().unwrap();
    let owner = StateOwner::User(astrid_core::UserUid::from_bytes([11; 32]));
    let engine = Arc::new(
        RuntimeEngine::open(
            directory.path(),
            Blake3ObjectIdentityV1,
            StateOwnerCodecV2,
            RecoveryLimits::process_addressable(),
        )
        .unwrap(),
    );
    let store = NativePrincipalContentStore::from_engine(Arc::clone(&engine));
    let name = ContentName::new("user/streamed.bin").unwrap();
    let roots_path = directory.path().join("roots.journal");
    let arena_path = directory.path().join("objects.arena");
    let roots_before = std::fs::read(&roots_path).unwrap();
    let arena_before = std::fs::read(&arena_path).unwrap();

    let streaming_error = store
        .put_streaming(&owner, &name, b"throwaway".as_slice())
        .unwrap_err();
    assert!(match streaming_error {
        PrincipalContentError::Projection(PrincipalProjectionError::Engine(error)) => {
            error == "principal is not admitted by the durable owner codec"
        },
        _ => false,
    });

    let batch_error = store
        .put_streaming_batch(
            &owner,
            [ContentIngest::new(
                ContentName::new("user/bulk.bin").unwrap(),
                b"throwaway".as_slice(),
            )],
        )
        .unwrap_err();
    assert!(match batch_error {
        PrincipalContentError::Projection(PrincipalProjectionError::Engine(error)) => {
            error == "principal is not admitted by the durable owner codec"
        },
        _ => false,
    });
    assert_eq!(engine.root(&owner).unwrap(), None);
    assert_eq!(engine.object_count().unwrap(), 0);
    assert_eq!(std::fs::read(&arena_path).unwrap(), arena_before);
    assert_eq!(std::fs::read(&roots_path).unwrap(), roots_before);

    engine.flush_projection().unwrap();
    engine.close().unwrap();
    drop(store);
    drop(engine);
    let reopened = Arc::new(
        RuntimeEngine::open(
            directory.path(),
            Blake3ObjectIdentityV1,
            StateOwnerCodecV2,
            RecoveryLimits::process_addressable(),
        )
        .unwrap(),
    );
    assert_eq!(reopened.root(&owner).unwrap(), None);
    assert_eq!(reopened.object_count().unwrap(), 0);
    assert_eq!(std::fs::read(&arena_path).unwrap(), arena_before);
    assert_eq!(
        std::fs::read(&roots_path).unwrap(),
        roots_before,
        "reopening changed roots or arena after rejected User streaming"
    );
    reopened.close().unwrap();
}

#[test]
fn owner_codec_v3_preserves_legacy_forms_and_rejects_bad_user_bytes() {
    let codec = StateOwnerCodecV3;
    let principal = test_uid("alice");
    let fleet = astrid_core::FleetUid::from_bytes([7; 32]);
    let user = astrid_core::UserUid::from_bytes([11; 32]);

    let mut principal_bytes = vec![1];
    principal_bytes.extend_from_slice(principal.as_bytes());
    let mut fleet_bytes = vec![2];
    fleet_bytes.extend_from_slice(fleet.as_bytes());
    let mut user_bytes = vec![3];
    user_bytes.extend_from_slice(user.as_bytes());

    assert_eq!(
        codec.decode(&principal_bytes),
        Some(StateOwner::Principal(principal))
    );
    assert_eq!(codec.decode(&fleet_bytes), Some(StateOwner::Fleet(fleet)));
    assert_eq!(codec.decode(&user_bytes), Some(StateOwner::User(user)));
    assert_eq!(codec.encode(&StateOwner::System), [0]);
    assert_eq!(
        codec.encode(&StateOwner::Principal(principal)),
        principal_bytes
    );
    assert_eq!(codec.encode(&StateOwner::Fleet(fleet)), fleet_bytes);
    assert_eq!(codec.encode(&StateOwner::User(user)), user_bytes);

    for malformed in [
        &[0, 0][..],
        &[1][..],
        &[2, 7][..],
        &[3][..],
        &[3, 11][..],
        &[4][..],
        &[0xff][..],
    ] {
        assert_eq!(codec.decode(malformed), None);
    }
}
