use super::runtime_tests::*;
use super::*;
use crate::volume::AstridVolume as _;

#[tokio::test]
async fn new_store_persists_and_verifies_the_in_band_specification() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();

    let record = bootstrap::format_specification().unwrap();
    let id = Blake3ObjectIdentityV1.identify(&record);
    assert_eq!(store.engine.object(id).unwrap(), Some(record.clone()));
    assert!(home.storage_volume_path().is_file());
    assert!(!home.principal_store_path().exists());
    store.engine.close().unwrap();
    drop(store);

    let reopened = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    assert_eq!(reopened.engine.object(id).unwrap(), Some(record));
    assert!(!home.principal_store_path().exists());
    reopened
        .retire_verified_legacy_directory_store(&home)
        .unwrap();
    assert!(!home.principal_store_path().exists());
}

#[tokio::test]
async fn explicit_close_releases_the_hosted_volume_while_store_references_remain() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let retained_engine = Arc::clone(&store.engine);
    retained_engine.close().unwrap();

    let reopened = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    reopened.engine.close().unwrap();
    drop(reopened);
    drop(store);
    drop(retained_engine);
}

#[tokio::test]
async fn volume_without_its_cutover_receipt_fails_closed() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let store = open_runtime_kv(&home, unlimited_quota()).await.unwrap();
    store.close().await.unwrap();
    drop(store);

    let volume = crate::volume::HostedFileVolume::open(home.storage_volume_path()).unwrap();
    let receipt =
        crate::volume::VolumeRegion::new("system/migrations/directory-store-to-volume-v1").unwrap();
    volume.remove_region(&receipt).unwrap();
    volume.sync().unwrap();
    drop(volume);

    let Err(error) = open_runtime_kv(&home, unlimited_quota()).await else {
        panic!("volume without a cutover receipt unexpectedly reopened");
    };
    assert!(error.to_string().contains("cutover receipt"), "{error}");
}

#[tokio::test]
async fn changed_surviving_directory_store_is_rejected_by_post_barrier_retirement() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    super::format_migration_tests::seed_current_directory_store(&home);
    let migrated = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    migrated.engine.close().unwrap();
    drop(migrated);
    assert!(home.principal_store_path().is_dir());
    let source = Arc::new(
        RuntimeEngine::open(
            home.principal_store_path(),
            Blake3ObjectIdentityV1,
            StateOwnerCodecV2,
            RecoveryLimits::process_addressable(),
        )
        .unwrap(),
    );
    let changed = RuntimeStore::from_engine(
        Arc::clone(&source),
        StateOwnerResolver::new(test_directory(&["alice"])),
    );
    changed
        .set("alice:capsule:shell", "drift", b"changed".to_vec())
        .await
        .unwrap();
    source.close().unwrap();
    drop(changed);
    drop(source);

    let reopened = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let error = reopened
        .retire_verified_legacy_directory_store(&home)
        .expect_err("changed surviving source must not be retired");
    assert!(error.to_string().contains("cutover receipt"), "{error}");
    assert!(home.principal_store_path().exists());
}

fn replace_catalog_with_legacy(
    engine: &RuntimeEngine,
    owner: &StateOwner,
    name: &ContentName,
    file: ObjectId,
    logical_bytes: u64,
) -> RootState {
    let previous = engine.root(owner).unwrap().unwrap();
    let quota_bytes = logical_bytes
        .checked_add(u64::try_from(name.as_str().len()).unwrap())
        .unwrap();
    let legacy = LegacyCatalog {
        entries: BTreeMap::from([(
            name.clone(),
            CatalogValue {
                file,
                logical_bytes,
            },
        )]),
        logical_bytes,
        quota_bytes,
    };
    let catalog = encode_legacy_catalog(&legacy).unwrap();
    let catalog_id = Blake3ObjectIdentityV1.identify(&catalog);
    let graph_version = ObjectFormatVersion::new(3).unwrap();
    let state = ObjectRecord::new(
        ObjectKind::PrincipalState,
        graph_version,
        Vec::new(),
        vec![ObjectReference::owns(
            ReferenceLabel::new(CONTENT_COMPONENT_LABEL.to_vec()),
            catalog_id,
        )],
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let state_id = Blake3ObjectIdentityV1.identify(&state);
    let commit = ObjectRecord::new(
        ObjectKind::Commit,
        graph_version,
        Vec::new(),
        vec![
            ObjectReference::new(
                ReferenceLabel::new(b"parent".to_vec()),
                previous.commit,
                ReferenceKind::Lineage,
            ),
            ObjectReference::owns(ReferenceLabel::new(b"state".to_vec()), state_id),
        ],
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let commit_id = Blake3ObjectIdentityV1.identify(&commit);
    engine
        .commit(RootTransaction::new(
            *owner,
            Some(previous),
            commit_id,
            vec![
                (catalog_id, catalog),
                (state_id, state),
                (commit_id, commit),
            ],
        ))
        .unwrap()
        .root()
}

fn mark_store_as_legacy(home: &AstridHome) {
    std::fs::write(
        home.principal_store_path()
            .join(migrations::MIGRATION_MARKER_FILE),
        migrations::LEGACY_TO_V1_MARKER,
    )
    .unwrap();
}

pub(super) fn install_legacy_catalog_fixtures(
    home: &AstridHome,
    fixtures: &[(&StateOwner, &ContentName, &[u8])],
) -> BTreeMap<StateOwner, RootState> {
    super::format_migration_tests::seed_current_directory_store(home);
    let engine = Arc::new(
        RuntimeEngine::open(
            home.principal_store_path(),
            Blake3ObjectIdentityV1,
            StateOwnerCodecV2,
            RecoveryLimits::process_addressable(),
        )
        .unwrap(),
    );
    let store = NativePrincipalContentStore::from_engine(Arc::clone(&engine));
    let published: Vec<_> = fixtures
        .iter()
        .map(|(owner, name, bytes)| {
            (
                **owner,
                (*name).clone(),
                store.put(owner, name, bytes).unwrap(),
            )
        })
        .collect();
    let legacy_roots = published
        .into_iter()
        .map(|(owner, name, outcome)| {
            let descriptor = outcome.descriptor();
            let root = replace_catalog_with_legacy(
                engine.as_ref(),
                &owner,
                &name,
                descriptor.file(),
                descriptor.logical_bytes(),
            );
            (owner, root)
        })
        .collect();
    drop(store);
    engine.close().unwrap();
    drop(engine);
    mark_store_as_legacy(home);
    legacy_roots
}
