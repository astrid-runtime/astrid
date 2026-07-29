use std::collections::BTreeMap;
use std::io::{Seek as _, SeekFrom, Write as _};
use std::path::Path;

use astrid_storage_engine::RootTransaction;
use astrid_storage_model::{
    ObjectClass, ObjectFormatVersion, ObjectKind, ObjectReference, ReferenceLabel, RootState,
};

use super::*;
use crate::content::{CONTENT_COMPONENT_LABEL, CatalogValue, LegacyCatalog, encode_legacy_catalog};
use crate::{ChunkingProfile, ContentName};

fn unlimited_quota() -> Arc<dyn KvQuotaResolver<StateOwner>> {
    Arc::new(|owner: &StateOwner| {
        Ok(match owner {
            StateOwner::System => None,
            StateOwner::Principal(_) => Some(u64::MAX),
        })
    })
}

#[cfg(not(target_os = "windows"))]
fn assert_reader_rejects_substituted_format_specification(home: &AstridHome, script: &Path) {
    let format_spec_id =
        Blake3ObjectIdentityV1.identify(&bootstrap::format_specification().unwrap());
    let catalog_spec_id = Blake3ObjectIdentityV1
        .identify(&bootstrap::content_catalog_format_specification().unwrap());
    let engine = RuntimeEngine::open(
        home.principal_store_path(),
        Blake3ObjectIdentityV1,
        StateOwnerCodecV1,
        RecoveryLimits::process_addressable(),
    )
    .unwrap();
    let replacement_spec = ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        b"self-consistent replacement format specification".to_vec(),
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let (replacement_id, inserted) = engine.persist_standalone_object(&replacement_spec).unwrap();
    assert_eq!(inserted, astrid_storage_model::InsertOutcome::Inserted);
    engine.close().unwrap();

    let metadata = home.principal_store_path().join(STORE_METADATA_FILE);
    std::fs::write(&metadata, store_metadata(replacement_id, catalog_spec_id)).unwrap();
    let substituted = std::process::Command::new("python3")
        .arg(script)
        .arg(home.principal_store_path())
        .output()
        .unwrap();
    assert!(
        !substituted.status.success(),
        "independent reader accepted a substituted format specification"
    );
    std::fs::write(metadata, store_metadata(format_spec_id, catalog_spec_id)).unwrap();
}

#[test]
fn owner_codec_round_trips_only_canonical_values() {
    let codec = StateOwnerCodecV1;
    let owners = [
        StateOwner::System,
        StateOwner::Principal(PrincipalId::new("alice").unwrap()),
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
        "32379c2a9e1d0fe166ac37f30d8772bd88d6c99a6ae31bb75cc7e8a8f4ce4307"
    );
    assert_eq!(
        object_id_hex(catalog_id),
        "8f3999b066b666396259c4a92f9de7c5b8e67df9d38a69fb4fb824968b56ecdb"
    );
    assert!(metadata.contains("identity-wire=tagged-identity-v1\n"));
    assert!(metadata.contains(&format!(
        "format-spec-object=1:1:32:{}\n",
        object_id_hex(id)
    )));
    assert!(metadata.contains(&format!(
        "content-catalog-spec-object=1:1:32:{}\n",
        object_id_hex(catalog_id)
    )));
}

#[test]
fn pre_derivation_v1_runatal_upgrade_is_idempotent_and_preserves_history() {
    let directory = tempfile::tempdir().unwrap();
    let store_path = directory.path().join("principal-store");
    std::fs::create_dir_all(&store_path).unwrap();
    let engine = RuntimeEngine::open(
        &store_path,
        Blake3ObjectIdentityV1,
        StateOwnerCodecV1,
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
        DestinationFormat::PriorV1(legacy_spec_id),
        &current_spec,
        current_spec_id,
    )
    .unwrap();
    prepare_catalog_specification(
        &engine,
        DestinationFormat::PriorV1(legacy_spec_id),
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

#[tokio::test]
async fn completed_pre_derivation_v1_store_is_selected_for_runatal_amendment() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let store = open_runtime_kv(&home, unlimited_quota()).await.unwrap();
    store.close().await.unwrap();
    drop(store);

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
        prepare_destination(&store_path, &current_metadata, current_spec_id).unwrap(),
        DestinationFormat::PriorV1(PRE_DERIVATION_FORMAT_SPEC_ID)
    );
}

#[tokio::test]
async fn new_store_persists_and_verifies_the_in_band_specification() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let store = open_runtime_kv(&home, unlimited_quota()).await.unwrap();
    store.close().await.unwrap();

    let record = bootstrap::format_specification().unwrap();
    let id = Blake3ObjectIdentityV1.identify(&record);
    let arena = std::fs::read(home.principal_store_path().join("objects.arena")).unwrap();
    assert_eq!(&arena[52..54], &1_u16.to_le_bytes());
    assert_eq!(&arena[54..56], &1_u16.to_le_bytes());
    assert_eq!(&arena[56..60], &32_u32.to_le_bytes());
    assert_eq!(&arena[60..92], id.as_bytes());

    let engine = RuntimeEngine::open(
        home.principal_store_path(),
        Blake3ObjectIdentityV1,
        StateOwnerCodecV1,
        RecoveryLimits::process_addressable(),
    )
    .unwrap();
    assert_eq!(engine.object(id).unwrap(), Some(record));
    drop(store);
}

async fn install_legacy_catalog_fixture(
    home: &AstridHome,
    owner: &StateOwner,
    name: &ContentName,
    bytes: &[u8],
) -> RootState {
    let store = open_runtime_principal_store(home, unlimited_quota())
        .await
        .unwrap();
    let published = store.content().put(owner, name, bytes).unwrap();
    drop(store);

    let engine = RuntimeEngine::open(
        home.principal_store_path(),
        Blake3ObjectIdentityV1,
        StateOwnerCodecV1,
        RecoveryLimits::process_addressable(),
    )
    .unwrap();
    let previous = engine.root(owner).unwrap().unwrap();
    let logical_bytes = u64::try_from(bytes.len()).unwrap();
    let quota_bytes = u64::try_from(bytes.len().checked_add(name.as_str().len()).unwrap()).unwrap();
    let legacy = LegacyCatalog {
        entries: BTreeMap::from([(
            name.clone(),
            CatalogValue {
                file: published.descriptor().file(),
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
    let legacy_root = engine
        .commit(RootTransaction::new(
            owner.clone(),
            Some(previous),
            commit_id,
            vec![
                (catalog_id, catalog),
                (state_id, state),
                (commit_id, commit),
            ],
        ))
        .unwrap()
        .root();
    engine.close().unwrap();

    std::fs::write(
        home.principal_store_path()
            .join(migrations::MIGRATION_MARKER_FILE),
        migrations::LEGACY_TO_V1_MARKER,
    )
    .unwrap();
    let format_spec_id =
        Blake3ObjectIdentityV1.identify(&bootstrap::format_specification().unwrap());
    std::fs::write(
        home.principal_store_path().join(STORE_METADATA_FILE),
        legacy_store_metadata(format_spec_id),
    )
    .unwrap();
    legacy_root
}

fn assert_catalog_tree_marker(home: &AstridHome) {
    assert_eq!(
        std::fs::read(
            home.principal_store_path()
                .join(migrations::MIGRATION_MARKER_FILE)
        )
        .unwrap(),
        migrations::CATALOG_TREE_MARKER
    );
}

#[tokio::test]
async fn flat_content_catalog_migration_resumes_and_is_idempotent() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let owner = StateOwner::Principal(PrincipalId::new("alice").unwrap());
    let name = ContentName::new("workspace/legacy.bin").unwrap();
    let bytes = b"legacy content survives the catalog migration";
    let legacy_root = install_legacy_catalog_fixture(&home, &owner, &name, bytes).await;

    let migrated = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    assert_eq!(migrated.validated_catalog_count(), 1);
    assert_eq!(
        migrated.content().read(&owner, &name).unwrap(),
        Some(bytes.to_vec())
    );
    drop(migrated);
    let migrated_engine = RuntimeEngine::open(
        home.principal_store_path(),
        Blake3ObjectIdentityV1,
        StateOwnerCodecV1,
        RecoveryLimits::process_addressable(),
    )
    .unwrap();
    let migrated_root = migrated_engine.root(&owner).unwrap().unwrap();
    assert_eq!(
        migrated_root.generation,
        legacy_root.generation.checked_next().unwrap()
    );
    migrated_engine.close().unwrap();
    assert_catalog_tree_marker(&home);
    let migrated_metadata =
        std::fs::read_to_string(home.principal_store_path().join(STORE_METADATA_FILE)).unwrap();
    assert!(migrated_metadata.contains("content-catalog-spec-object="));
    std::fs::write(
        home.principal_store_path()
            .join(migrations::MIGRATION_MARKER_FILE),
        migrations::LEGACY_TO_V1_MARKER,
    )
    .unwrap();

    let reopened = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    assert_eq!(
        reopened.content().read(&owner, &name).unwrap(),
        Some(bytes.to_vec())
    );
    drop(reopened);
    let reopened_engine = RuntimeEngine::open(
        home.principal_store_path(),
        Blake3ObjectIdentityV1,
        StateOwnerCodecV1,
        RecoveryLimits::process_addressable(),
    )
    .unwrap();
    assert_eq!(reopened_engine.root(&owner).unwrap(), Some(migrated_root));
    assert_catalog_tree_marker(&home);
}

#[tokio::test]
async fn native_stage_acknowledges_before_ingest_and_publishes_on_a_blocking_worker() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let owner = StateOwner::Principal(PrincipalId::new("alice").unwrap());
    let name = ContentName::new("workspace/target/release/game").unwrap();
    let mut writer = store
        .staging()
        .begin(owner.clone(), name.clone(), ChunkingProfile::ASTRID_V1)
        .unwrap();
    writer.write_all(b"linux build.......").unwrap();
    writer.seek(SeekFrom::Start(12)).unwrap();
    writer.write_all(b"artifact").unwrap();
    writer.set_len(20).unwrap();
    let staged = writer.seal().unwrap();

    assert_eq!(staged.logical_bytes(), 20);
    assert_eq!(store.content().describe(&owner, &name).unwrap(), None);
    assert_eq!(store.staging().ready().unwrap(), vec![staged.clone()]);

    let outcome = store.publish_staged(staged).await.unwrap();
    assert_eq!(outcome.descriptor().logical_bytes(), 20);
    assert_eq!(
        store.content().read(&owner, &name).unwrap(),
        Some(b"linux build.artifact".to_vec())
    );
    assert!(store.staging().ready().unwrap().is_empty());
    drop(store);

    let reopened = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    assert_eq!(
        reopened.content().read(&owner, &name).unwrap(),
        Some(b"linux build.artifact".to_vec())
    );
}

#[tokio::test]
async fn staged_publication_retries_after_root_commit_before_cleanup() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let owner = StateOwner::Principal(PrincipalId::new("alice").unwrap());
    let name = ContentName::new("workspace/retry.bin").unwrap();
    let mut writer = store
        .staging()
        .begin(owner.clone(), name.clone(), ChunkingProfile::ASTRID_V1)
        .unwrap();
    writer.write_all(b"one identity").unwrap();
    let staged = writer.seal().unwrap();

    let source = native_io::open_private_file(&staged.content_path()).unwrap();
    let first = store
        .content()
        .put_streaming(&owner, &name, source)
        .unwrap();
    assert_eq!(store.staging().ready().unwrap(), vec![staged.clone()]);

    let retried = store.publish_staged(staged).await.unwrap();
    assert_eq!(retried.descriptor(), first.descriptor());
    assert_eq!(retried.principal_root(), first.principal_root());
    assert_eq!(retried.objects_inserted(), 0);
    assert!(store.staging().ready().unwrap().is_empty());
}

#[tokio::test]
async fn staged_publication_enforces_close_order_for_the_same_name() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let owner = StateOwner::Principal(PrincipalId::new("alice").unwrap());
    let name = ContentName::new("workspace/order.txt").unwrap();
    let mut first = store
        .staging()
        .begin(owner.clone(), name.clone(), ChunkingProfile::ASTRID_V1)
        .unwrap();
    first.write_all(b"first close").unwrap();
    let first = first.seal().unwrap();
    let mut second = store
        .staging()
        .begin(owner.clone(), name.clone(), ChunkingProfile::ASTRID_V1)
        .unwrap();
    second.write_all(b"second close").unwrap();
    let second = second.seal().unwrap();

    let error = store.publish_staged(second.clone()).await.unwrap_err();
    assert!(error.to_string().contains("earlier close"));
    store.publish_staged(first).await.unwrap();
    store.publish_staged(second).await.unwrap();
    assert_eq!(
        store.content().read(&owner, &name).unwrap(),
        Some(b"second close".to_vec())
    );
}

#[cfg(not(target_os = "windows"))]
#[tokio::test]
async fn independent_reader_accepts_a_rust_produced_store() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let store = open_runtime_kv(&home, unlimited_quota()).await.unwrap();
    store
        .set("alice:capsule:shell", "cwd", b"/workspace".to_vec())
        .await
        .unwrap();
    store.close().await.unwrap();
    drop(store);

    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/runatal_v1_reader.py");
    let output = std::process::Command::new("python3")
        .arg(&script)
        .arg(home.principal_store_path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "independent reader failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let decoded: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(decoded["roots"]["alice"]["generation"], 0);
    assert!(
        decoded["roots"]["alice"]["commit"]
            .as_str()
            .unwrap()
            .starts_with("1:1:32:")
    );
    assert!(
        decoded["objects"]
            .as_array()
            .unwrap()
            .iter()
            .any(|object| object["kind"] == "Evidence")
    );
    assert!(
        decoded["objects"]
            .as_array()
            .unwrap()
            .iter()
            .any(|object| object["kind"] == "Commit")
    );
    assert_eq!(
        decoded["content_catalog_spec_object"],
        format!(
            "1:1:32:{}",
            object_id_hex(
                Blake3ObjectIdentityV1
                    .identify(&bootstrap::content_catalog_format_specification().unwrap(),)
            )
        )
    );

    assert_reader_rejects_substituted_format_specification(&home, &script);

    let arena_path = home.principal_store_path().join("objects.arena");
    let mut arena = std::fs::read(&arena_path).unwrap();
    arena[100] ^= 0x80;
    std::fs::write(&arena_path, arena).unwrap();
    let rejected = std::process::Command::new("python3")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/runatal_v1_reader.py"))
        .arg(home.principal_store_path())
        .output()
        .unwrap();
    assert!(
        !rejected.status.success(),
        "independent reader accepted a corrupt Rust-produced store"
    );
}

#[tokio::test]
async fn completed_store_does_not_self_heal_a_missing_runatal_object() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let path = home.principal_store_path();
    std::fs::create_dir_all(&path).unwrap();
    let record = bootstrap::format_specification().unwrap();
    let id = Blake3ObjectIdentityV1.identify(&record);
    let catalog_id = Blake3ObjectIdentityV1
        .identify(&bootstrap::content_catalog_format_specification().unwrap());
    std::fs::write(
        path.join(STORE_METADATA_FILE),
        store_metadata(id, catalog_id),
    )
    .unwrap();
    drop(
        RuntimeEngine::open(
            &path,
            Blake3ObjectIdentityV1,
            StateOwnerCodecV1,
            RecoveryLimits::process_addressable(),
        )
        .unwrap(),
    );
    std::fs::write(
        path.join(migrations::MIGRATION_MARKER_FILE),
        b"migration=surrealkv-to-principal-store\nfrom=legacy\nto=1\n",
    )
    .unwrap();

    let Err(error) = open_runtime_kv(&home, unlimited_quota()).await else {
        panic!("completed store without its RÚNATAL object was accepted");
    };
    assert!(
        error
            .to_string()
            .contains("missing its in-band format specification")
    );
}

#[tokio::test]
async fn current_metadata_does_not_self_heal_a_missing_catalog_specification() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let path = home.principal_store_path();
    std::fs::create_dir_all(&path).unwrap();
    let format_spec = bootstrap::format_specification().unwrap();
    let format_id = Blake3ObjectIdentityV1.identify(&format_spec);
    let catalog_id = Blake3ObjectIdentityV1
        .identify(&bootstrap::content_catalog_format_specification().unwrap());
    std::fs::write(
        path.join(STORE_METADATA_FILE),
        store_metadata(format_id, catalog_id),
    )
    .unwrap();
    let engine = RuntimeEngine::open(
        &path,
        Blake3ObjectIdentityV1,
        StateOwnerCodecV1,
        RecoveryLimits::process_addressable(),
    )
    .unwrap();
    engine.persist_standalone_object(&format_spec).unwrap();
    engine.close().unwrap();
    std::fs::write(
        path.join(migrations::MIGRATION_MARKER_FILE),
        migrations::CATALOG_TREE_MARKER,
    )
    .unwrap();

    let Err(error) = open_runtime_kv(&home, unlimited_quota()).await else {
        panic!("completed store without its catalog specification was accepted");
    };
    assert!(
        error
            .to_string()
            .contains("missing its content catalog specification")
    );
}

#[test]
fn namespace_owner_fails_closed_at_the_host_stamped_boundary() {
    let resolver = StateOwnerResolver;
    assert_eq!(
        resolver.resolve("system:identity").unwrap(),
        StateOwner::System
    );
    assert_eq!(
        resolver.resolve("alice:capsule:shell").unwrap(),
        StateOwner::Principal(PrincipalId::new("alice").unwrap())
    );
    assert!(matches!(
        resolver.resolve("alice:capsule:"),
        Err(StorageError::InvalidKey(message))
            if message.contains("empty capsule identifier")
    ));
}

#[cfg(feature = "legacy-surrealkv")]
#[tokio::test]
async fn first_boot_migrates_verifies_and_preserves_legacy_state() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let legacy = SurrealKvStore::open(home.state_db_path()).unwrap();
    legacy
        .set("system:identity", "root", b"default".to_vec())
        .await
        .unwrap();
    legacy
        .set("alice:capsule:shell", "cwd", b"/workspace".to_vec())
        .await
        .unwrap();
    legacy
        .set("bob:capsule:build", "toolchain", b"rust".to_vec())
        .await
        .unwrap();
    legacy.close().await.unwrap();

    let store = open_runtime_kv(&home, unlimited_quota()).await.unwrap();
    assert_eq!(
        store.get("system:identity", "root").await.unwrap(),
        Some(b"default".to_vec())
    );
    assert_eq!(
        store.get("alice:capsule:shell", "cwd").await.unwrap(),
        Some(b"/workspace".to_vec())
    );
    assert_eq!(
        store.get("bob:capsule:build", "toolchain").await.unwrap(),
        Some(b"rust".to_vec())
    );
    assert!(
        home.principal_store_path()
            .join(migrations::MIGRATION_MARKER_FILE)
            .exists()
    );
    store.close().await.unwrap();
    drop(store);

    let legacy = SurrealKvStore::open(home.state_db_path()).unwrap();
    assert_eq!(
        legacy.get("alice:capsule:shell", "cwd").await.unwrap(),
        Some(b"/workspace".to_vec())
    );
    legacy
        .set("alice:capsule:shell", "legacy-only", b"stale".to_vec())
        .await
        .unwrap();
    legacy.close().await.unwrap();

    let reopened = open_runtime_kv(&home, unlimited_quota()).await.unwrap();
    assert_eq!(
        reopened
            .get("alice:capsule:shell", "legacy-only")
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        reopened.get("alice:capsule:shell", "cwd").await.unwrap(),
        Some(b"/workspace".to_vec())
    );
}

#[tokio::test]
async fn live_quota_blocks_growth_but_allows_recovery_and_system_state() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|owner: &StateOwner| {
        Ok(match owner {
            StateOwner::System => None,
            StateOwner::Principal(_) => Some(27),
        })
    });
    let store = open_runtime_kv(&home, quota).await.unwrap();

    store
        .set("alice:capsule:shell", "one", b"1234".to_vec())
        .await
        .unwrap();
    assert!(matches!(
        store.set("alice:capsule:shell", "two", b"5".to_vec()).await,
        Err(StorageError::Internal(message))
            if message
                == "storage quota exceeded: mutation would use 51 bytes (limit 27)"
    ));
    store
        .set("alice:capsule:shell", "one", b"123".to_vec())
        .await
        .unwrap();
    assert!(store.delete("alice:capsule:shell", "one").await.unwrap());
    store
        .set("alice:capsule:shell", "two", b"1234".to_vec())
        .await
        .unwrap();
    assert!(matches!(
        store.set("alice:capsule:shell", "empty", Vec::new()).await,
        Err(StorageError::Internal(message))
            if message
                == "storage quota exceeded: mutation would use 52 bytes (limit 27)"
    ));
    store
        .set("system:identity", "unmetered", vec![0; 64])
        .await
        .unwrap();
}

#[tokio::test]
async fn incomplete_destination_is_quarantined_before_reimport() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    std::fs::create_dir_all(home.principal_store_path()).unwrap();
    std::fs::write(home.principal_store_path().join("partial"), b"incomplete").unwrap();

    let store = open_runtime_kv(&home, unlimited_quota()).await.unwrap();
    assert!(
        home.var_dir()
            .join("principal-store.incomplete.0")
            .join("partial")
            .exists()
    );
    assert!(
        home.principal_store_path()
            .join(migrations::MIGRATION_MARKER_FILE)
            .exists()
    );
    drop(store);
}

#[cfg(not(feature = "legacy-surrealkv"))]
#[tokio::test]
async fn legacy_source_requires_the_transition_feature() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    std::fs::create_dir_all(home.state_db_path()).unwrap();

    let Err(error) = open_runtime_kv(&home, unlimited_quota()).await else {
        panic!("legacy source opened without transition support");
    };
    assert!(
        error
            .to_string()
            .contains("rebuild with the legacy-surrealkv feature")
    );
}

#[tokio::test]
async fn durable_point_update_has_height_bounded_write_amplification() {
    let directory = tempfile::tempdir().unwrap();
    let limits = RecoveryLimits::new(1024 * 1024).unwrap();
    let engine = Arc::new(
        RuntimeEngine::open(
            directory.path(),
            Blake3ObjectIdentityV1,
            StateOwnerCodecV1,
            limits,
        )
        .unwrap(),
    );
    let store = RuntimeStore::from_engine(Arc::clone(&engine), StateOwnerResolver);
    for value in 0..256_u32 {
        store
            .set(
                "alice:capsule:build",
                &format!("{value:04}"),
                value.to_le_bytes().to_vec(),
            )
            .await
            .unwrap();
    }
    let before = engine.object_count().unwrap();
    store
        .set("alice:capsule:build", "0128", b"replacement".to_vec())
        .await
        .unwrap();
    let inserted = engine.object_count().unwrap().saturating_sub(before);
    assert!(
        inserted <= 16,
        "one point update inserted {inserted} objects for a 256-key tree"
    );
    store.close().await.unwrap();
    drop(store);
    drop(engine);

    let reopened = Arc::new(
        RuntimeEngine::open(
            directory.path(),
            Blake3ObjectIdentityV1,
            StateOwnerCodecV1,
            limits,
        )
        .unwrap(),
    );
    let store = RuntimeStore::from_engine(reopened, StateOwnerResolver);
    assert_eq!(
        store.get("alice:capsule:build", "0128").await.unwrap(),
        Some(b"replacement".to_vec())
    );
}
