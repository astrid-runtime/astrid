use std::collections::BTreeMap;
use std::io::{Seek as _, SeekFrom, Write as _};
use std::path::Path;
use std::time::{Duration, Instant};

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

fn chunker_golden_source(length: usize) -> Vec<u8> {
    let mut state = 0x4d59_5df4_d0f3_3173_u64;
    (0..length)
        .map(|_| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            ((state >> 37) & 0xff) as u8
        })
        .collect()
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

#[cfg(not(target_os = "windows"))]
fn assert_reader_requires_catalog_specification(home: &AstridHome, script: &Path) {
    let metadata = home.principal_store_path().join(STORE_METADATA_FILE);
    let current = std::fs::read_to_string(&metadata).unwrap();
    let without_catalog = current
        .lines()
        .filter(|line| !line.starts_with("content-catalog-spec-object="))
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(&metadata, format!("{without_catalog}\n")).unwrap();
    let rejected = std::process::Command::new("python3")
        .arg(script)
        .arg(home.principal_store_path())
        .output()
        .unwrap();
    assert!(
        !rejected.status.success(),
        "independent reader accepted metadata without its catalog specification"
    );
    std::fs::write(metadata, current).unwrap();
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
        "55c88679f00f3f8249eaf847fe4fba889f3f9f09e01048f5eb00e2d0d80c8e93"
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
        StateOwnerCodecV1,
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

async fn install_legacy_catalog_fixtures(
    home: &AstridHome,
    fixtures: &[(&StateOwner, &ContentName, &[u8])],
) -> BTreeMap<StateOwner, RootState> {
    let store = open_runtime_principal_store(home, unlimited_quota())
        .await
        .unwrap();
    let published: Vec<_> = fixtures
        .iter()
        .map(|(owner, name, bytes)| {
            (
                (*owner).clone(),
                (*name).clone(),
                store.content().put(owner, name, bytes).unwrap(),
            )
        })
        .collect();
    drop(store);

    let engine = RuntimeEngine::open(
        home.principal_store_path(),
        Blake3ObjectIdentityV1,
        StateOwnerCodecV1,
        RecoveryLimits::process_addressable(),
    )
    .unwrap();
    let legacy_roots = published
        .into_iter()
        .map(|(owner, name, outcome)| {
            let descriptor = outcome.descriptor();
            let root = replace_catalog_with_legacy(
                &engine,
                &owner,
                &name,
                descriptor.file(),
                descriptor.logical_bytes(),
            );
            (owner, root)
        })
        .collect();
    engine.close().unwrap();
    mark_store_as_legacy(home);
    legacy_roots
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

#[derive(Debug)]
struct CatalogWorkloadMetrics {
    arena_bytes: u64,
    root_journal_bytes: u64,
    publication_time: Duration,
    reopen_time: Duration,
}

fn durable_file_len(home: &AstridHome, name: &str) -> u64 {
    std::fs::metadata(home.principal_store_path().join(name))
        .unwrap()
        .len()
}

async fn measure_catalog_publications(unique_content: bool) -> CatalogWorkloadMetrics {
    const PUBLICATIONS: u64 = 1_000;
    const CONTENT_BYTES: usize = 4 * 1024;

    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let owner = StateOwner::Principal(PrincipalId::new("catalog-probe").unwrap());
    let store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let arena_before = durable_file_len(&home, "objects.arena");
    let roots_before = durable_file_len(&home, "roots.journal");
    let started = Instant::now();
    for index in 0..PUBLICATIONS {
        let name = ContentName::new(format!("workspace/fixture/{index:04}")).unwrap();
        let mut bytes = vec![7_u8; CONTENT_BYTES];
        if unique_content {
            bytes[..8].copy_from_slice(&index.to_le_bytes());
        }
        store.content().put(&owner, &name, &bytes).unwrap();
    }
    let publication_time = started.elapsed();
    let arena_bytes = durable_file_len(&home, "objects.arena")
        .checked_sub(arena_before)
        .unwrap();
    let root_journal_bytes = durable_file_len(&home, "roots.journal")
        .checked_sub(roots_before)
        .unwrap();
    drop(store);

    let reopen_started = Instant::now();
    let reopened = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let reopen_time = reopen_started.elapsed();
    assert_eq!(
        reopened.content().list(&owner).unwrap().len(),
        usize::try_from(PUBLICATIONS).unwrap()
    );
    drop(reopened);

    CatalogWorkloadMetrics {
        arena_bytes,
        root_journal_bytes,
        publication_time,
        reopen_time,
    }
}

#[tokio::test]
async fn thousand_deduplicated_four_kib_publications_bound_durable_arena_growth() {
    const PUBLICATIONS: u64 = 1_000;
    const MAX_ARENA_BYTES_PER_PUBLICATION: u64 = 16 * 1024;

    let metrics = measure_catalog_publications(false).await;
    assert!(
        metrics.arena_bytes
            < PUBLICATIONS
                .checked_mul(MAX_ARENA_BYTES_PER_PUBLICATION)
                .unwrap(),
        "deduplicated publications appended unexpected arena bytes: {metrics:?}"
    );
}

#[tokio::test]
#[ignore = "explicit durable catalog amplification and reopen probe"]
async fn catalog_durable_performance_probe() {
    let duplicate = measure_catalog_publications(false).await;
    let unique = measure_catalog_publications(true).await;
    for (name, metrics) in [("duplicate", duplicate), ("unique", unique)] {
        eprintln!(
            "{name}: arena={} roots={} publication={:?} reopen={:?}",
            metrics.arena_bytes,
            metrics.root_journal_bytes,
            metrics.publication_time,
            metrics.reopen_time
        );
    }
}

#[tokio::test]
async fn flat_content_catalog_migration_resumes_and_is_idempotent() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let alice = StateOwner::Principal(PrincipalId::new("alice").unwrap());
    let bob = StateOwner::Principal(PrincipalId::new("bob").unwrap());
    let alice_name = ContentName::new("workspace/alice-legacy.bin").unwrap();
    let bob_name = ContentName::new("workspace/bob-legacy.bin").unwrap();
    let alice_bytes = b"alice content survives the catalog migration";
    let bob_bytes = b"bob content survives the catalog migration";
    let legacy_roots = install_legacy_catalog_fixtures(
        &home,
        &[
            (&alice, &alice_name, alice_bytes),
            (&bob, &bob_name, bob_bytes),
        ],
    )
    .await;

    let engine = Arc::new(
        RuntimeEngine::open(
            home.principal_store_path(),
            Blake3ObjectIdentityV1,
            StateOwnerCodecV1,
            RecoveryLimits::process_addressable(),
        )
        .unwrap(),
    );
    let content = NativePrincipalContentStore::from_engine(Arc::clone(&engine));
    assert!(content.migrate_legacy_catalog(&alice).unwrap());
    let partially_migrated_alice_root = engine.root(&alice).unwrap().unwrap();
    assert_eq!(engine.root(&bob).unwrap(), legacy_roots.get(&bob).copied());
    drop(content);
    engine.close().unwrap();
    drop(engine);

    let migrated = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    assert_eq!(migrated.validated_catalog_count(), 2);
    assert_eq!(
        migrated.content().read(&alice, &alice_name).unwrap(),
        Some(alice_bytes.to_vec())
    );
    assert_eq!(
        migrated.content().read(&bob, &bob_name).unwrap(),
        Some(bob_bytes.to_vec())
    );
    drop(migrated);
    let migrated_engine = RuntimeEngine::open(
        home.principal_store_path(),
        Blake3ObjectIdentityV1,
        StateOwnerCodecV1,
        RecoveryLimits::process_addressable(),
    )
    .unwrap();
    let migrated_alice_root = migrated_engine.root(&alice).unwrap().unwrap();
    let migrated_bob_root = migrated_engine.root(&bob).unwrap().unwrap();
    assert_eq!(migrated_alice_root, partially_migrated_alice_root);
    assert_eq!(
        migrated_bob_root.generation,
        legacy_roots
            .get(&bob)
            .unwrap()
            .generation
            .checked_next()
            .unwrap()
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
        reopened.content().read(&alice, &alice_name).unwrap(),
        Some(alice_bytes.to_vec())
    );
    assert_eq!(
        reopened.content().read(&bob, &bob_name).unwrap(),
        Some(bob_bytes.to_vec())
    );
    drop(reopened);
    let reopened_engine = RuntimeEngine::open(
        home.principal_store_path(),
        Blake3ObjectIdentityV1,
        StateOwnerCodecV1,
        RecoveryLimits::process_addressable(),
    )
    .unwrap();
    assert_eq!(
        reopened_engine.root(&alice).unwrap(),
        Some(migrated_alice_root)
    );
    assert_eq!(reopened_engine.root(&bob).unwrap(), Some(migrated_bob_root));
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
    let store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    store
        .kv()
        .set("alice:capsule:shell", "cwd", b"/workspace".to_vec())
        .await
        .unwrap();
    let owner = StateOwner::Principal(PrincipalId::new("alice").unwrap());
    let name = ContentName::new("workspace/fastcdc-golden.bin").unwrap();
    store
        .content()
        .put(&owner, &name, &chunker_golden_source(1024 * 1024))
        .unwrap();
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
    assert_eq!(decoded["roots"]["alice"]["generation"], 1);
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
    assert!(
        decoded["objects"]
            .as_array()
            .unwrap()
            .iter()
            .any(|object| object["kind"] == "File")
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

    assert_reader_requires_catalog_specification(&home, &script);
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
