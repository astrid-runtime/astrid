use std::io::{Seek as _, SeekFrom, Write as _};

use super::runtime_tests::*;
use super::store_open_volume_tests::install_legacy_catalog_fixtures;
use super::*;

#[derive(Debug)]
struct CatalogWorkloadMetrics {
    arena_bytes: u64,
    root_journal_bytes: u64,
    representation_metadata_bytes: u64,
    publication_time: Duration,
    reopen_time: Duration,
}

fn durable_file_len(store: &RuntimePrincipalStore, name: &str) -> u64 {
    store.engine.durable_region_len(name).unwrap()
}

pub(super) fn volume_file_len(home: &AstridHome) -> u64 {
    std::fs::metadata(home.storage_volume_path()).unwrap().len()
}

async fn measure_catalog_publications(unique_content: bool) -> CatalogWorkloadMetrics {
    const PUBLICATIONS: u64 = 1_000;
    const CONTENT_BYTES: usize = 4 * 1024;

    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let owner = test_owner("catalog-probe");
    let store = open_runtime_principal_store_with_directory(
        &home,
        unlimited_quota(),
        test_directory(&["catalog-probe"]),
    )
    .await
    .unwrap();
    let arena_before = durable_file_len(&store, "objects.arena");
    let roots_before = durable_file_len(&store, "roots.journal");
    let volume_before = volume_file_len(&home);
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
    let arena_bytes = durable_file_len(&store, "objects.arena")
        .checked_sub(arena_before)
        .unwrap();
    let root_journal_bytes = durable_file_len(&store, "roots.journal")
        .checked_sub(roots_before)
        .unwrap();
    let representation_metadata_bytes = volume_file_len(&home).checked_sub(volume_before).unwrap();
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
        representation_metadata_bytes,
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
            "{name}: arena={} roots={} representations={} publication={:?} reopen={:?}",
            metrics.arena_bytes,
            metrics.root_journal_bytes,
            metrics.representation_metadata_bytes,
            metrics.publication_time,
            metrics.reopen_time
        );
    }
}

#[tokio::test]
async fn flat_content_catalog_migration_resumes_and_is_idempotent() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    seed_legacy_layout(&home);
    let alice = test_owner("alice");
    let bob = test_owner("bob");
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
    );

    let engine = Arc::new(
        RuntimeEngine::open(
            home.principal_store_path(),
            Blake3ObjectIdentityV1,
            StateOwnerCodecV2,
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
    assert_eq!(
        migrated.content().read(&alice, &alice_name).unwrap(),
        Some(alice_bytes.to_vec())
    );
    assert_eq!(
        migrated.content().read(&bob, &bob_name).unwrap(),
        Some(bob_bytes.to_vec())
    );
    let migrated_alice_root = migrated.engine.root(&alice).unwrap().unwrap();
    let migrated_bob_root = migrated.engine.root(&bob).unwrap().unwrap();
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
    migrated.engine.close().unwrap();
    drop(migrated);
    let retired = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    retired
        .retire_verified_legacy_directory_store(&home)
        .unwrap();
    retired.engine.close().unwrap();
    drop(retired);
    assert!(home.storage_volume_path().is_file());
    assert!(!home.principal_store_path().exists());

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
    assert_eq!(
        reopened.engine.root(&alice).unwrap(),
        Some(migrated_alice_root)
    );
    assert_eq!(reopened.engine.root(&bob).unwrap(), Some(migrated_bob_root));
}

#[tokio::test]
async fn native_stage_acknowledges_before_ingest_and_publishes_on_a_blocking_worker() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let owner = test_owner("alice");
    let name = ContentName::new("workspace/target/release/game").unwrap();
    let mut writer = store
        .staging()
        .begin(owner, name.clone(), ChunkingProfile::ASTRID_V1)
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
    let snapshot = store.content().engine().snapshot(&owner).unwrap().unwrap();
    assert!(
        snapshot
            .records()
            .iter()
            .any(|(_, record)| record.kind() == ObjectKind::Chunk),
        "archival snapshots must materialize canonical chunk records"
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
async fn native_staging_batch_publishes_one_atomic_root_and_reaps_together() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let owner = test_owner("alice");
    let values = [
        ("workspace/a.txt", b"alpha".as_slice()),
        ("workspace/b.txt", b"bravo".as_slice()),
        ("workspace/c.txt", b"charlie".as_slice()),
    ];
    let mut staged = Vec::new();
    for (name, value) in values {
        let mut writer = store
            .staging()
            .begin(
                owner,
                ContentName::new(name).unwrap(),
                ChunkingProfile::ASTRID_V1,
            )
            .unwrap();
        writer.write_all(value).unwrap();
        staged.push(writer.seal().unwrap());
    }

    let outcome = store.publish_staged_batch(staged).await.unwrap();

    assert_eq!(outcome.principal_root().generation, RootGeneration::INITIAL);
    assert_eq!(outcome.entries().len(), values.len());
    assert!(store.staging().ready().unwrap().is_empty());
    for (name, value) in values {
        assert_eq!(
            store
                .content()
                .read(&owner, &ContentName::new(name).unwrap())
                .unwrap(),
            Some(value.to_vec())
        );
    }
    drop(store);

    let reopened = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    for (name, value) in values {
        assert_eq!(
            reopened
                .content()
                .read(&owner, &ContentName::new(name).unwrap())
                .unwrap(),
            Some(value.to_vec())
        );
    }
}

#[tokio::test]
async fn native_staging_batch_rejects_mixed_owners_without_consuming_generations() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let mut staged = Vec::new();
    for owner in [test_owner("alice"), test_owner("bob")] {
        let mut writer = store
            .staging()
            .begin(
                owner,
                ContentName::new("workspace/shared.txt").unwrap(),
                ChunkingProfile::ASTRID_V1,
            )
            .unwrap();
        writer.write_all(b"owner-specific bytes").unwrap();
        staged.push(writer.seal().unwrap());
    }

    let error = store
        .publish_staged_batch(staged.clone())
        .await
        .unwrap_err();

    assert!(error.to_string().contains("multiple owners"));
    assert_eq!(store.staging().ready().unwrap(), staged);
}

#[tokio::test]
async fn staged_publication_rejects_a_generation_truncated_after_seal() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let owner = test_owner("alice");
    let name = ContentName::new("workspace/truncated.bin").unwrap();
    let mut writer = store
        .staging()
        .begin(owner, name.clone(), ChunkingProfile::ASTRID_V1)
        .unwrap();
    writer.write_all(b"durable staged bytes").unwrap();
    let staged = writer.seal().unwrap();
    let path = staged.content_path();

    std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(staged.logical_bytes().saturating_sub(1))
        .unwrap();

    let error = store.publish_staged(staged).await.unwrap_err();
    assert!(error.to_string().contains("footer"));
    assert_eq!(store.content().describe(&owner, &name).unwrap(), None);
    assert!(
        path.exists(),
        "failed publication must retain staged evidence"
    );
}

#[tokio::test]
async fn staged_publication_retries_after_root_commit_before_cleanup() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let owner = test_owner("alice");
    let name = ContentName::new("workspace/retry.bin").unwrap();
    let mut writer = store
        .staging()
        .begin(owner, name.clone(), ChunkingProfile::ASTRID_V1)
        .unwrap();
    writer.write_all(b"one identity").unwrap();
    let staged = writer.seal().unwrap();

    let source = native_io::open_private_file(&staged.content_path())
        .unwrap()
        .take(staged.logical_bytes());
    let first = store
        .content()
        .put_streaming(&owner, &name, source)
        .unwrap();
    assert_eq!(store.staging().ready().unwrap(), vec![staged.clone()]);

    let retried = store.publish_staged(staged).await.unwrap();
    assert_eq!(retried.descriptor(), first.descriptor());
    assert_eq!(retried.principal_root(), first.principal_root());
    assert_eq!(
        retried.objects_inserted(),
        0,
        "retry must not count immutable objects admitted by the first publication"
    );
    assert!(store.staging().ready().unwrap().is_empty());
}

#[tokio::test]
async fn staged_publication_enforces_close_order_for_the_same_name() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let owner = test_owner("alice");
    let name = ContentName::new("workspace/order.txt").unwrap();
    let mut first = store
        .staging()
        .begin(owner, name.clone(), ChunkingProfile::ASTRID_V1)
        .unwrap();
    first.write_all(b"first close").unwrap();
    let first = first.seal().unwrap();
    let mut second = store
        .staging()
        .begin(owner, name.clone(), ChunkingProfile::ASTRID_V1)
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
