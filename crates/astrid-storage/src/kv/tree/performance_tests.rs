//! Explicitly ignored release-mode comparison against the legacy `SurrealKV`
//! oracle. These gates are machine evidence, not part of the default unit run.

use std::num::NonZeroU64;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::engine::{
    DurableEngine, DurableEnginePolicy, GroupCommitPolicy, ObjectCacheConfig, PrincipalCodec,
    RecoveryLimits, RecoveryRetryPolicy, TransactionWalPolicy,
};
use crate::kv::principal::KvPrincipalResolver;
use crate::kv::{
    KvBatchCondition, KvBatchMutation, KvEntryKey, KvMutationBatch, KvReadCacheConfig, KvStore,
    SurrealKvStore, composite_key,
};
use crate::principal_state::Blake3ObjectIdentityV1;
use crate::{StorageError, StorageResult};

use super::TreeKvStore;

#[derive(Clone, Copy)]
struct Resolver;

impl KvPrincipalResolver<String> for Resolver {
    fn resolve(&self, namespace: &str) -> StorageResult<String> {
        namespace
            .split_once(":capsule:")
            .map(|(principal, _)| principal.to_owned())
            .ok_or_else(|| StorageError::InvalidKey("test namespace has no owner".to_owned()))
    }
}

#[derive(Clone, Copy)]
struct Utf8Codec;

impl PrincipalCodec<String> for Utf8Codec {
    fn encode(&self, principal: &String) -> Vec<u8> {
        principal.as_bytes().to_vec()
    }

    fn decode(&self, bytes: &[u8]) -> Option<String> {
        std::str::from_utf8(bytes).ok().map(str::to_owned)
    }
}

type NativeEngine = DurableEngine<String, Blake3ObjectIdentityV1, Utf8Codec>;
type NativeStore = TreeKvStore<String, Blake3ObjectIdentityV1, Resolver, NativeEngine>;

fn native_fixture() -> (tempfile::TempDir, Arc<NativeEngine>, NativeStore) {
    let directory = tempfile::tempdir().unwrap();
    let engine = Arc::new(
        DurableEngine::open_with_group_commit_policy(
            directory.path(),
            Blake3ObjectIdentityV1,
            Utf8Codec,
            RecoveryLimits::process_addressable(),
            GroupCommitPolicy::immediate(),
        )
        .unwrap(),
    );
    let store = TreeKvStore::from_engine(Arc::clone(&engine), Resolver)
        .with_read_cache(KvReadCacheConfig::reserved_64_mib());
    (directory, engine, store)
}

fn native_wal_fixture() -> (tempfile::TempDir, Arc<NativeEngine>, NativeStore) {
    let directory = tempfile::tempdir().unwrap();
    let policy = DurableEnginePolicy::new(
        GroupCommitPolicy::immediate(),
        RecoveryRetryPolicy::immediate(),
        ObjectCacheConfig::disabled(),
    )
    .with_transaction_wal(TransactionWalPolicy::enabled(
        NonZeroU64::new(256 * 1024 * 1024).unwrap(),
    ));
    let engine = Arc::new(
        DurableEngine::open_with_policy(
            directory.path(),
            Blake3ObjectIdentityV1,
            Utf8Codec,
            RecoveryLimits::process_addressable(),
            policy,
        )
        .unwrap(),
    );
    let store = TreeKvStore::from_engine(Arc::clone(&engine), Resolver)
        .with_read_cache(KvReadCacheConfig::reserved_64_mib());
    (directory, engine, store)
}

fn operations_per_second(operations: usize, elapsed: Duration) -> f64 {
    f64::from(u32::try_from(operations).expect("benchmark operation count fits u32"))
        / elapsed.as_secs_f64()
}

fn benchmark_byte(value: usize) -> u8 {
    u8::try_from(value % 256).expect("benchmark byte is bounded")
}

const AUDIT_BATCH_ENTRIES: usize = 64;
const AUDIT_BATCHES: usize = 8;
const AUDIT_BATCH_SAMPLES: usize = 20;
const AUDIT_VALUE_BYTES: usize = 128;
const AUDIT_NAMESPACE: &str = "alice:capsule:audit-batch";

struct AuditBatch {
    native: KvMutationBatch,
    native_entries: Vec<(String, Vec<u8>)>,
    legacy_entries: Vec<(Vec<u8>, Vec<u8>)>,
}

fn audit_batches(sample: usize) -> Vec<AuditBatch> {
    (0..AUDIT_BATCHES)
        .map(|batch| {
            let mut mutations = Vec::with_capacity(AUDIT_BATCH_ENTRIES);
            let mut native_entries = Vec::with_capacity(AUDIT_BATCH_ENTRIES);
            let mut legacy_entries = Vec::with_capacity(AUDIT_BATCH_ENTRIES);
            for index in 0..AUDIT_BATCH_ENTRIES {
                let key = format!("event-{sample:02}-{batch:02}-{index:02}");
                let value = vec![
                    benchmark_byte(
                        sample
                            .saturating_mul(AUDIT_BATCHES)
                            .saturating_mul(AUDIT_BATCH_ENTRIES)
                            .saturating_add(batch.saturating_mul(AUDIT_BATCH_ENTRIES))
                            .saturating_add(index),
                    );
                    AUDIT_VALUE_BYTES
                ];
                mutations.push(KvBatchMutation::Set {
                    key: KvEntryKey::new(AUDIT_NAMESPACE, key.clone()).unwrap(),
                    value: value.clone(),
                });
                native_entries.push((key.clone(), value.clone()));
                legacy_entries.push((composite_key(AUDIT_NAMESPACE, &key), value));
            }
            let native =
                KvMutationBatch::new(std::iter::empty::<KvBatchCondition>(), mutations).unwrap();
            AuditBatch {
                native,
                native_entries,
                legacy_entries,
            }
        })
        .collect()
}

fn percentile_micros(latencies: &[Duration], percentile: usize) -> f64 {
    assert!(!latencies.is_empty());
    let mut sorted = latencies.to_vec();
    sorted.sort_unstable();
    let index = sorted.len().saturating_sub(1).saturating_mul(percentile) / 100;
    sorted[index].as_secs_f64() * 1_000_000.0
}

async fn assert_native_audit_values(store: &NativeStore, batches: &[AuditBatch]) {
    for batch in batches {
        for (key, expected) in &batch.native_entries {
            assert_eq!(
                store.get(AUDIT_NAMESPACE, key).await.unwrap().as_deref(),
                Some(expected.as_slice()),
                "native value mismatch for {key}"
            );
        }
    }
}

fn assert_legacy_audit_values(tree: &surrealkv::Tree, batches: &[AuditBatch]) {
    let tx = tree.begin_with_mode(surrealkv::Mode::ReadOnly).unwrap();
    for batch in batches {
        for (key, expected) in &batch.legacy_entries {
            assert_eq!(
                tx.get(key).unwrap().as_deref(),
                Some(expected.as_slice()),
                "SurrealKV value mismatch for {key:?}"
            );
        }
    }
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "release-mode comparative hot-read diagnostic"]
async fn hot_point_reads_outpace_legacy_surrealkv() {
    const READS: usize = 500_000;
    const SAMPLES: usize = 5;

    let (_native_directory, _native_engine, native) = native_fixture();
    let legacy_directory = tempfile::tempdir().unwrap();
    let legacy = SurrealKvStore::open(legacy_directory.path()).unwrap();
    let namespace = "alice:capsule:bench";
    let key = "hot";
    let value = vec![7_u8; 128];
    native.set(namespace, key, value.clone()).await.unwrap();
    legacy.set(namespace, key, value.clone()).await.unwrap();
    assert_eq!(
        native.get(namespace, key).await.unwrap(),
        Some(value.clone())
    );
    assert_eq!(legacy.get(namespace, key).await.unwrap(), Some(value));

    let mut native_rates = Vec::with_capacity(SAMPLES);
    let mut legacy_rates = Vec::with_capacity(SAMPLES);
    for sample in 0..SAMPLES {
        let native_started = Instant::now();
        for _ in 0..READS {
            let observed = native.get(namespace, key).await.unwrap();
            assert_eq!(observed.as_deref(), Some([7_u8; 128].as_slice()));
            std::hint::black_box(observed);
        }
        let native_rate = operations_per_second(READS, native_started.elapsed());

        let legacy_started = Instant::now();
        for _ in 0..READS {
            let observed = legacy.get(namespace, key).await.unwrap();
            assert_eq!(observed.as_deref(), Some([7_u8; 128].as_slice()));
            std::hint::black_box(observed);
        }
        let legacy_rate = operations_per_second(READS, legacy_started.elapsed());
        eprintln!(
            "sample={sample} astrid_reads_per_second={native_rate:.0} \
             surrealkv_reads_per_second={legacy_rate:.0} ratio={:.3}",
            native_rate / legacy_rate
        );
        native_rates.push(native_rate);
        legacy_rates.push(legacy_rate);
    }
    native_rates.sort_by(f64::total_cmp);
    legacy_rates.sort_by(f64::total_cmp);
    eprintln!(
        "median_ratio={:.3}",
        native_rates[SAMPLES / 2] / legacy_rates[SAMPLES / 2]
    );
    native.close().await.unwrap();
    legacy.close().await.unwrap();
}

async fn concurrent_rate(store: Arc<dyn KvStore>, readers: usize, reads_per_reader: usize) -> f64 {
    const NAMESPACE: &str = "alice:capsule:bench";
    const KEY: &str = "hot";
    let barrier = Arc::new(tokio::sync::Barrier::new(readers.saturating_add(1)));
    let mut tasks = Vec::with_capacity(readers);
    for _ in 0..readers {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            for _ in 0..reads_per_reader {
                let value = store.get(NAMESPACE, KEY).await.unwrap();
                assert_eq!(value.as_deref(), Some([7_u8; 128].as_slice()));
                std::hint::black_box(value);
            }
        }));
    }
    barrier.wait().await;
    let started = Instant::now();
    for task in tasks {
        task.await.unwrap();
    }
    operations_per_second(readers.saturating_mul(reads_per_reader), started.elapsed())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "release-mode comparative concurrent hot-read diagnostic"]
async fn concurrent_hot_point_reads_outpace_legacy_surrealkv() {
    const READS_PER_READER: usize = 100_000;
    const SAMPLES: usize = 3;
    const NAMESPACE: &str = "alice:capsule:bench";
    const KEY: &str = "hot";

    let (_native_directory, _native_engine, native) = native_fixture();
    let native = Arc::new(native);
    let legacy_directory = tempfile::tempdir().unwrap();
    let legacy = Arc::new(SurrealKvStore::open(legacy_directory.path()).unwrap());
    native.set(NAMESPACE, KEY, vec![7; 128]).await.unwrap();
    legacy.set(NAMESPACE, KEY, vec![7; 128]).await.unwrap();
    native.get(NAMESPACE, KEY).await.unwrap();
    legacy.get(NAMESPACE, KEY).await.unwrap();

    for readers in [1_usize, 2, 4, 8] {
        let mut native_rates = Vec::with_capacity(SAMPLES);
        let mut legacy_rates = Vec::with_capacity(SAMPLES);
        for sample in 0..SAMPLES {
            let native_rate = concurrent_rate(
                Arc::clone(&native) as Arc<dyn KvStore>,
                readers,
                READS_PER_READER,
            )
            .await;
            let legacy_rate = concurrent_rate(
                Arc::clone(&legacy) as Arc<dyn KvStore>,
                readers,
                READS_PER_READER,
            )
            .await;
            eprintln!(
                "readers={readers} sample={sample} astrid_reads_per_second={native_rate:.0} \
                 surrealkv_reads_per_second={legacy_rate:.0} ratio={:.3}",
                native_rate / legacy_rate
            );
            native_rates.push(native_rate);
            legacy_rates.push(legacy_rate);
        }
        native_rates.sort_by(f64::total_cmp);
        legacy_rates.sort_by(f64::total_cmp);
        eprintln!(
            "readers={readers} median_ratio={:.3}",
            native_rates[SAMPLES / 2] / legacy_rates[SAMPLES / 2]
        );
    }
    native.close().await.unwrap();
    legacy.close().await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "release-mode comparative hot working-set diagnostic"]
async fn hot_working_set_reads_outpace_legacy_surrealkv() {
    const KEYS: usize = 4_096;
    const READS: usize = 500_000;
    const SAMPLES: usize = 3;
    const NAMESPACE: &str = "alice:capsule:bench";

    let (_native_directory, _native_engine, native) = native_fixture();
    native
        .seed_sorted_for_test(
            "alice".to_owned(),
            (0..KEYS)
                .map(|index| {
                    (
                        format!("{NAMESPACE}\0{index:04x}").into_bytes(),
                        vec![benchmark_byte(index); 128],
                    )
                })
                .collect(),
        )
        .unwrap();
    let legacy_directory = tempfile::tempdir().unwrap();
    let legacy = SurrealKvStore::open(legacy_directory.path()).unwrap();
    for index in 0..KEYS {
        legacy
            .set(
                NAMESPACE,
                &format!("{index:04x}"),
                vec![benchmark_byte(index); 128],
            )
            .await
            .unwrap();
    }
    for index in 0..KEYS {
        let key = format!("{index:04x}");
        assert_eq!(
            native.get(NAMESPACE, &key).await.unwrap(),
            legacy.get(NAMESPACE, &key).await.unwrap()
        );
    }

    let mut native_rates = Vec::with_capacity(SAMPLES);
    let mut legacy_rates = Vec::with_capacity(SAMPLES);
    for sample in 0..SAMPLES {
        let mut state = 0x9e37_79b9_u32;
        let native_started = Instant::now();
        for _ in 0..READS {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let index = usize::try_from(state).unwrap() % KEYS;
            let key = format!("{index:04x}");
            let observed = native.get(NAMESPACE, &key).await.unwrap();
            assert_eq!(
                observed.as_deref(),
                Some([benchmark_byte(index); 128].as_slice())
            );
            std::hint::black_box(observed);
        }
        let native_rate = operations_per_second(READS, native_started.elapsed());

        state = 0x9e37_79b9_u32;
        let legacy_started = Instant::now();
        for _ in 0..READS {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let index = usize::try_from(state).unwrap() % KEYS;
            let key = format!("{index:04x}");
            let observed = legacy.get(NAMESPACE, &key).await.unwrap();
            assert_eq!(
                observed.as_deref(),
                Some([benchmark_byte(index); 128].as_slice())
            );
            std::hint::black_box(observed);
        }
        let legacy_rate = operations_per_second(READS, legacy_started.elapsed());
        eprintln!(
            "working_set={KEYS} sample={sample} astrid_reads_per_second={native_rate:.0} \
             surrealkv_reads_per_second={legacy_rate:.0} ratio={:.3}",
            native_rate / legacy_rate
        );
        native_rates.push(native_rate);
        legacy_rates.push(legacy_rate);
    }
    native_rates.sort_by(f64::total_cmp);
    legacy_rates.sort_by(f64::total_cmp);
    eprintln!(
        "working_set={KEYS} median_ratio={:.3}",
        native_rates[SAMPLES / 2] / legacy_rates[SAMPLES / 2]
    );
    native.close().await.unwrap();
    legacy.close().await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "release-mode strict-durability single-owner write evidence"]
async fn strict_single_owner_writes_compare_with_surrealkv() {
    const WRITES: usize = 64;
    const SAMPLES: usize = 5;
    const NAMESPACE: &str = "alice:capsule:audit";
    const KEY: &str = "head";

    let (_native_directory, _native_engine, native) = native_wal_fixture();
    let legacy_directory = tempfile::tempdir().unwrap();
    let legacy = surrealkv::TreeBuilder::new()
        .with_path(legacy_directory.path().to_path_buf())
        .build()
        .unwrap();
    let legacy_key = composite_key(NAMESPACE, KEY);

    for sample in 0..SAMPLES {
        let native_started = Instant::now();
        for sequence in 0..WRITES {
            native
                .set(
                    NAMESPACE,
                    KEY,
                    vec![benchmark_byte(sample * WRITES + sequence); 128],
                )
                .await
                .unwrap();
        }
        let native_rate = operations_per_second(WRITES, native_started.elapsed());

        let legacy_started = Instant::now();
        for sequence in 0..WRITES {
            let mut transaction = legacy.begin().unwrap();
            transaction.set_durability(surrealkv::Durability::Immediate);
            transaction
                .set(
                    &legacy_key,
                    vec![benchmark_byte(sample * WRITES + sequence); 128],
                )
                .unwrap();
            transaction.commit().await.unwrap();
        }
        let legacy_rate = operations_per_second(WRITES, legacy_started.elapsed());
        eprintln!(
            "sample={sample} astrid_strict_writes_per_second={native_rate:.1} \
             surrealkv_strict_writes_per_second={legacy_rate:.1} ratio={:.3}",
            native_rate / legacy_rate
        );
    }
    native.close().await.unwrap();
    legacy.close().await.unwrap();
}

async fn measure_native_audit_sample(
    store: &NativeStore,
    batches: &[AuditBatch],
    latencies: &mut Vec<Duration>,
) -> Duration {
    let started = Instant::now();
    for (batch_index, batch) in batches.iter().enumerate() {
        let commit_started = Instant::now();
        let outcome = store.apply_batch(&batch.native).await.unwrap();
        latencies.push(commit_started.elapsed());
        assert!(outcome.applied, "native batch {batch_index} did not apply");
        assert!(
            outcome.conditions.is_empty(),
            "native batch {batch_index} unexpectedly returned conditions"
        );
    }
    started.elapsed()
}

async fn measure_legacy_audit_sample(
    tree: &surrealkv::Tree,
    batches: &[AuditBatch],
    latencies: &mut Vec<Duration>,
) -> Duration {
    let started = Instant::now();
    for batch in batches {
        let commit_started = Instant::now();
        let mut transaction = tree.begin().unwrap();
        transaction.set_durability(surrealkv::Durability::Immediate);
        for (key, value) in &batch.legacy_entries {
            transaction.set(key, value.clone()).unwrap();
        }
        transaction.commit().await.unwrap();
        latencies.push(commit_started.elapsed());
    }
    started.elapsed()
}

fn print_audit_sample_metrics(
    sample: usize,
    batches: &[AuditBatch],
    native_elapsed: Duration,
    native_latencies: &[Duration],
    legacy_elapsed: Duration,
    legacy_latencies: &[Duration],
) {
    eprintln!(
        "sample={sample} entries={} batches={} \
         astrid_batch_p50_us={:.1} astrid_batch_p95_us={:.1} \
         astrid_batches_per_second={:.1} astrid_entries_per_second={:.1} \
         surrealkv_batch_p50_us={:.1} surrealkv_batch_p95_us={:.1} \
         surrealkv_batches_per_second={:.1} surrealkv_entries_per_second={:.1}",
        batches.len().saturating_mul(AUDIT_BATCH_ENTRIES),
        batches.len(),
        percentile_micros(native_latencies, 50),
        percentile_micros(native_latencies, 95),
        operations_per_second(batches.len(), native_elapsed),
        operations_per_second(
            batches.len().saturating_mul(AUDIT_BATCH_ENTRIES),
            native_elapsed,
        ),
        percentile_micros(legacy_latencies, 50),
        percentile_micros(legacy_latencies, 95),
        operations_per_second(batches.len(), legacy_elapsed),
        operations_per_second(
            batches.len().saturating_mul(AUDIT_BATCH_ENTRIES),
            legacy_elapsed,
        ),
    );
}

async fn assert_native_audit_reopen(directory: &tempfile::TempDir, batches: &[AuditBatch]) {
    let reopened_engine = Arc::new(
        DurableEngine::open_with_group_commit_policy(
            directory.path(),
            Blake3ObjectIdentityV1,
            Utf8Codec,
            RecoveryLimits::process_addressable(),
            GroupCommitPolicy::immediate(),
        )
        .unwrap(),
    );
    let reopened = TreeKvStore::from_engine(Arc::clone(&reopened_engine), Resolver)
        .with_read_cache(KvReadCacheConfig::reserved_64_mib());
    assert_native_audit_values(&reopened, batches).await;
    reopened.close().await.unwrap();
}

async fn assert_legacy_audit_reopen(directory: &tempfile::TempDir, batches: &[AuditBatch]) {
    let reopened = surrealkv::TreeBuilder::new()
        .with_path(directory.path().to_path_buf())
        .build()
        .unwrap();
    assert_legacy_audit_values(&reopened, batches);
    reopened.close().await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "release-mode strict-durability same-owner KvMutationBatch evidence"]
async fn strict_same_owner_batch_commits_compare_with_surrealkv() {
    let (native_directory, native_engine, native) = native_wal_fixture();
    let legacy_directory = tempfile::tempdir().unwrap();
    let legacy = surrealkv::TreeBuilder::new()
        .with_path(legacy_directory.path().to_path_buf())
        .build()
        .unwrap();

    let mut native_latencies = Vec::with_capacity(AUDIT_BATCH_SAMPLES * AUDIT_BATCHES);
    let mut legacy_latencies = Vec::with_capacity(AUDIT_BATCH_SAMPLES * AUDIT_BATCHES);
    let mut native_elapsed = Duration::ZERO;
    let mut legacy_elapsed = Duration::ZERO;
    let mut all_batches = Vec::with_capacity(AUDIT_BATCH_SAMPLES * AUDIT_BATCHES);

    for sample in 0..AUDIT_BATCH_SAMPLES {
        let batches = audit_batches(sample);
        let native_sample_start = native_latencies.len();
        let legacy_sample_start = legacy_latencies.len();
        let (native_sample_elapsed, legacy_sample_elapsed) = if sample % 2 == 0 {
            let native =
                measure_native_audit_sample(&native, &batches, &mut native_latencies).await;
            let legacy =
                measure_legacy_audit_sample(&legacy, &batches, &mut legacy_latencies).await;
            (native, legacy)
        } else {
            let legacy =
                measure_legacy_audit_sample(&legacy, &batches, &mut legacy_latencies).await;
            let native =
                measure_native_audit_sample(&native, &batches, &mut native_latencies).await;
            (native, legacy)
        };
        native_elapsed = native_elapsed.saturating_add(native_sample_elapsed);
        legacy_elapsed = legacy_elapsed.saturating_add(legacy_sample_elapsed);

        let native_sample_latencies = &native_latencies[native_sample_start..];
        let legacy_sample_latencies = &legacy_latencies[legacy_sample_start..];
        print_audit_sample_metrics(
            sample,
            &batches,
            native_sample_elapsed,
            native_sample_latencies,
            legacy_sample_elapsed,
            legacy_sample_latencies,
        );
        all_batches.extend(batches);
    }

    assert_native_audit_values(&native, &all_batches).await;
    assert_legacy_audit_values(&legacy, &all_batches);

    let total_batches = AUDIT_BATCH_SAMPLES.saturating_mul(AUDIT_BATCHES);
    let total_entries = total_batches.saturating_mul(AUDIT_BATCH_ENTRIES);
    eprintln!(
        "aggregate entries={total_entries} batches={total_batches} \
         astrid_batch_p50_us={:.1} astrid_batch_p95_us={:.1} \
         astrid_batches_per_second={:.1} astrid_entries_per_second={:.1} \
         surrealkv_batch_p50_us={:.1} surrealkv_batch_p95_us={:.1} \
         surrealkv_batches_per_second={:.1} surrealkv_entries_per_second={:.1} \
         entries_per_second_ratio={:.3}",
        percentile_micros(&native_latencies, 50),
        percentile_micros(&native_latencies, 95),
        operations_per_second(total_batches, native_elapsed),
        operations_per_second(total_entries, native_elapsed),
        percentile_micros(&legacy_latencies, 50),
        percentile_micros(&legacy_latencies, 95),
        operations_per_second(total_batches, legacy_elapsed),
        operations_per_second(total_entries, legacy_elapsed),
        operations_per_second(total_entries, native_elapsed)
            / operations_per_second(total_entries, legacy_elapsed),
    );

    native.close().await.unwrap();
    drop(native);
    drop(native_engine);
    assert_native_audit_reopen(&native_directory, &all_batches).await;

    legacy.close().await.unwrap();
    assert_legacy_audit_reopen(&legacy_directory, &all_batches).await;
}
