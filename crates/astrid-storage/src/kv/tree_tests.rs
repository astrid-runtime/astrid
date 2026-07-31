use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use astrid_storage_engine::{
    CommitOutcome, InMemoryEngine, KvProjectionEngine, KvProjectionError, RootSnapshot,
    RootTransaction,
};
#[cfg(not(target_family = "wasm"))]
use astrid_storage_engine::{
    DurableEngine, IdentityScheme, PersistentObjectIdentity, PrincipalCodec, RecoveryLimits,
};
use astrid_storage_model::{
    ObjectClass, ObjectId, ObjectIdentity, ObjectKind, ObjectRecord, ObjectReference,
    ReferenceKind, ReferenceLabel, RootState,
};

use super::{KvPrincipalResolver, KvStore, TreeKvStore, migrate_legacy_avl};
use crate::principal_graph::{LEGACY_PRINCIPAL_GRAPH_VERSION, PRINCIPAL_GRAPH_VERSION};
use crate::{StorageError, StorageResult};

#[derive(Clone, Copy, Debug)]
struct TestIdentity;

impl ObjectIdentity for TestIdentity {
    fn identify(&self, record: &ObjectRecord) -> ObjectId {
        let mut hasher = blake3::Hasher::new_derive_key("astrid persistent KV tree test v1");
        hasher.update(&record.kind().code().to_le_bytes());
        hasher.update(&record.format_version().get().to_le_bytes());
        hasher.update(&(record.canonical_bytes().len() as u128).to_le_bytes());
        hasher.update(record.canonical_bytes());
        hasher.update(&record.logical_bytes().to_le_bytes());
        hasher.update(&[match record.class() {
            ObjectClass::Data => 0,
            ObjectClass::Metadata => 1,
        }]);
        hasher.update(&(record.references().len() as u128).to_le_bytes());
        for reference in record.references() {
            hasher.update(&(reference.label().as_bytes().len() as u128).to_le_bytes());
            hasher.update(reference.label().as_bytes());
            hasher.update(reference.target().as_bytes());
            hasher.update(&[match reference.kind() {
                ReferenceKind::Owns => 0,
                ReferenceKind::Evidence => 1,
                ReferenceKind::Lineage => 2,
                ReferenceKind::Derived => 3,
            }]);
        }
        ObjectId::new(*hasher.finalize().as_bytes())
    }
}

#[cfg(not(target_family = "wasm"))]
const TEST_IDENTITY_SCHEME: IdentityScheme = match IdentityScheme::new(u16::MAX, 41) {
    Some(scheme) => scheme,
    None => unreachable!(),
};

#[cfg(not(target_family = "wasm"))]
impl PersistentObjectIdentity for TestIdentity {
    fn scheme(&self) -> IdentityScheme {
        TEST_IDENTITY_SCHEME
    }
}

#[cfg(not(target_family = "wasm"))]
#[derive(Clone, Copy, Debug)]
struct Utf8Codec;

#[cfg(not(target_family = "wasm"))]
impl PrincipalCodec<String> for Utf8Codec {
    fn encode(&self, principal: &String) -> Vec<u8> {
        principal.as_bytes().to_vec()
    }

    fn decode(&self, bytes: &[u8]) -> Option<String> {
        std::str::from_utf8(bytes).ok().map(str::to_owned)
    }
}

#[derive(Clone, Copy, Debug)]
struct Resolver;

impl KvPrincipalResolver<String> for Resolver {
    fn resolve(&self, namespace: &str) -> StorageResult<String> {
        namespace
            .split_once(":capsule:")
            .map(|(principal, _)| principal.to_owned())
            .ok_or_else(|| StorageError::InvalidKey("test namespace has no owner".to_owned()))
    }
}

type Store = TreeKvStore<String, TestIdentity, Resolver, InMemoryEngine<String, TestIdentity>>;

#[derive(Debug)]
struct MeasuringEngine {
    inner: InMemoryEngine<String, TestIdentity>,
    last_authoritative_bytes: AtomicU64,
}

impl MeasuringEngine {
    fn new() -> Self {
        Self {
            inner: InMemoryEngine::new(TestIdentity),
            last_authoritative_bytes: AtomicU64::new(0),
        }
    }

    fn last_authoritative_bytes(&self) -> u64 {
        self.last_authoritative_bytes.load(Ordering::Acquire)
    }
}

impl KvProjectionEngine<String> for MeasuringEngine {
    fn identify_kv_object(&self, record: &ObjectRecord) -> ObjectId {
        self.inner.identify(record)
    }

    fn current_kv_root(&self, principal: &String) -> Result<Option<RootState>, KvProjectionError> {
        Ok(self.inner.root(principal))
    }

    fn load_kv_object(&self, id: ObjectId) -> Result<Option<ObjectRecord>, KvProjectionError> {
        Ok(self.inner.object(id))
    }

    fn snapshot_kv_root(
        &self,
        principal: &String,
    ) -> Result<Option<RootSnapshot>, KvProjectionError> {
        self.inner.snapshot(principal).map_err(Into::into)
    }

    fn commit_kv_root(
        &self,
        transaction: RootTransaction<String>,
    ) -> Result<CommitOutcome, KvProjectionError> {
        let object_bytes = transaction
            .records()
            .iter()
            .filter(|(object, _)| self.inner.object(*object).is_none())
            .try_fold(0_u64, |total, (_, record)| {
                total.checked_add(object_frame_bytes(record))
            })
            .ok_or_else(|| KvProjectionError::Engine("measurement overflow".to_owned()))?;
        let journal_bytes = root_frame_bytes(
            transaction.principal().as_bytes(),
            transaction.expected().is_some(),
        )
        .ok_or_else(|| KvProjectionError::Engine("measurement overflow".to_owned()))?;
        let outcome = self.inner.commit(transaction)?;
        self.last_authoritative_bytes.store(
            object_bytes
                .checked_add(journal_bytes)
                .ok_or_else(|| KvProjectionError::Engine("measurement overflow".to_owned()))?,
            Ordering::Release,
        );
        Ok(outcome)
    }

    fn flush_kv(&self) -> Result<(), KvProjectionError> {
        Ok(())
    }
}

fn object_frame_bytes(record: &ObjectRecord) -> u64 {
    const FRAME_HEADER: u64 = 52;
    const OBJECT_FIXED: u64 = 69;
    const REFERENCE_FIXED: u64 = 49;
    let references = record.references().iter().fold(0_u64, |total, reference| {
        total
            .saturating_add(REFERENCE_FIXED)
            .saturating_add(reference.label().as_bytes().len() as u64)
    });
    FRAME_HEADER
        .saturating_add(OBJECT_FIXED)
        .saturating_add(record.canonical_bytes().len() as u64)
        .saturating_add(references)
}

fn root_frame_bytes(principal: &[u8], has_expected: bool) -> Option<u64> {
    const FRAME_HEADER: u64 = 52;
    const IDENTITY_AND_GENERATION: u64 = 48;
    FRAME_HEADER
        .checked_add(8)?
        .checked_add(principal.len() as u64)?
        .checked_add(1)?
        .checked_add(if has_expected {
            IDENTITY_AND_GENERATION
        } else {
            0
        })?
        .checked_add(IDENTITY_AND_GENERATION)
}

fn fixture() -> Arc<Store> {
    Arc::new(TreeKvStore::from_engine(
        Arc::new(InMemoryEngine::new(TestIdentity)),
        Resolver,
    ))
}

fn next(seed: &mut u64) -> u64 {
    *seed ^= *seed << 13;
    *seed ^= *seed >> 7;
    *seed ^= *seed << 17;
    *seed
}

fn admit(
    engine: &InMemoryEngine<String, TestIdentity>,
    records: &mut Vec<(ObjectId, ObjectRecord)>,
    record: ObjectRecord,
) -> ObjectId {
    let object = engine.identify(&record);
    records.push((object, record));
    object
}

fn legacy_value(
    engine: &InMemoryEngine<String, TestIdentity>,
    records: &mut Vec<(ObjectId, ObjectRecord)>,
    value: &[u8],
) -> ObjectId {
    admit(
        engine,
        records,
        ObjectRecord::new(
            ObjectKind::KvLeaf,
            LEGACY_PRINCIPAL_GRAPH_VERSION,
            value.to_vec(),
            Vec::new(),
            0,
            ObjectClass::Data,
        )
        .unwrap(),
    )
}

#[derive(Clone, Copy)]
struct LegacyNodeSpec<'a> {
    key: &'a [u8],
    value: &'a [u8],
    left: Option<ObjectId>,
    right: Option<ObjectId>,
    height: u32,
    logical_bytes: u64,
    quota_bytes: u64,
}

fn legacy_node(
    engine: &InMemoryEngine<String, TestIdentity>,
    records: &mut Vec<(ObjectId, ObjectRecord)>,
    spec: LegacyNodeSpec<'_>,
) -> ObjectId {
    let value = legacy_value(engine, records, spec.value);
    let mut canonical = Vec::new();
    canonical.extend_from_slice(&spec.height.to_le_bytes());
    canonical.extend_from_slice(&spec.logical_bytes.to_le_bytes());
    canonical.extend_from_slice(&spec.quota_bytes.to_le_bytes());
    canonical.extend_from_slice(&(spec.value.len() as u64).to_le_bytes());
    canonical.extend_from_slice(spec.key);
    let mut references = vec![ObjectReference::owns(
        ReferenceLabel::new(b"value".to_vec()),
        value,
    )];
    if let Some(left) = spec.left {
        references.push(ObjectReference::owns(
            ReferenceLabel::new(b"left".to_vec()),
            left,
        ));
    }
    if let Some(right) = spec.right {
        references.push(ObjectReference::owns(
            ReferenceLabel::new(b"right".to_vec()),
            right,
        ));
    }
    references.sort();
    admit(
        engine,
        records,
        ObjectRecord::new(
            ObjectKind::KvBranch,
            LEGACY_PRINCIPAL_GRAPH_VERSION,
            canonical,
            references,
            0,
            ObjectClass::Metadata,
        )
        .unwrap(),
    )
}

fn publish_legacy_tree(
    engine: &InMemoryEngine<String, TestIdentity>,
    wrapper_quota_adjustment: u64,
) -> (ObjectId, Vec<(String, String, Vec<u8>)>) {
    let LegacyTreeFixture {
        wrapper,
        mut records,
        entries,
    } = build_legacy_tree(engine, wrapper_quota_adjustment);
    let state = admit(
        engine,
        &mut records,
        ObjectRecord::new(
            ObjectKind::PrincipalState,
            LEGACY_PRINCIPAL_GRAPH_VERSION,
            Vec::new(),
            vec![ObjectReference::owns(
                ReferenceLabel::new(b"kv".to_vec()),
                wrapper,
            )],
            0,
            ObjectClass::Metadata,
        )
        .unwrap(),
    );
    let commit = admit(
        engine,
        &mut records,
        ObjectRecord::new(
            ObjectKind::Commit,
            LEGACY_PRINCIPAL_GRAPH_VERSION,
            Vec::new(),
            vec![ObjectReference::owns(
                ReferenceLabel::new(b"state".to_vec()),
                state,
            )],
            0,
            ObjectClass::Metadata,
        )
        .unwrap(),
    );
    engine
        .commit(RootTransaction::new(
            "alice".to_owned(),
            None,
            commit,
            records,
        ))
        .unwrap();
    (commit, entries)
}

struct LegacyTreeFixture {
    wrapper: ObjectId,
    records: Vec<(ObjectId, ObjectRecord)>,
    entries: Vec<(String, String, Vec<u8>)>,
}

fn build_legacy_tree(
    engine: &InMemoryEngine<String, TestIdentity>,
    wrapper_quota_adjustment: u64,
) -> LegacyTreeFixture {
    let namespace = "alice:capsule:test";
    let entries = [
        ("a", b"left".to_vec()),
        ("m", b"middle".to_vec()),
        ("z", vec![9_u8; 1_025]),
    ];
    let key = |name: &str| format!("{namespace}\0{name}").into_bytes();
    let left_key = key(entries[0].0);
    let right_key = key(entries[2].0);
    let root_key = key(entries[1].0);
    let mut records = Vec::new();
    let left = legacy_node(
        engine,
        &mut records,
        LegacyNodeSpec {
            key: &left_key,
            value: &entries[0].1,
            left: None,
            right: None,
            height: 1,
            logical_bytes: entries[0].1.len() as u64,
            quota_bytes: legacy_entry_quota(&left_key, &entries[0].1),
        },
    );
    let right = legacy_node(
        engine,
        &mut records,
        LegacyNodeSpec {
            key: &right_key,
            value: &entries[2].1,
            left: None,
            right: None,
            height: 1,
            logical_bytes: entries[2].1.len() as u64,
            quota_bytes: legacy_entry_quota(&right_key, &entries[2].1),
        },
    );
    let logical_bytes = entries.iter().map(|(_, value)| value.len() as u64).sum();
    let quota_bytes = [left_key.len(), root_key.len(), right_key.len()]
        .into_iter()
        .map(|length| length as u64)
        .fold(logical_bytes, u64::saturating_add);
    let root = legacy_node(
        engine,
        &mut records,
        LegacyNodeSpec {
            key: &root_key,
            value: &entries[1].1,
            left: Some(left),
            right: Some(right),
            height: 2,
            logical_bytes,
            quota_bytes,
        },
    );
    let wrapper = admit(
        engine,
        &mut records,
        ObjectRecord::new(
            ObjectKind::NamespaceMap,
            LEGACY_PRINCIPAL_GRAPH_VERSION,
            quota_bytes
                .saturating_add(wrapper_quota_adjustment)
                .to_le_bytes()
                .to_vec(),
            vec![ObjectReference::owns(
                ReferenceLabel::new(b"root".to_vec()),
                root,
            )],
            logical_bytes,
            ObjectClass::Metadata,
        )
        .unwrap(),
    );
    LegacyTreeFixture {
        wrapper,
        records,
        entries: entries
            .into_iter()
            .map(|(key, value)| (namespace.to_owned(), key.to_owned(), value))
            .collect(),
    }
}

fn legacy_entry_quota(key: &[u8], value: &[u8]) -> u64 {
    u64::try_from(key.len())
        .unwrap()
        .saturating_add(u64::try_from(value.len()).unwrap())
}

#[tokio::test]
async fn legacy_avl_migration_preserves_entries_and_commit_lineage() {
    let engine = Arc::new(InMemoryEngine::new(TestIdentity));
    let (legacy_commit, entries) = publish_legacy_tree(engine.as_ref(), 0);

    assert!(migrate_legacy_avl(engine.as_ref(), &"alice".to_owned()).unwrap());
    assert!(!migrate_legacy_avl(engine.as_ref(), &"alice".to_owned()).unwrap());

    let store = TreeKvStore::<String, TestIdentity, Resolver, _>::from_engine(
        Arc::clone(&engine),
        Resolver,
    );
    for (namespace, key, value) in entries {
        assert_eq!(store.get(&namespace, &key).await.unwrap(), Some(value));
    }
    let current = engine.root(&"alice".to_owned()).unwrap();
    assert_ne!(current.commit, legacy_commit);
    let commit = engine.object(current.commit).unwrap();
    let parent = commit
        .reference(&ReferenceLabel::new(b"parent".to_vec()))
        .unwrap();
    assert_eq!(parent.kind(), ReferenceKind::Lineage);
    assert_eq!(parent.target(), legacy_commit);
}

#[test]
fn legacy_avl_migration_rejects_forged_wrapper_totals() {
    let engine = InMemoryEngine::new(TestIdentity);
    publish_legacy_tree(&engine, 1);

    let error = migrate_legacy_avl(&engine, &"alice".to_owned()).unwrap_err();
    assert!(
        error.to_string().contains("legacy KV root totals disagree"),
        "{error}"
    );
}

#[test]
fn migration_revalidates_an_existing_current_projection_before_marking_complete() {
    let engine = InMemoryEngine::new(TestIdentity);
    let mut records = Vec::new();
    let kv = admit(
        &engine,
        &mut records,
        ObjectRecord::new(
            ObjectKind::NamespaceMap,
            PRINCIPAL_GRAPH_VERSION,
            vec![0],
            Vec::new(),
            0,
            ObjectClass::Metadata,
        )
        .unwrap(),
    );
    let state = admit(
        &engine,
        &mut records,
        ObjectRecord::new(
            ObjectKind::PrincipalState,
            PRINCIPAL_GRAPH_VERSION,
            Vec::new(),
            vec![ObjectReference::owns(
                ReferenceLabel::new(b"kv".to_vec()),
                kv,
            )],
            0,
            ObjectClass::Metadata,
        )
        .unwrap(),
    );
    let commit = admit(
        &engine,
        &mut records,
        ObjectRecord::new(
            ObjectKind::Commit,
            PRINCIPAL_GRAPH_VERSION,
            Vec::new(),
            vec![ObjectReference::owns(
                ReferenceLabel::new(b"state".to_vec()),
                state,
            )],
            0,
            ObjectClass::Metadata,
        )
        .unwrap(),
    );
    engine
        .commit(RootTransaction::new(
            "alice".to_owned(),
            None,
            commit,
            records,
        ))
        .unwrap();

    let error = migrate_legacy_avl(&engine, &"alice".to_owned()).unwrap_err();
    assert!(
        error.to_string().contains("truncated KV projection head"),
        "{error}"
    );
}

#[tokio::test]
async fn generated_point_and_range_trace_matches_ordered_map() {
    let store = fixture();
    let namespaces = ["alice:capsule:a", "alice:capsule:b", "bob:capsule:a"];
    let keys = ["a", "ab", "b", "build.cache", "build.meta", "z"];
    let mut expected = BTreeMap::<(String, String), Vec<u8>>::new();
    let mut seed = 0x5452_4545_4b56_3032_u64;

    for step in 0..768 {
        let bits = next(&mut seed);
        let namespace = namespaces[usize::try_from(bits % namespaces.len() as u64).unwrap()];
        let key = keys[usize::try_from((bits >> 8) % keys.len() as u64).unwrap()];
        let map_key = (namespace.to_owned(), key.to_owned());
        let value = bits.to_le_bytes()[..=usize::try_from((bits >> 16) % 8).unwrap()].to_vec();
        match (bits >> 24) % 6 {
            0 => {
                store.set(namespace, key, value.clone()).await.unwrap();
                expected.insert(map_key, value);
            },
            1 => {
                assert_eq!(
                    store.delete(namespace, key).await.unwrap(),
                    expected.remove(&map_key).is_some()
                );
            },
            2 => {
                assert_eq!(
                    store.get(namespace, key).await.unwrap(),
                    expected.get(&map_key).cloned()
                );
            },
            3 => {
                let wanted = expected.get(&map_key).cloned();
                let supplied = if bits & (1 << 40) == 0 {
                    wanted.clone()
                } else {
                    None
                };
                let swapped = store
                    .compare_and_swap(namespace, key, supplied.as_deref(), value.clone())
                    .await
                    .unwrap();
                let should_swap = wanted.as_deref() == supplied.as_deref();
                assert_eq!(swapped, should_swap);
                if should_swap {
                    expected.insert(map_key, value);
                }
            },
            4 => {
                let prefix = if bits & (1 << 41) == 0 { "build." } else { "a" };
                let removed = expected
                    .keys()
                    .filter(|(owner, candidate)| {
                        owner == namespace && candidate.starts_with(prefix)
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                assert_eq!(
                    store.clear_prefix(namespace, prefix).await.unwrap(),
                    removed.len() as u64
                );
                for key in removed {
                    expected.remove(&key);
                }
            },
            _ => {
                let expected_keys = expected
                    .keys()
                    .filter(|(owner, _)| owner == namespace)
                    .map(|(_, key)| key.clone())
                    .collect::<Vec<_>>();
                assert_eq!(
                    store.list_keys(namespace).await.unwrap(),
                    expected_keys,
                    "step {step}"
                );
            },
        }
    }
}

#[tokio::test]
async fn sorted_inserts_use_fat_pages() {
    let engine = Arc::new(InMemoryEngine::new(TestIdentity));
    let store = TreeKvStore::<String, TestIdentity, Resolver, _>::from_engine(
        Arc::clone(&engine),
        Resolver,
    );
    let entries = (0..4_096_u32)
        .map(|value| {
            (
                format!("alice:capsule:build\0{value:08}").into_bytes(),
                value.to_le_bytes().to_vec(),
            )
        })
        .collect();
    store
        .seed_sorted_for_test("alice".to_owned(), entries)
        .unwrap();
    assert!(
        store.height_for_test("alice".to_owned()).unwrap() <= 4,
        "B+-tree height should reflect page fanout"
    );
    for value in [0_u32, 1, 2_047, 4_095] {
        assert_eq!(
            store
                .get("alice:capsule:build", &format!("{value:08}"))
                .await
                .unwrap(),
            Some(value.to_le_bytes().to_vec())
        );
    }
}

#[tokio::test]
async fn inline_and_spilled_values_round_trip_and_replace() {
    let store = fixture();
    let small = vec![7_u8; 1_024];
    let large = vec![9_u8; 1_025];
    store
        .set("alice:capsule:test", "value", small.clone())
        .await
        .unwrap();
    assert_eq!(
        store.get("alice:capsule:test", "value").await.unwrap(),
        Some(small)
    );
    store
        .set("alice:capsule:test", "value", large.clone())
        .await
        .unwrap();
    assert_eq!(
        store.get("alice:capsule:test", "value").await.unwrap(),
        Some(large)
    );
    assert!(store.delete("alice:capsule:test", "value").await.unwrap());
    assert_eq!(
        store.get("alice:capsule:test", "value").await.unwrap(),
        None
    );
}

#[tokio::test]
async fn checkpoint_collapses_deltas_without_changing_the_projection() {
    let store = fixture();
    for value in 0..128_u32 {
        store
            .set(
                "alice:capsule:build",
                &format!("{value:08}"),
                value.to_le_bytes().to_vec(),
            )
            .await
            .unwrap();
    }
    store
        .delete("alice:capsule:build", "00000007")
        .await
        .unwrap();
    assert_eq!(store.delta_depth_for_test("alice".to_owned()).unwrap(), 129);

    assert!(store.checkpoint_for_test("alice".to_owned()).unwrap());
    assert_eq!(store.delta_depth_for_test("alice".to_owned()).unwrap(), 0);
    assert_eq!(
        store.get("alice:capsule:build", "00000007").await.unwrap(),
        None
    );
    for value in [0_u32, 1, 63, 127] {
        assert_eq!(
            store
                .get("alice:capsule:build", &format!("{value:08}"))
                .await
                .unwrap(),
            Some(value.to_le_bytes().to_vec())
        );
    }
}

#[tokio::test]
async fn checkpoint_rebases_a_mutation_that_lands_during_the_build() {
    let store = fixture();
    for value in 0..128_u32 {
        store
            .set(
                "alice:capsule:build",
                &format!("{value:08}"),
                value.to_le_bytes().to_vec(),
            )
            .await
            .unwrap();
    }
    let replacement = vec![7_u8; 2_048];
    assert!(
        store
            .checkpoint_after_mutation_for_test(
                "alice".to_owned(),
                b"alice:capsule:build\0late".to_vec(),
                replacement.clone(),
            )
            .unwrap()
    );

    assert_eq!(store.delta_depth_for_test("alice".to_owned()).unwrap(), 1);
    assert_eq!(
        store.get("alice:capsule:build", "late").await.unwrap(),
        Some(replacement)
    );
    assert_eq!(
        store.get("alice:capsule:build", "00000063").await.unwrap(),
        Some(63_u32.to_le_bytes().to_vec())
    );
}

#[tokio::test]
#[ignore = "release-mode storage format evidence probe"]
async fn transition_point_mutation_authoritative_bytes() {
    for cardinality in [10_000_usize, 100_000, 1_000_000] {
        let engine = Arc::new(MeasuringEngine::new());
        let store = TreeKvStore::<String, TestIdentity, Resolver, _>::from_engine(
            Arc::clone(&engine),
            Resolver,
        );
        let entries = (0..cardinality)
            .map(|index| {
                (
                    format!("alice:capsule:bench\0{index:08}").into_bytes(),
                    vec![0_u8; 128],
                )
            })
            .collect();
        store
            .seed_sorted_for_test("alice".to_owned(), entries)
            .unwrap();
        let checkpoint_bytes = engine.last_authoritative_bytes();
        store
            .get("alice:capsule:bench", &format!("{:08}", cardinality / 3))
            .await
            .unwrap();
        let reads = 2_048_usize;
        let get_started = Instant::now();
        for sample in 0..reads {
            let index = sample.saturating_mul(cardinality / reads.max(1)) % cardinality;
            assert!(
                store
                    .get("alice:capsule:bench", &format!("{index:08}"))
                    .await
                    .unwrap()
                    .is_some()
            );
        }
        let get_ns = get_started.elapsed().as_nanos() / reads as u128;
        let set_started = Instant::now();
        store
            .set(
                "alice:capsule:bench",
                &format!("{:08}", cardinality / 2),
                vec![1_u8; 128],
            )
            .await
            .unwrap();
        let set_elapsed = set_started.elapsed();
        let set_bytes = engine.last_authoritative_bytes();
        let delete_started = Instant::now();
        assert!(
            store
                .delete("alice:capsule:bench", &format!("{:08}", cardinality / 4))
                .await
                .unwrap()
        );
        eprintln!(
            "cardinality={cardinality} checkpoint_bytes={checkpoint_bytes} \
             replacement_bytes={set_bytes} delete_bytes={} get_ns={get_ns} \
             set_us={} delete_us={}",
            engine.last_authoritative_bytes(),
            set_elapsed.as_micros(),
            delete_started.elapsed().as_micros(),
        );
    }
}

#[cfg(not(target_family = "wasm"))]
#[tokio::test]
#[ignore = "release-mode durable storage format evidence probe"]
async fn durable_transition_latency_and_bytes_are_cardinality_stable() {
    for cardinality in [10_000_usize, 100_000, 1_000_000] {
        let directory = tempfile::tempdir().unwrap();
        let engine = Arc::new(
            DurableEngine::open(
                directory.path(),
                TestIdentity,
                Utf8Codec,
                RecoveryLimits::process_addressable(),
            )
            .unwrap(),
        );
        let store = TreeKvStore::<String, TestIdentity, Resolver, _>::from_engine(
            Arc::clone(&engine),
            Resolver,
        );
        let entries = (0..cardinality)
            .map(|index| {
                (
                    format!("alice:capsule:bench\0{index:08}").into_bytes(),
                    vec![0_u8; 128],
                )
            })
            .collect();
        store
            .seed_sorted_for_test("alice".to_owned(), entries)
            .unwrap();
        let warm_key = format!("{:08}", cardinality / 3);
        store.get("alice:capsule:bench", &warm_key).await.unwrap();
        let reads = 2_048_usize;
        let get_started = Instant::now();
        for sample in 0..reads {
            let index = sample.saturating_mul(cardinality / reads.max(1)) % cardinality;
            assert!(
                store
                    .get("alice:capsule:bench", &format!("{index:08}"))
                    .await
                    .unwrap()
                    .is_some()
            );
        }
        let get_ns = get_started.elapsed().as_nanos() / reads as u128;
        let before_arena = std::fs::metadata(directory.path().join("objects.arena"))
            .unwrap()
            .len();
        let before_roots = std::fs::metadata(directory.path().join("roots.journal"))
            .unwrap()
            .len();
        let set_started = Instant::now();
        store
            .set(
                "alice:capsule:bench",
                &format!("{:08}", cardinality / 2),
                vec![1_u8; 128],
            )
            .await
            .unwrap();
        let set_elapsed = set_started.elapsed();
        let written = std::fs::metadata(directory.path().join("objects.arena"))
            .unwrap()
            .len()
            .saturating_sub(before_arena)
            .saturating_add(
                std::fs::metadata(directory.path().join("roots.journal"))
                    .unwrap()
                    .len()
                    .saturating_sub(before_roots),
            );
        store.close().await.unwrap();
        drop(store);
        drop(engine);
        let reopen_started = Instant::now();
        let reopened = DurableEngine::<String, TestIdentity, Utf8Codec>::open(
            directory.path(),
            TestIdentity,
            Utf8Codec,
            RecoveryLimits::process_addressable(),
        )
        .unwrap();
        let reopen_elapsed = reopen_started.elapsed();
        eprintln!(
            "durable cardinality={cardinality} replacement_bytes={written} \
             get_ns={get_ns} set_us={} reopen_ms={}",
            set_elapsed.as_micros(),
            reopen_elapsed.as_millis(),
        );
        reopened.close().unwrap();
    }
}
