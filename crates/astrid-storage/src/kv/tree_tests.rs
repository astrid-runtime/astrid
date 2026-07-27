use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use astrid_storage_engine::{InMemoryEngine, RootTransaction};
use astrid_storage_model::{
    ObjectClass, ObjectId, ObjectIdentity, ObjectKind, ObjectRecord, ObjectReference,
    ReferenceKind, ReferenceLabel,
};

use super::tree::{FORMAT_VERSION, KV_LABEL, LEFT_LABEL, ROOT_LABEL, STATE_LABEL, VALUE_LABEL};
use super::{KvPrincipalResolver, KvQuotaResolver, KvStore, TreeKvStore};
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

struct BlockingQuota {
    entered: Arc<AtomicBool>,
    released: Arc<AtomicBool>,
}

impl KvQuotaResolver<String> for BlockingQuota {
    fn max_logical_bytes(&self, _principal: &String) -> StorageResult<Option<u64>> {
        self.entered.store(true, Ordering::Release);
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(500))
            .unwrap();
        while !self.released.load(Ordering::Acquire) {
            if Instant::now() >= deadline {
                return Err(StorageError::Internal(
                    "async executor stalled behind storage I/O".to_owned(),
                ));
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        Ok(None)
    }
}

type Store = TreeKvStore<String, TestIdentity, Resolver, InMemoryEngine<String, TestIdentity>>;

fn fixture() -> Arc<Store> {
    Arc::new(TreeKvStore::from_engine(
        Arc::new(InMemoryEngine::new(TestIdentity)),
        Resolver,
    ))
}

fn insert_record(
    engine: &InMemoryEngine<String, TestIdentity>,
    records: &mut Vec<(ObjectId, ObjectRecord)>,
    record: ObjectRecord,
) -> ObjectId {
    let id = engine.identify(&record);
    records.push((id, record));
    id
}

fn leaf(
    engine: &InMemoryEngine<String, TestIdentity>,
    records: &mut Vec<(ObjectId, ObjectRecord)>,
    value: &[u8],
) -> ObjectId {
    let record = ObjectRecord::new(
        ObjectKind::KvLeaf,
        FORMAT_VERSION,
        value.to_vec(),
        Vec::new(),
        0,
        ObjectClass::Data,
    )
    .unwrap();
    insert_record(engine, records, record)
}

#[derive(Clone, Copy)]
struct BranchSpec<'a> {
    key: &'a [u8],
    value: ObjectId,
    value_len: u64,
    left: Option<ObjectId>,
    height: u32,
    logical_total: u64,
    quota_total: u64,
}

fn branch(
    engine: &InMemoryEngine<String, TestIdentity>,
    records: &mut Vec<(ObjectId, ObjectRecord)>,
    spec: BranchSpec<'_>,
) -> ObjectId {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&spec.height.to_le_bytes());
    bytes.extend_from_slice(&spec.logical_total.to_le_bytes());
    bytes.extend_from_slice(&spec.quota_total.to_le_bytes());
    bytes.extend_from_slice(&spec.value_len.to_le_bytes());
    bytes.extend_from_slice(spec.key);
    let mut references = vec![ObjectReference::owns(
        ReferenceLabel::new(VALUE_LABEL.to_vec()),
        spec.value,
    )];
    if let Some(left) = spec.left {
        references.push(ObjectReference::owns(
            ReferenceLabel::new(LEFT_LABEL.to_vec()),
            left,
        ));
    }
    references.sort();
    let record = ObjectRecord::new(
        ObjectKind::KvBranch,
        FORMAT_VERSION,
        bytes,
        references,
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    insert_record(engine, records, record)
}

fn publish_tree(
    engine: &InMemoryEngine<String, TestIdentity>,
    mut records: Vec<(ObjectId, ObjectRecord)>,
    root: ObjectId,
    logical_total: u64,
    quota_total: u64,
) {
    let wrapper = ObjectRecord::new(
        ObjectKind::NamespaceMap,
        FORMAT_VERSION,
        quota_total.to_le_bytes().to_vec(),
        vec![ObjectReference::owns(
            ReferenceLabel::new(ROOT_LABEL.to_vec()),
            root,
        )],
        logical_total,
        ObjectClass::Metadata,
    )
    .unwrap();
    let wrapper = insert_record(engine, &mut records, wrapper);
    let state = ObjectRecord::new(
        ObjectKind::PrincipalState,
        FORMAT_VERSION,
        Vec::new(),
        vec![ObjectReference::owns(
            ReferenceLabel::new(KV_LABEL.to_vec()),
            wrapper,
        )],
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let state = insert_record(engine, &mut records, state);
    let commit = ObjectRecord::new(
        ObjectKind::Commit,
        FORMAT_VERSION,
        Vec::new(),
        vec![ObjectReference::owns(
            ReferenceLabel::new(STATE_LABEL.to_vec()),
            state,
        )],
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let commit = insert_record(engine, &mut records, commit);
    engine
        .commit(RootTransaction::new(
            "alice".to_owned(),
            None,
            commit,
            records,
        ))
        .unwrap();
}

fn next(seed: &mut u64) -> u64 {
    *seed ^= *seed << 13;
    *seed ^= *seed >> 7;
    *seed ^= *seed << 17;
    *seed
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

        if step % 32 == 0 {
            for namespace in namespaces {
                let expected_keys = expected
                    .keys()
                    .filter(|(owner, _)| owner == namespace)
                    .map(|(_, key)| key.clone())
                    .collect::<Vec<_>>();
                assert_eq!(store.list_keys(namespace).await.unwrap(), expected_keys);
            }
        }
    }
}

#[tokio::test]
async fn sorted_inserts_remain_height_bounded() {
    let store = fixture();
    for value in 0..1_024_u32 {
        store
            .set(
                "alice:capsule:build",
                &format!("{value:04}"),
                value.to_le_bytes().to_vec(),
            )
            .await
            .unwrap();
    }
    assert!(
        store.height_for_test("alice".to_owned()).unwrap() <= 11,
        "AVL height should remain logarithmic"
    );
}

#[tokio::test]
async fn self_consistent_forged_tree_totals_are_rejected() {
    let engine = Arc::new(InMemoryEngine::new(TestIdentity));
    let mut records = Vec::new();
    let value = leaf(engine.as_ref(), &mut records, b"value");
    let key = b"alice:capsule:test\0key";
    let root = branch(
        engine.as_ref(),
        &mut records,
        BranchSpec {
            key,
            value,
            value_len: 5,
            left: None,
            height: 1,
            logical_total: 0,
            quota_total: u64::try_from(key.len()).unwrap(),
        },
    );
    publish_tree(engine.as_ref(), records, root, 0, key.len() as u64);
    let store = TreeKvStore::<String, TestIdentity, Resolver, _>::from_engine(engine, Resolver);

    assert!(
        store
            .get("alice:capsule:test", "key")
            .await
            .unwrap_err()
            .to_string()
            .contains("node totals disagree")
    );
}

#[tokio::test]
async fn self_consistent_out_of_order_tree_is_rejected() {
    let engine = Arc::new(InMemoryEngine::new(TestIdentity));
    let mut records = Vec::new();
    let value = leaf(engine.as_ref(), &mut records, b"x");
    let left_key = b"alice:capsule:test\0z";
    let left = branch(
        engine.as_ref(),
        &mut records,
        BranchSpec {
            key: left_key,
            value,
            value_len: 1,
            left: None,
            height: 1,
            logical_total: 1,
            quota_total: u64::try_from(left_key.len() + 1).unwrap(),
        },
    );
    let root_key = b"alice:capsule:test\0m";
    let quota = u64::try_from(left_key.len() + root_key.len() + 2).unwrap();
    let root = branch(
        engine.as_ref(),
        &mut records,
        BranchSpec {
            key: root_key,
            value,
            value_len: 1,
            left: Some(left),
            height: 2,
            logical_total: 2,
            quota_total: quota,
        },
    );
    publish_tree(engine.as_ref(), records, root, 2, quota);
    let store = TreeKvStore::<String, TestIdentity, Resolver, _>::from_engine(engine, Resolver);

    assert!(
        store
            .list_keys("alice:capsule:test")
            .await
            .unwrap_err()
            .to_string()
            .contains("key order is invalid")
    );
}

#[tokio::test(flavor = "current_thread")]
async fn engine_work_runs_off_the_async_executor() {
    let entered = Arc::new(AtomicBool::new(false));
    let released = Arc::new(AtomicBool::new(false));
    let store = TreeKvStore::<String, TestIdentity, Resolver, _>::from_engine_with_quota(
        Arc::new(InMemoryEngine::new(TestIdentity)),
        Resolver,
        Arc::new(BlockingQuota {
            entered: Arc::clone(&entered),
            released: Arc::clone(&released),
        }),
    );
    let release = tokio::spawn(async move {
        while !entered.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
        released.store(true, Ordering::Release);
    });

    store
        .set("alice:capsule:build", "executor", b"alive".to_vec())
        .await
        .unwrap();
    release.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_insert_if_absent_has_one_root_cas_winner() {
    let store = fixture();
    let barrier = Arc::new(tokio::sync::Barrier::new(17));
    let mut tasks = Vec::new();
    for value in 0..16_u8 {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store
                .compare_and_swap("alice:capsule:build", "winner", None, vec![value])
                .await
                .unwrap()
        }));
    }
    barrier.wait().await;
    let mut winners = 0;
    for task in tasks {
        winners += usize::from(task.await.unwrap());
    }
    assert_eq!(winners, 1);
}
