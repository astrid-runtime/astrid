use std::collections::BTreeMap;
use std::sync::Arc;

use astrid_storage_engine::InMemoryEngine;
use astrid_storage_model::{ObjectClass, ObjectId, ObjectIdentity, ObjectRecord, ReferenceKind};

use super::{KvPrincipalResolver, KvStore, TreeKvStore};
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

type Store = TreeKvStore<String, TestIdentity, Resolver, InMemoryEngine<String, TestIdentity>>;

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
