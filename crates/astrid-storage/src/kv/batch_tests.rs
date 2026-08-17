use std::sync::Arc;

use crate::engine::InMemoryEngine;
use crate::storage_model::{ObjectClass, ObjectId, ObjectIdentity, ObjectRecord, ReferenceKind};
use crate::{StorageError, StorageResult};

use super::{
    KvBatchCondition, KvBatchMutation, KvEntryKey, KvMutationBatch, KvPrincipalResolver,
    KvQuotaResolver, KvStore, MAX_KV_BATCH_OPERATIONS, MemoryKvStore, TreeKvStore,
};

#[derive(Clone, Copy, Debug)]
struct TestIdentity;

impl ObjectIdentity for TestIdentity {
    fn identify(&self, record: &ObjectRecord) -> ObjectId {
        let mut hasher = blake3::Hasher::new_derive_key("astrid KV batch test identity v1");
        hasher.update(&record.kind().code().to_le_bytes());
        hasher.update(&record.format_version().get().to_le_bytes());
        hasher.update(record.canonical_bytes());
        hasher.update(&record.logical_bytes().to_le_bytes());
        hasher.update(&[match record.class() {
            ObjectClass::Data => 0,
            ObjectClass::Metadata => 1,
        }]);
        hasher.update(&(record.references().len() as u64).to_le_bytes());
        for reference in record.references() {
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

type TreeStore = TreeKvStore<String, TestIdentity, Resolver, InMemoryEngine<String, TestIdentity>>;

fn tree_store() -> TreeStore {
    TreeKvStore::from_engine(Arc::new(InMemoryEngine::new(TestIdentity)), Resolver)
}

fn key(namespace: &str, key: &str) -> KvEntryKey {
    KvEntryKey::new(namespace, key).unwrap()
}

#[tokio::test]
async fn memory_applies_set_delete_and_cas_atomically() {
    let store = MemoryKvStore::new();
    store.set("ns", "cas", b"old".to_vec()).await.unwrap();
    store
        .set("ns", "remove", b"present".to_vec())
        .await
        .unwrap();

    let batch = KvMutationBatch::new(
        [
            KvBatchCondition::ValueEquals {
                key: key("ns", "cas"),
                expected: Some(b"old".to_vec()),
            },
            KvBatchCondition::ValueEquals {
                key: key("ns", "remove"),
                expected: Some(b"present".to_vec()),
            },
        ],
        [
            KvBatchMutation::Set {
                key: key("ns", "cas"),
                value: b"new".to_vec(),
            },
            KvBatchMutation::Delete {
                key: key("ns", "remove"),
            },
        ],
    )
    .unwrap();

    let outcome = store.apply_batch(&batch).await.unwrap();
    assert!(outcome.applied);
    assert!(outcome.conditions.iter().all(|condition| condition.matched));
    assert_eq!(store.get("ns", "cas").await.unwrap(), Some(b"new".to_vec()));
    assert_eq!(store.get("ns", "remove").await.unwrap(), None);
}

#[tokio::test]
async fn memory_failed_condition_does_not_mutate_any_key() {
    let store = MemoryKvStore::new();
    store.set("ns", "guard", b"actual".to_vec()).await.unwrap();
    store
        .set("ns", "untouched", b"before".to_vec())
        .await
        .unwrap();

    let batch = KvMutationBatch::new(
        [KvBatchCondition::ValueEquals {
            key: key("ns", "guard"),
            expected: Some(b"wrong".to_vec()),
        }],
        [KvBatchMutation::Set {
            key: key("ns", "untouched"),
            value: b"after".to_vec(),
        }],
    )
    .unwrap();
    let outcome = store.apply_batch(&batch).await.unwrap();
    assert!(!outcome.applied);
    assert!(!outcome.conditions[0].matched);
    assert_eq!(
        store.get("ns", "untouched").await.unwrap(),
        Some(b"before".to_vec())
    );
}

#[test]
fn batch_rejects_duplicate_keys_and_bounds() {
    let duplicate = key("ns", "same");
    assert!(
        KvMutationBatch::new(
            [],
            [
                KvBatchMutation::Delete {
                    key: duplicate.clone(),
                },
                KvBatchMutation::Set {
                    key: duplicate,
                    value: vec![1],
                },
            ],
        )
        .is_err()
    );

    let too_many = (0..MAX_KV_BATCH_OPERATIONS)
        .map(|index| KvBatchMutation::Delete {
            key: key("ns", &format!("key-{index}")),
        })
        .collect::<Vec<_>>();
    // One condition plus the maximum number of mutations exceeds the total
    // operation bound.
    assert!(
        KvMutationBatch::new(
            [KvBatchCondition::ValueEquals {
                key: key("ns", "condition"),
                expected: None,
            }],
            too_many,
        )
        .is_err()
    );
}

#[tokio::test]
async fn tree_applies_same_owner_set_delete_as_one_batch() {
    let store = tree_store();
    store
        .set("alice:capsule:one", "cas", b"old".to_vec())
        .await
        .unwrap();
    store
        .set("alice:capsule:two", "remove", b"present".to_vec())
        .await
        .unwrap();

    let batch = KvMutationBatch::new(
        [
            KvBatchCondition::ValueEquals {
                key: key("alice:capsule:one", "cas"),
                expected: Some(b"old".to_vec()),
            },
            KvBatchCondition::ValueEquals {
                key: key("alice:capsule:two", "remove"),
                expected: Some(b"present".to_vec()),
            },
        ],
        [
            KvBatchMutation::Set {
                key: key("alice:capsule:one", "cas"),
                value: b"new".to_vec(),
            },
            KvBatchMutation::Delete {
                key: key("alice:capsule:two", "remove"),
            },
        ],
    )
    .unwrap();
    let outcome = store.apply_batch(&batch).await.unwrap();
    assert!(outcome.applied);
    assert_eq!(outcome.conditions.len(), 2);
    assert_eq!(
        store.get("alice:capsule:one", "cas").await.unwrap(),
        Some(b"new".to_vec())
    );
    assert_eq!(
        store.get("alice:capsule:two", "remove").await.unwrap(),
        None
    );
}

#[tokio::test]
async fn tree_failed_condition_leaves_every_key_unchanged() {
    let store = tree_store();
    store
        .set("alice:capsule:one", "guard", b"actual".to_vec())
        .await
        .unwrap();
    store
        .set("alice:capsule:two", "untouched", b"before".to_vec())
        .await
        .unwrap();

    let batch = KvMutationBatch::new(
        [KvBatchCondition::ValueEquals {
            key: key("alice:capsule:one", "guard"),
            expected: Some(b"wrong".to_vec()),
        }],
        [KvBatchMutation::Set {
            key: key("alice:capsule:two", "untouched"),
            value: b"after".to_vec(),
        }],
    )
    .unwrap();
    let outcome = store.apply_batch(&batch).await.unwrap();
    assert!(!outcome.applied);
    assert!(!outcome.conditions[0].matched);
    assert_eq!(
        store.get("alice:capsule:two", "untouched").await.unwrap(),
        Some(b"before".to_vec())
    );
}

#[tokio::test]
async fn tree_rejects_mixed_owner_batch_before_mutating() {
    let store = tree_store();
    let batch = KvMutationBatch::new(
        [KvBatchCondition::ValueEquals {
            key: key("alice:capsule:one", "guard"),
            expected: None,
        }],
        [KvBatchMutation::Set {
            key: key("bob:capsule:one", "value"),
            value: b"must-not-commit".to_vec(),
        }],
    )
    .unwrap();
    let error = store.apply_batch(&batch).await.unwrap_err();
    assert!(matches!(error, StorageError::InvalidKey(_)));
    assert_eq!(store.get("bob:capsule:one", "value").await.unwrap(), None);
}

#[tokio::test]
async fn tree_quota_failure_is_atomic() {
    let quota: Arc<dyn KvQuotaResolver<String>> = Arc::new(|_: &String| Ok(Some(1_u64)));
    let store: TreeStore = TreeKvStore::from_engine_with_quota(
        Arc::new(InMemoryEngine::new(TestIdentity)),
        Resolver,
        quota,
    );
    let batch = KvMutationBatch::new(
        [],
        [KvBatchMutation::Set {
            key: key("alice:capsule:one", "value"),
            value: b"too-large".to_vec(),
        }],
    )
    .unwrap();
    assert!(store.apply_batch(&batch).await.is_err());
    assert_eq!(store.get("alice:capsule:one", "value").await.unwrap(), None);
}
