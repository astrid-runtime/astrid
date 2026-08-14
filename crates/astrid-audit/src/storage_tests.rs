use super::*;
use crate::entry::{AuditAction, AuditOutcome, AuthorizationProof};
use astrid_crypto::{ContentHash, KeyPair};
use astrid_storage::{StorageError, StorageResult};
use std::sync::atomic::{AtomicUsize, Ordering};

struct FailOneMutationStore {
    inner: MemoryKvStore,
    fail_at: usize,
    mutations: AtomicUsize,
    block_commit: bool,
    commit_entered: tokio::sync::Notify,
}

impl FailOneMutationStore {
    fn new(fail_at: usize) -> Self {
        Self {
            inner: MemoryKvStore::new(),
            fail_at,
            mutations: AtomicUsize::new(0),
            block_commit: false,
            commit_entered: tokio::sync::Notify::new(),
        }
    }

    fn blocking_commit() -> Self {
        Self {
            inner: MemoryKvStore::new(),
            fail_at: usize::MAX,
            mutations: AtomicUsize::new(0),
            block_commit: true,
            commit_entered: tokio::sync::Notify::new(),
        }
    }

    fn fail_now(&self) -> StorageResult<()> {
        let mutation = self
            .mutations
            .fetch_add(1, Ordering::SeqCst)
            .saturating_add(1);
        if mutation == self.fail_at {
            Err(StorageError::Internal(format!(
                "injected mutation failure {mutation}"
            )))
        } else {
            Ok(())
        }
    }
}

#[async_trait]
impl KvStore for FailOneMutationStore {
    async fn get(&self, namespace: &str, key: &str) -> StorageResult<Option<Vec<u8>>> {
        self.inner.get(namespace, key).await
    }

    async fn set(&self, namespace: &str, key: &str, value: Vec<u8>) -> StorageResult<()> {
        if self.block_commit && namespace == NS_SESSION_ENTRIES {
            self.commit_entered.notify_one();
            std::future::pending::<()>().await;
        }
        self.fail_now()?;
        self.inner.set(namespace, key, value).await
    }

    async fn delete(&self, namespace: &str, key: &str) -> StorageResult<bool> {
        self.inner.delete(namespace, key).await
    }

    async fn exists(&self, namespace: &str, key: &str) -> StorageResult<bool> {
        self.inner.exists(namespace, key).await
    }

    async fn list_keys(&self, namespace: &str) -> StorageResult<Vec<String>> {
        self.inner.list_keys(namespace).await
    }

    async fn list_keys_with_prefix(
        &self,
        namespace: &str,
        prefix: &str,
    ) -> StorageResult<Vec<String>> {
        self.inner.list_keys_with_prefix(namespace, prefix).await
    }

    async fn compare_and_swap(
        &self,
        namespace: &str,
        key: &str,
        expected: Option<&[u8]>,
        new: Vec<u8>,
    ) -> StorageResult<bool> {
        self.fail_now()?;
        self.inner
            .compare_and_swap(namespace, key, expected, new)
            .await
    }

    async fn clear_namespace(&self, namespace: &str) -> StorageResult<u64> {
        self.inner.clear_namespace(namespace).await
    }
}

fn test_keypair() -> KeyPair {
    KeyPair::generate()
}

#[tokio::test]
async fn test_store_and_retrieve() {
    let storage = SurrealKvAuditStorage::in_memory();
    let keypair = test_keypair();
    let session_id = SessionId::new();

    let entry = AuditEntry::create(
        session_id.clone(),
        AuditAction::SessionStarted {
            user_id: keypair.key_id(),
            platform: "cli".to_string(),
        },
        AuthorizationProof::System {
            reason: "test".to_string(),
        },
        AuditOutcome::success(),
        ContentHash::zero(),
        &keypair,
    );

    let entry_id = entry.id.clone();

    storage.store(&entry).await.unwrap();

    let retrieved = storage.get(&entry_id).await.unwrap().unwrap();
    assert_eq!(retrieved.id, entry_id);
}

#[tokio::test]
async fn test_session_index() {
    let storage = SurrealKvAuditStorage::in_memory();
    let keypair = test_keypair();
    let session_id = SessionId::new();

    // Create multiple entries
    let mut prev_hash = ContentHash::zero();
    for i in 0..3 {
        let entry = AuditEntry::create(
            session_id.clone(),
            AuditAction::McpToolCall {
                server: "test".to_string(),
                tool: format!("tool_{i}"),
                args_hash: ContentHash::zero(),
            },
            AuthorizationProof::NotRequired {
                reason: "test".to_string(),
            },
            AuditOutcome::success(),
            prev_hash,
            &keypair,
        );
        prev_hash = entry.content_hash();
        storage.store(&entry).await.unwrap();
    }

    let entries = storage.get_session_entries(&session_id).await.unwrap();
    assert_eq!(entries.len(), 3);
}

#[tokio::test]
async fn failed_precommit_writes_remain_invisible_and_reopen_cleanly() {
    // The append protocol has three mutations: direct lookup entry, CAS
    // sequence reservation, then the self-contained commit record.
    for fail_at in 1..=3 {
        let raw = Arc::new(FailOneMutationStore::new(fail_at));
        let store: Arc<dyn KvStore> = raw;
        let storage = SurrealKvAuditStorage {
            store: Arc::clone(&store),
        };
        let keypair = KeyPair::generate();
        let session_id = SessionId::new();
        let failed = AuditEntry::create(
            session_id.clone(),
            AuditAction::ConfigReloaded,
            AuthorizationProof::System {
                reason: "failure injection".into(),
            },
            AuditOutcome::success(),
            ContentHash::zero(),
            &keypair,
        );
        assert!(storage.store(&failed).await.is_err());
        assert_eq!(storage.count_session(&session_id).await.unwrap(), 0);
        assert!(storage.list_sessions().await.unwrap().is_empty());
        assert!(
            storage
                .get_chain_head(&session_id, None)
                .await
                .unwrap()
                .is_none()
        );

        // A fresh storage/log view over the same durable bytes must ignore
        // any orphan lookup entry or sequence gap and start one valid chain.
        let reopened =
            crate::AuditLog::with_test_storage(Box::new(SurrealKvAuditStorage { store }), keypair);
        reopened
            .append(
                session_id.clone(),
                AuditAction::ConfigReloaded,
                AuthorizationProof::System {
                    reason: "reopen".into(),
                },
                AuditOutcome::success(),
            )
            .await
            .unwrap();
        assert_eq!(reopened.count().await.unwrap(), 1);
        assert_eq!(reopened.count_session(&session_id).await.unwrap(), 1);
        assert_eq!(
            reopened.list_sessions().await.unwrap(),
            vec![session_id.clone()]
        );
        assert!(reopened.verify_chain(&session_id).await.unwrap().valid);
    }
}

#[tokio::test]
async fn cancelled_before_commit_remains_invisible_and_reopens_cleanly() {
    let raw = Arc::new(FailOneMutationStore::blocking_commit());
    let store: Arc<dyn KvStore> = raw.clone();
    let storage = Arc::new(SurrealKvAuditStorage {
        store: Arc::clone(&store),
    });
    let keypair = KeyPair::generate();
    let session_id = SessionId::new();
    let entry = AuditEntry::create(
        session_id.clone(),
        AuditAction::ConfigReloaded,
        AuthorizationProof::System {
            reason: "cancel injection".into(),
        },
        AuditOutcome::success(),
        ContentHash::zero(),
        &keypair,
    );
    let task = {
        let storage = Arc::clone(&storage);
        tokio::spawn(async move { storage.store(&entry).await })
    };
    raw.commit_entered.notified().await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(storage.count_session(&session_id).await.unwrap(), 0);
    assert!(storage.list_sessions().await.unwrap().is_empty());

    // Reopen through a non-blocking view of the same bytes. The wrapper's
    // inner store cannot be extracted, so copy only durable raw records to
    // model a process restart after cancellation.
    let reopened_store = Arc::new(MemoryKvStore::new());
    for namespace in [NS_ENTRIES, NS_SESSION_SEQUENCE, NS_SESSION_ENTRIES] {
        for key in raw.inner.list_keys(namespace).await.unwrap() {
            let value = raw.inner.get(namespace, &key).await.unwrap().unwrap();
            reopened_store.set(namespace, &key, value).await.unwrap();
        }
    }
    let reopened = crate::AuditLog::with_test_storage(
        Box::new(SurrealKvAuditStorage {
            store: reopened_store,
        }),
        keypair,
    );
    reopened
        .append(
            session_id.clone(),
            AuditAction::ConfigReloaded,
            AuthorizationProof::System {
                reason: "after cancellation".into(),
            },
            AuditOutcome::success(),
        )
        .await
        .unwrap();
    assert_eq!(reopened.count_session(&session_id).await.unwrap(), 1);
    assert!(reopened.verify_chain(&session_id).await.unwrap().valid);
}

#[tokio::test]
async fn append_only_index_has_bounded_per_entry_records() {
    let storage = SurrealKvAuditStorage::in_memory();
    let keypair = test_keypair();
    let session_id = SessionId::new();

    for _ in 0..64 {
        let entry = AuditEntry::create(
            session_id.clone(),
            AuditAction::ConfigReloaded,
            AuthorizationProof::System {
                reason: "bounded index test".to_string(),
            },
            AuditOutcome::success(),
            ContentHash::zero(),
            &keypair,
        );
        storage.store(&entry).await.unwrap();
    }

    let session_key = session_id.0.to_string();
    assert!(
        storage
            .store
            .get(NS_SESSION_INDEX, &session_key)
            .await
            .unwrap()
            .is_none(),
        "new appends must not rewrite the legacy growing array"
    );
    let keys = storage
        .store
        .list_keys_with_prefix(NS_SESSION_ENTRIES, &format!("{session_key}:"))
        .await
        .unwrap();
    assert_eq!(keys.len(), 64);
    for key in keys {
        let record = storage
            .store
            .get(NS_SESSION_ENTRIES, &key)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record, vec![1]);
    }
    assert_eq!(
        storage
            .store
            .get(NS_SESSION_SEQUENCE, &session_key)
            .await
            .unwrap()
            .unwrap()
            .len(),
        std::mem::size_of::<u64>()
    );
}

#[tokio::test]
async fn legacy_and_append_only_indexes_merge_without_duplicates_in_order() {
    let storage = SurrealKvAuditStorage::in_memory();
    let keypair = test_keypair();
    let session_id = SessionId::new();
    let create_entry = || {
        AuditEntry::create(
            session_id.clone(),
            AuditAction::ConfigReloaded,
            AuthorizationProof::System {
                reason: "mixed index test".to_string(),
            },
            AuditOutcome::success(),
            ContentHash::zero(),
            &keypair,
        )
    };
    let legacy_first = create_entry();
    let overlap = create_entry();
    let appended = create_entry();

    for entry in [&legacy_first, &overlap] {
        storage
            .store
            .set(
                NS_ENTRIES,
                &entry.id.0.to_string(),
                serde_json::to_vec(entry).unwrap(),
            )
            .await
            .unwrap();
    }
    storage
        .store
        .set(
            NS_SESSION_INDEX,
            &session_id.0.to_string(),
            serde_json::to_vec(&vec![legacy_first.id.clone(), overlap.id.clone()]).unwrap(),
        )
        .await
        .unwrap();

    // Simulate a partially migrated overlap, then a normal new append.
    storage.store(&overlap).await.unwrap();
    storage.store(&appended).await.unwrap();

    let entries = storage.get_session_entries(&session_id).await.unwrap();
    let ids: Vec<_> = entries.into_iter().map(|entry| entry.id).collect();
    assert_eq!(
        ids,
        vec![legacy_first.id, overlap.id, appended.id],
        "legacy insertion order is the prefix and new records follow it"
    );
    assert_eq!(storage.count_session(&session_id).await.unwrap(), 3);
    assert_eq!(storage.list_sessions().await.unwrap(), vec![session_id]);
}

#[tokio::test]
async fn list_and_count_cover_legacy_and_new_sessions() {
    let storage = SurrealKvAuditStorage::in_memory();
    let keypair = test_keypair();
    let legacy_session = SessionId::new();
    let new_session = SessionId::new();
    let legacy_entry = AuditEntry::create(
        legacy_session.clone(),
        AuditAction::ConfigReloaded,
        AuthorizationProof::System {
            reason: "legacy".to_string(),
        },
        AuditOutcome::success(),
        ContentHash::zero(),
        &keypair,
    );
    storage
        .store
        .set(
            NS_ENTRIES,
            &legacy_entry.id.0.to_string(),
            serde_json::to_vec(&legacy_entry).unwrap(),
        )
        .await
        .unwrap();
    storage
        .store
        .set(
            NS_SESSION_INDEX,
            &legacy_session.0.to_string(),
            serde_json::to_vec(&vec![legacy_entry.id]).unwrap(),
        )
        .await
        .unwrap();

    let new_entry = AuditEntry::create(
        new_session.clone(),
        AuditAction::ConfigReloaded,
        AuthorizationProof::System {
            reason: "new".to_string(),
        },
        AuditOutcome::success(),
        ContentHash::zero(),
        &keypair,
    );
    storage.store(&new_entry).await.unwrap();

    assert_eq!(storage.count_session(&legacy_session).await.unwrap(), 1);
    assert_eq!(storage.count_session(&new_session).await.unwrap(), 1);
    let sessions = storage.list_sessions().await.unwrap();
    assert_eq!(sessions.len(), 2);
    assert!(sessions.contains(&legacy_session));
    assert!(sessions.contains(&new_session));
}

#[tokio::test]
async fn test_chain_head() {
    let storage = SurrealKvAuditStorage::in_memory();
    let keypair = test_keypair();
    let session_id = SessionId::new();

    let entry1 = AuditEntry::create(
        session_id.clone(),
        AuditAction::SessionStarted {
            user_id: keypair.key_id(),
            platform: "cli".to_string(),
        },
        AuthorizationProof::System {
            reason: "test".to_string(),
        },
        AuditOutcome::success(),
        ContentHash::zero(),
        &keypair,
    );

    storage.store(&entry1).await.unwrap();

    let entry2 = AuditEntry::create(
        session_id.clone(),
        AuditAction::SessionEnded {
            reason: "done".to_string(),
            duration_secs: 100,
        },
        AuthorizationProof::System {
            reason: "test".to_string(),
        },
        AuditOutcome::success(),
        entry1.content_hash(),
        &keypair,
    );

    storage.store(&entry2).await.unwrap();

    let head = storage
        .get_chain_head(&session_id, None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(head, entry2.id);
}

/// Exercises the `block_in_place` branch that only fires under a
/// multi-threaded runtime (the production path fixed by #305).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_store_and_retrieve_multi_thread() {
    let storage = SurrealKvAuditStorage::in_memory();
    let keypair = test_keypair();
    let session_id = SessionId::new();

    let entry = AuditEntry::create(
        session_id.clone(),
        AuditAction::SessionStarted {
            user_id: keypair.key_id(),
            platform: "cli".to_string(),
        },
        AuthorizationProof::System {
            reason: "test".to_string(),
        },
        AuditOutcome::success(),
        ContentHash::zero(),
        &keypair,
    );

    let entry_id = entry.id.clone();
    storage.store(&entry).await.unwrap();

    let retrieved = storage.get(&entry_id).await.unwrap().unwrap();
    assert_eq!(retrieved.id, entry_id);

    // Also verify session queries work under a multi-threaded runtime.
    let entries = storage.get_session_entries(&session_id).await.unwrap();
    assert_eq!(entries.len(), 1);

    let head = storage
        .get_chain_head(&session_id, None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(head, entry_id);
}

/// Concurrent stores from multiple tasks under a multi-threaded runtime.
/// Exercises the async persist path under the load pattern from #305.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_concurrent_stores_multi_thread() {
    let storage = std::sync::Arc::new(SurrealKvAuditStorage::in_memory());
    let mut handles = Vec::new();

    for _ in 0..8 {
        let s = std::sync::Arc::clone(&storage);
        handles.push(tokio::task::spawn(async move {
            let keypair = test_keypair();
            let session_id = SessionId::new();
            let entry = AuditEntry::create(
                session_id,
                AuditAction::SessionStarted {
                    user_id: keypair.key_id(),
                    platform: "cli".to_string(),
                },
                AuthorizationProof::System {
                    reason: "test".to_string(),
                },
                AuditOutcome::success(),
                ContentHash::zero(),
                &keypair,
            );
            s.store(&entry).await.unwrap();
            entry.id
        }));
    }

    for h in handles {
        let id = h.await.unwrap();
        assert!(storage.get(&id).await.unwrap().is_some());
    }

    // All 8 sessions should be visible.
    let sessions = storage.list_sessions().await.unwrap();
    assert_eq!(sessions.len(), 8);
}
