use super::*;
use crate::entry::{AuditAction, AuditOutcome, AuthorizationProof};
use astrid_crypto::{ContentHash, KeyPair};
use astrid_storage::{StorageError, StorageResult};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

struct FailOneMutationStore {
    inner: MemoryKvStore,
    fail_at: usize,
    mutations: AtomicUsize,
    block_commit: bool,
    commit_entered: tokio::sync::Notify,
}

#[derive(Clone, Copy, Debug)]
enum AppendFailureStage {
    /// The entry, session index, chain head, and commit marker are durable;
    /// the metadata stage is rejected before it can apply.
    EntryHead,
    /// Chain metadata is durable, then the append reports a fault before the
    /// segment/global stages.
    Metadata,
    /// The sealed-segment descriptor is durable, then the append reports a
    /// fault before global accounting.
    Segment,
    /// Global accounting is durable, but the caller observes a post-commit
    /// error (the crash/cancellation boundary).
    Global,
}

struct FailAfterAppendStageStore {
    inner: Arc<MemoryKvStore>,
    stage: AppendFailureStage,
    fired: AtomicBool,
}

impl FailAfterAppendStageStore {
    fn should_fire(&self) -> bool {
        self.fired
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    fn injected(stage: AppendFailureStage) -> StorageError {
        StorageError::Internal(format!("injected single-append failure after {stage:?}"))
    }
}

#[async_trait]
impl KvStore for FailAfterAppendStageStore {
    fn supports_atomic_batch(&self) -> bool {
        false
    }

    async fn get(&self, namespace: &str, key: &str) -> StorageResult<Option<Vec<u8>>> {
        self.inner.get(namespace, key).await
    }

    async fn set(&self, namespace: &str, key: &str, value: Vec<u8>) -> StorageResult<()> {
        self.inner.set(namespace, key, value).await?;
        if matches!(self.stage, AppendFailureStage::Segment)
            && namespace == NS_SEGMENT_INDEX
            && self.should_fire()
        {
            return Err(Self::injected(self.stage));
        }
        Ok(())
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
        // Reject before the metadata write for the entry/head fault: all
        // earlier entry/head mutations have already completed.
        if matches!(self.stage, AppendFailureStage::EntryHead)
            && namespace == NS_CHAIN_METADATA
            && self.should_fire()
        {
            return Err(Self::injected(self.stage));
        }

        let swapped = self
            .inner
            .compare_and_swap(namespace, key, expected, new)
            .await?;
        if !swapped {
            return Ok(false);
        }

        let fail_after = match self.stage {
            AppendFailureStage::Metadata => namespace == NS_CHAIN_METADATA,
            AppendFailureStage::Global => namespace == NS_GLOBAL_METADATA && key == "current",
            AppendFailureStage::EntryHead | AppendFailureStage::Segment => false,
        };
        if fail_after && self.should_fire() {
            return Err(Self::injected(self.stage));
        }
        Ok(true)
    }

    async fn clear_namespace(&self, namespace: &str) -> StorageResult<u64> {
        self.inner.clear_namespace(namespace).await
    }
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
    let storage = KvAuditStorage::in_memory();
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
    let storage = KvAuditStorage::in_memory();
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
        let storage = KvAuditStorage {
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
            crate::AuditLog::with_test_storage(Box::new(KvAuditStorage { store }), keypair);
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
    let storage = Arc::new(KvAuditStorage {
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
        Box::new(KvAuditStorage {
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

#[expect(
    clippy::too_many_lines,
    reason = "the restart matrix keeps each durable stage assertion together"
)]
async fn assert_single_append_stage_reopens_canonical(
    stage: AppendFailureStage,
    setup_entries: usize,
) {
    let backing = Arc::new(MemoryKvStore::new());
    let keypair = Arc::new(KeyPair::generate());
    let session_id = SessionId::new();
    let setup = crate::AuditLog::with_test_storage(
        Box::new(KvAuditStorage {
            store: Arc::clone(&backing) as Arc<dyn KvStore>,
        }),
        Arc::clone(&keypair),
    );
    for index in 0..setup_entries {
        setup
            .append(
                session_id.clone(),
                AuditAction::ConfigReloaded,
                AuthorizationProof::System {
                    reason: format!("setup-{index}"),
                },
                AuditOutcome::success(),
            )
            .await
            .expect("setup append must succeed");
    }

    let fault_store: Arc<dyn KvStore> = Arc::new(FailAfterAppendStageStore {
        inner: Arc::clone(&backing),
        stage,
        fired: AtomicBool::new(false),
    });
    let failing = crate::AuditLog::with_test_storage(
        Box::new(KvAuditStorage {
            store: Arc::clone(&fault_store),
        }),
        Arc::clone(&keypair),
    );
    let failed = failing
        .append(
            session_id.clone(),
            AuditAction::ConfigReloaded,
            AuthorizationProof::System {
                reason: format!("fault-{stage:?}"),
            },
            AuditOutcome::success(),
        )
        .await;
    assert!(failed.is_err(), "fault stage {stage:?} must be observed");
    assert!(
        fault_store
            .get(NS_APPEND_INTENTS, "current")
            .await
            .unwrap()
            .is_some(),
        "stage {stage:?} must leave a durable append intent for recovery"
    );

    // A fresh log view models process restart.  It must recover the durable
    // successor (including any post-commit fault) before appending again.
    let reopened = crate::AuditLog::with_test_storage(
        Box::new(KvAuditStorage {
            store: Arc::clone(&fault_store),
        }),
        keypair,
    );
    let restarted = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        reopened.append(
            session_id.clone(),
            AuditAction::ConfigReloaded,
            AuthorizationProof::System {
                reason: "after-restart".into(),
            },
            AuditOutcome::success(),
        ),
    )
    .await
    .unwrap_or_else(|_| {
        panic!("restart append after {stage:?} did not complete; recovery must not spin")
    });
    restarted.unwrap_or_else(|error| panic!("restart append after {stage:?} failed: {error}"));

    let expected = setup_entries.saturating_add(2);
    let entries = reopened
        .get_session_entries(&session_id)
        .await
        .unwrap_or_else(|error| panic!("read entries after {stage:?}: {error}"));
    assert_eq!(
        entries.len(),
        expected,
        "stage {stage:?} must retain both durable appends"
    );
    let expected_bytes = entries
        .iter()
        .map(|entry| {
            serde_json::to_vec(entry)
                .expect("canonical entry encoding")
                .len()
        })
        .fold(0_u64, |total, len| {
            total.saturating_add(u64::try_from(len).unwrap_or(u64::MAX))
        });
    assert_eq!(
        reopened.count_session(&session_id).await.unwrap(),
        expected,
        "stage {stage:?} must retain exactly one failed append and one restart append"
    );
    let chain = reopened
        .chain_stats(&session_id, None)
        .await
        .unwrap()
        .expect("chain metadata after restart");
    assert_eq!(
        chain.count, expected as u64,
        "stage {stage:?} chain count must match durable entries"
    );
    let global = reopened.global_stats().await.unwrap();
    assert_eq!(
        global.total_count, expected as u64,
        "stage {stage:?} global accounting must match durable entries"
    );
    assert_eq!(
        global.total_bytes, expected_bytes,
        "stage {stage:?} global byte accounting must match canonical entries"
    );
    let expected_segments = if matches!(stage, AppendFailureStage::Segment) {
        2
    } else {
        1
    };
    let expected_sealed_segments = u64::from(matches!(stage, AppendFailureStage::Segment));
    assert_eq!(global.segments, expected_segments);
    assert_eq!(global.sealed_segments, expected_sealed_segments);
    assert_eq!(global.eligible_segments, expected_sealed_segments);
    assert!(
        fault_store
            .get(NS_APPEND_INTENTS, "current")
            .await
            .unwrap()
            .is_none(),
        "stage {stage:?} recovery must retire its append intent"
    );
    let verification = reopened.verify_chain(&session_id).await.unwrap();
    assert!(
        verification.valid,
        "stage {stage:?} restart recovery forked the chain: {:?}",
        verification.issues
    );
    assert_eq!(verification.entries_verified, expected);
}

#[tokio::test]
async fn append_failure_after_entry_and_head_reopens_canonical() {
    assert_single_append_stage_reopens_canonical(AppendFailureStage::EntryHead, 1).await;
}

#[tokio::test]
async fn append_failure_after_metadata_reopens_canonical() {
    assert_single_append_stage_reopens_canonical(AppendFailureStage::Metadata, 1).await;
}

#[tokio::test]
async fn append_failure_after_sealed_segment_reopens_canonical() {
    // The production segment threshold is 1,024 entries.  Seed exactly one
    // less so the faulted append durably seals and indexes that segment.
    assert_single_append_stage_reopens_canonical(
        AppendFailureStage::Segment,
        usize::try_from(DEFAULT_SEGMENT_MAX_ENTRIES).expect("platform supports segment threshold")
            - 1,
    )
    .await;
}

#[tokio::test]
async fn append_failure_after_global_accounting_reopens_canonical() {
    assert_single_append_stage_reopens_canonical(AppendFailureStage::Global, 1).await;
}

#[tokio::test]
async fn append_only_index_has_bounded_per_entry_records() {
    let storage = KvAuditStorage::in_memory();
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
    let storage = KvAuditStorage::in_memory();
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
    let storage = KvAuditStorage::in_memory();
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
    let storage = KvAuditStorage::in_memory();
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

#[tokio::test]
async fn get_chain_head_does_not_scan_session_entries() {
    let storage = KvAuditStorage::in_memory();
    let keypair = test_keypair();
    let session_id = SessionId::new();
    let mut last = None;
    for i in 0..32 {
        let previous = last
            .as_ref()
            .map_or_else(ContentHash::zero, AuditEntry::content_hash);
        let entry = AuditEntry::create(
            session_id.clone(),
            AuditAction::ConfigReloaded,
            AuthorizationProof::System {
                reason: format!("scan-{i}"),
            },
            AuditOutcome::success(),
            previous,
            &keypair,
        );
        storage.store(&entry).await.unwrap();
        last = Some(entry);
    }
    let expected = last.unwrap().id;
    let head = storage
        .get_chain_head(&session_id, None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(head, expected);
    assert!(
        !storage.is_entry_committed(&expected).await.unwrap(),
        "store() does not mint committed-entry seals; lookup must not session-scan to true"
    );
}

/// Exercises the `block_in_place` branch that only fires under a
/// multi-threaded runtime (the production path fixed by #305).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_store_and_retrieve_multi_thread() {
    let storage = KvAuditStorage::in_memory();
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
    let storage = std::sync::Arc::new(KvAuditStorage::in_memory());
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
