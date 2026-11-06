//! Interrupt the real retirement authorization, not a parallel test journal.

use super::super::migration::{LegacyRetirementRecord, decode_receipt};
use super::*;
use crate::entry::{AuditAction, AuditOutcome, AuthorizationProof};
use astrid_storage::{KvStore, MemoryKvStore, StorageError, StorageResult};
use std::sync::atomic::{AtomicU8, Ordering};

struct InterruptedIntentStore {
    inner: Arc<dyn KvStore>,
    // 1 rejects Authorized publication; 2 publishes Authorized then loses ack.
    // 3 publishes Staged then loses ack (MOVE done, delete not started).
    // 4 rejects Completed publication (delete already finished).
    // 5 rejects Staged publication (MOVE done, delete cannot have started).
    interruption: AtomicU8,
}

impl Default for InterruptedIntentStore {
    fn default() -> Self {
        Self {
            inner: Arc::new(MemoryKvStore::new()),
            interruption: AtomicU8::new(0),
        }
    }
}

#[async_trait::async_trait]
impl KvStore for InterruptedIntentStore {
    async fn get(&self, namespace: &str, key: &str) -> StorageResult<Option<Vec<u8>>> {
        self.inner.get(namespace, key).await
    }

    async fn set(&self, namespace: &str, key: &str, value: Vec<u8>) -> StorageResult<()> {
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

    async fn clear_namespace(&self, namespace: &str) -> StorageResult<u64> {
        self.inner.clear_namespace(namespace).await
    }

    async fn close(&self) -> StorageResult<()> {
        self.inner.close().await
    }

    async fn compare_and_swap(
        &self,
        namespace: &str,
        key: &str,
        expected: Option<&[u8]>,
        new: Vec<u8>,
    ) -> StorageResult<bool> {
        let phase = retirement_cas_phase(&new);
        let wanted = self.interruption.load(Ordering::SeqCst);
        let matches = match wanted {
            1 | 2 => phase == RetirementCasPhase::Authorized,
            3 | 5 => phase == RetirementCasPhase::Staged,
            4 => phase == RetirementCasPhase::Completed,
            _ => false,
        };
        let interruption = if matches {
            self.interruption.swap(0, Ordering::SeqCst)
        } else {
            0
        };
        if matches!(interruption, 1 | 4 | 5) {
            return Err(StorageError::Internal(
                "injected before retirement intent".to_owned(),
            ));
        }
        let applied = self
            .inner
            .compare_and_swap(namespace, key, expected, new)
            .await?;
        if (interruption == 2 || interruption == 3) && applied {
            return Err(StorageError::Internal(
                "injected after retirement intent".to_owned(),
            ));
        }
        Ok(applied)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RetirementCasPhase {
    None,
    Authorized,
    Staged,
    Completed,
}

fn retirement_cas_phase(new: &[u8]) -> RetirementCasPhase {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(new) else {
        return RetirementCasPhase::None;
    };
    let Some(retirement) = value.get("retirement").filter(|value| !value.is_null()) else {
        return RetirementCasPhase::None;
    };
    if retirement.get("completed").is_some() {
        RetirementCasPhase::Completed
    } else if retirement.get("staged").is_some() {
        RetirementCasPhase::Staged
    } else {
        RetirementCasPhase::Authorized
    }
}

fn destination(store: &Arc<InterruptedIntentStore>, key: &Arc<KeyPair>) -> AuditLog {
    AuditLog::open_with_kv_store(store.clone(), Arc::clone(key)).unwrap()
}

fn retirement_phase(bytes: &[u8]) -> &'static str {
    match decode_receipt(bytes).unwrap().retirement {
        None => "none",
        Some(LegacyRetirementRecord::Authorized(_)) => "authorized",
        Some(LegacyRetirementRecord::Staged(_)) => "staged",
        Some(LegacyRetirementRecord::Completed(_)) => "completed",
    }
}

async fn marker_bytes(audit: &AuditLog) -> Vec<u8> {
    audit.storage.migration_marker().await.unwrap().unwrap()
}

#[tokio::test]
async fn retirement_requires_a_move_receipt_and_preserves_unverified_bytes() {
    let directory = super::super::legacy_test_directory::temporary().unwrap();
    let source = directory.path().join("source");
    std::fs::create_dir(&source).unwrap();
    std::fs::write(source.join("unverified"), b"preserve").unwrap();
    let audit = AuditLog::in_memory(KeyPair::generate());
    let error = audit
        .retire_legacy_audit(&source, directory.path().join("stage"), "test")
        .await
        .unwrap_err();
    assert!(error.to_string().contains("durable MOVE receipt"));
    assert_eq!(
        std::fs::read(source.join("unverified")).unwrap(),
        b"preserve"
    );
}

#[tokio::test]
async fn interrupted_intent_publication_preserves_source_and_retries_with_the_same_authority() {
    for interruption in [1, 2] {
        let directory = super::super::legacy_test_directory::temporary().unwrap();
        let source = directory.path().join("source");
        let stage = directory.path().join("stage");
        published_legacy_source(&source);
        let before = source_files(&source);
        let store = Arc::new(InterruptedIntentStore::default());
        let key = Arc::new(KeyPair::generate());
        let audit = destination(&store, &key);
        audit
            .import_legacy_audit(&source, "intent-retry")
            .await
            .unwrap();
        store.interruption.store(interruption, Ordering::SeqCst);
        let error = audit
            .retire_legacy_audit(&source, &stage, "intent-retry")
            .await
            .unwrap_err();
        assert!(error.to_string().contains("injected"));
        assert_eq!(store.interruption.load(Ordering::SeqCst), 0);
        assert_eq!(source_files(&source), before);
        assert!(!stage.exists());
        let before_retry = decode_receipt(&marker_bytes(&audit).await).unwrap();
        assert_eq!(before_retry.retirement.is_some(), interruption == 2);
        drop(audit);
        let audit = destination(&store, &key);
        audit
            .import_legacy_audit(&source, "intent-retry")
            .await
            .unwrap();
        let after_retry = decode_receipt(&marker_bytes(&audit).await).unwrap();
        assert_eq!(after_retry.retirement, before_retry.retirement);
        audit
            .retire_legacy_audit(&source, &stage, "intent-retry")
            .await
            .unwrap();
        assert!(!source.exists());
        assert!(std::fs::read_dir(&stage).unwrap().next().is_none());
        assert_eq!(retirement_phase(&marker_bytes(&audit).await), "completed");
        audit
            .retire_legacy_audit(&source, &stage, "intent-retry")
            .await
            .unwrap();
        assert_eq!(retirement_phase(&marker_bytes(&audit).await), "completed");
    }
}

#[cfg(unix)]
#[tokio::test]
async fn import_retry_cannot_reauthorize_a_same_payload_replacement() {
    let directory = super::super::legacy_test_directory::temporary().unwrap();
    let source = directory.path().join("source");
    let retained = directory.path().join("retained-original");
    let stage = directory.path().join("stage");
    published_legacy_source(&source);
    let before = source_files(&source);
    let store = Arc::new(InterruptedIntentStore::default());
    let key = Arc::new(KeyPair::generate());
    let audit = destination(&store, &key);
    audit
        .import_legacy_audit(&source, "identity-retry")
        .await
        .unwrap();
    store.interruption.store(2, Ordering::SeqCst);
    audit
        .retire_legacy_audit(&source, &stage, "identity-retry")
        .await
        .unwrap_err();
    std::fs::rename(&source, &retained).unwrap();
    published_legacy_source(&source);
    audit
        .import_legacy_audit(&source, "identity-retry")
        .await
        .unwrap();
    let error = audit
        .retire_legacy_audit(&source, &stage, "identity-retry")
        .await
        .unwrap_err();
    assert!(error.to_string().contains("identity conflicts"));
    assert_eq!(source_files(&source), before);
    assert_eq!(source_files(&retained), before);
    assert!(!stage.exists());
}

#[tokio::test]
async fn empty_authorized_present_retry_refuses_and_preserves_the_original() {
    let directory = super::super::legacy_test_directory::temporary().unwrap();
    let source = directory.path().join("source");
    let stage = directory.path().join("stage");
    std::fs::create_dir(&source).unwrap();
    let store = Arc::new(InterruptedIntentStore::default());
    let key = Arc::new(KeyPair::generate());
    let audit = destination(&store, &key);
    audit
        .import_legacy_audit(&source, "empty-refuse")
        .await
        .unwrap();
    store.interruption.store(2, Ordering::SeqCst);
    let error = audit
        .retire_legacy_audit(&source, &stage, "empty-refuse")
        .await
        .unwrap_err();
    assert!(error.to_string().contains("injected"));
    assert!(source.exists());
    assert_eq!(retirement_phase(&marker_bytes(&audit).await), "authorized");
    let error = audit
        .retire_legacy_audit(&source, &stage, "empty-refuse")
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("refusing to delete a present original")
    );
    assert!(source.exists());
    assert!(std::fs::read_dir(&source).unwrap().next().is_none());
    assert_eq!(retirement_phase(&marker_bytes(&audit).await), "authorized");
}

#[tokio::test]
async fn first_live_empty_source_retires_and_completes() {
    let directory = super::super::legacy_test_directory::temporary().unwrap();
    let source = directory.path().join("source");
    let stage = directory.path().join("stage");
    std::fs::create_dir(&source).unwrap();
    let audit =
        AuditLog::open_with_kv_store(Arc::new(MemoryKvStore::new()), KeyPair::generate()).unwrap();
    audit
        .import_legacy_audit(&source, "empty-complete")
        .await
        .unwrap();
    audit
        .retire_legacy_audit(&source, &stage, "empty-complete")
        .await
        .unwrap();
    assert!(!source.exists());
    assert_eq!(retirement_phase(&marker_bytes(&audit).await), "completed");
}

#[tokio::test]
async fn staged_durable_before_delete_preserves_a_restored_original() {
    let directory = super::super::legacy_test_directory::temporary().unwrap();
    let source = directory.path().join("source");
    let stage = directory.path().join("stage");
    published_legacy_source(&source);
    let store = Arc::new(InterruptedIntentStore::default());
    let key = Arc::new(KeyPair::generate());
    let audit = destination(&store, &key);
    audit
        .import_legacy_audit(&source, "staged-restore")
        .await
        .unwrap();
    store.interruption.store(3, Ordering::SeqCst);
    let error = audit
        .retire_legacy_audit(&source, &stage, "staged-restore")
        .await
        .unwrap_err();
    assert!(error.to_string().contains("injected"));
    assert!(!source.exists());
    assert_eq!(retirement_phase(&marker_bytes(&audit).await), "staged");
    published_legacy_source(&source);
    let restored = source_files(&source);
    let report = audit
        .import_legacy_audit(&source, "staged-restore")
        .await
        .unwrap();
    assert!(!report.marker_installed);
    assert_eq!(report.imported_entries, 0);
    audit
        .retire_legacy_audit(&source, &stage, "staged-restore")
        .await
        .unwrap();
    assert_eq!(source_files(&source), restored);
    assert_eq!(retirement_phase(&marker_bytes(&audit).await), "completed");
    assert!(std::fs::read_dir(&stage).unwrap().next().is_none());
}

#[tokio::test]
async fn completed_cas_failure_after_delete_preserves_a_restored_original() {
    let directory = super::super::legacy_test_directory::temporary().unwrap();
    let source = directory.path().join("source");
    let stage = directory.path().join("stage");
    published_legacy_source(&source);
    let store = Arc::new(InterruptedIntentStore::default());
    let key = Arc::new(KeyPair::generate());
    let audit = destination(&store, &key);
    audit
        .import_legacy_audit(&source, "completed-restore")
        .await
        .unwrap();
    store.interruption.store(4, Ordering::SeqCst);
    let error = audit
        .retire_legacy_audit(&source, &stage, "completed-restore")
        .await
        .unwrap_err();
    assert!(error.to_string().contains("injected"));
    assert!(!source.exists());
    assert_eq!(retirement_phase(&marker_bytes(&audit).await), "staged");
    published_legacy_source(&source);
    let restored = source_files(&source);
    audit
        .import_legacy_audit(&source, "completed-restore")
        .await
        .unwrap();
    audit
        .retire_legacy_audit(&source, &stage, "completed-restore")
        .await
        .unwrap();
    assert_eq!(source_files(&source), restored);
    assert_eq!(retirement_phase(&marker_bytes(&audit).await), "completed");
}

#[tokio::test]
async fn completed_retirement_preserves_a_later_same_payload_original() {
    let directory = super::super::legacy_test_directory::temporary().unwrap();
    let source = directory.path().join("source");
    let stage = directory.path().join("stage");
    published_legacy_source(&source);
    let audit =
        AuditLog::open_with_kv_store(Arc::new(MemoryKvStore::new()), KeyPair::generate()).unwrap();
    audit
        .import_legacy_audit(&source, "later-occupant")
        .await
        .unwrap();
    audit
        .retire_legacy_audit(&source, &stage, "later-occupant")
        .await
        .unwrap();
    assert!(!source.exists());
    assert_eq!(retirement_phase(&marker_bytes(&audit).await), "completed");
    published_legacy_source(&source);
    let restored = source_files(&source);
    let report = audit
        .import_legacy_audit(&source, "later-occupant")
        .await
        .unwrap();
    assert!(!report.marker_installed);
    assert_eq!(report.imported_entries, 0);
    audit
        .retire_legacy_audit(&source, &stage, "later-occupant")
        .await
        .unwrap();
    assert_eq!(source_files(&source), restored);
    assert_eq!(retirement_phase(&marker_bytes(&audit).await), "completed");
}

#[test]
fn retirement_record_keeps_raw_intent_as_authorized() {
    let authorized = serde_json::json!({
        "kind": "empty",
        "captured_root": {"platform": "unix", "volume": 1, "inode": 2}
    });
    let record: LegacyRetirementRecord = serde_json::from_value(authorized.clone()).unwrap();
    assert!(matches!(record, LegacyRetirementRecord::Authorized(_)));
    assert_eq!(serde_json::to_value(&record).unwrap(), authorized);

    let staged = serde_json::json!({ "staged": authorized });
    let record: LegacyRetirementRecord = serde_json::from_value(staged.clone()).unwrap();
    assert!(matches!(record, LegacyRetirementRecord::Staged(_)));
    assert_eq!(serde_json::to_value(&record).unwrap(), staged);

    let completed = serde_json::json!({ "completed": authorized });
    let record: LegacyRetirementRecord = serde_json::from_value(completed.clone()).unwrap();
    assert!(matches!(record, LegacyRetirementRecord::Completed(_)));
    assert_eq!(serde_json::to_value(&record).unwrap(), completed);

    let mixed = serde_json::json!({
        "staged": authorized,
        "completed": authorized
    });
    assert!(serde_json::from_value::<LegacyRetirementRecord>(mixed).is_err());
    let extra = serde_json::json!({ "staged": authorized, "extra": true });
    assert!(serde_json::from_value::<LegacyRetirementRecord>(extra).is_err());
}

async fn native_destination_store(
    home: &astrid_core::dirs::AstridHome,
) -> Arc<InterruptedIntentStore> {
    let kv =
        astrid_storage::open_runtime_kv(home, Arc::new(|_: &astrid_storage::StateOwner| Ok(None)))
            .await
            .unwrap();
    Arc::new(InterruptedIntentStore {
        inner: kv,
        interruption: AtomicU8::new(0),
    })
}

#[tokio::test]
async fn retirement_intent_survives_native_store_reopen_before_source_mutation() {
    let directory = super::super::legacy_test_directory::temporary().unwrap();
    let home = astrid_core::dirs::AstridHome::from_path(directory.path().join("native-home"));
    home.ensure().unwrap();
    let source = directory.path().join("source");
    let stage = directory.path().join("stage");
    published_legacy_source(&source);
    let before = source_files(&source);
    let key = Arc::new(KeyPair::generate());
    let store = native_destination_store(&home).await;
    let audit = destination(&store, &key);
    audit
        .import_legacy_audit(&source, "native-intent")
        .await
        .unwrap();
    store.interruption.store(2, Ordering::SeqCst);
    audit
        .retire_legacy_audit(&source, &stage, "native-intent")
        .await
        .unwrap_err();
    let authorized = marker_bytes(&audit).await;
    assert_eq!(retirement_phase(&authorized), "authorized");
    assert_eq!(source_files(&source), before);
    audit.close().await.unwrap();
    drop(audit);
    drop(store);

    let store = native_destination_store(&home).await;
    let audit = destination(&store, &key);
    assert_eq!(marker_bytes(&audit).await, authorized);
    audit
        .import_legacy_audit(&source, "native-intent")
        .await
        .unwrap();
    assert_eq!(marker_bytes(&audit).await, authorized);
    audit
        .retire_legacy_audit(&source, &stage, "native-intent")
        .await
        .unwrap();
    assert!(!source.exists());
    assert!(std::fs::read_dir(&stage).unwrap().next().is_none());
    let completed = marker_bytes(&audit).await;
    assert_eq!(retirement_phase(&completed), "completed");
    assert_ne!(completed, authorized);
    audit.close().await.unwrap();
    drop(audit);
    drop(store);

    let store = native_destination_store(&home).await;
    let audit = destination(&store, &key);
    published_legacy_source(&source);
    let restored = source_files(&source);
    let report = audit
        .import_legacy_audit(&source, "native-intent")
        .await
        .unwrap();
    assert!(!report.marker_installed);
    audit
        .retire_legacy_audit(&source, &stage, "native-intent")
        .await
        .unwrap();
    assert_eq!(source_files(&source), restored);
    assert_eq!(retirement_phase(&marker_bytes(&audit).await), "completed");
    audit.close().await.unwrap();
}

async fn append_native_entry(audit: &AuditLog) {
    audit
        .append(
            astrid_core::SessionId::new(),
            AuditAction::McpToolCall {
                server: "test".to_owned(),
                tool: "post-retire".to_owned(),
                args_hash: astrid_crypto::ContentHash::zero(),
            },
            AuthorizationProof::NotRequired {
                reason: "test".to_owned(),
            },
            AuditOutcome::success(),
        )
        .await
        .unwrap();
    audit.flush().await.unwrap();
}

#[tokio::test]
async fn public_import_of_absent_source_after_completed_retirement_allows_native_append() {
    let directory = super::super::legacy_test_directory::temporary().unwrap();
    let home = astrid_core::dirs::AstridHome::from_path(directory.path().join("native-home"));
    home.ensure().unwrap();
    let source = directory.path().join("source");
    let stage = directory.path().join("stage");
    published_legacy_source(&source);
    let key = Arc::new(KeyPair::generate());
    let store = native_destination_store(&home).await;
    let audit = destination(&store, &key);
    audit
        .import_legacy_audit(&source, "native-append-retry")
        .await
        .unwrap();
    audit
        .retire_legacy_audit(&source, &stage, "native-append-retry")
        .await
        .unwrap();
    assert!(!source.exists());
    assert_eq!(retirement_phase(&marker_bytes(&audit).await), "completed");
    append_native_entry(&audit).await;
    let report = audit
        .import_legacy_audit(&source, "native-append-retry")
        .await
        .unwrap();
    assert!(!report.marker_installed);
    assert_eq!(report.imported_entries, 0);
    audit.close().await.unwrap();
}

#[tokio::test]
async fn public_import_of_absent_source_with_authorized_receipt_still_requires_payload_proof() {
    let directory = super::super::legacy_test_directory::temporary().unwrap();
    let source = directory.path().join("source");
    let stage = directory.path().join("stage");
    published_legacy_source(&source);
    let store = Arc::new(InterruptedIntentStore::default());
    let key = Arc::new(KeyPair::generate());
    let audit = destination(&store, &key);
    audit
        .import_legacy_audit(&source, "authorized-append-proof")
        .await
        .unwrap();
    store.interruption.store(2, Ordering::SeqCst);
    audit
        .retire_legacy_audit(&source, &stage, "authorized-append-proof")
        .await
        .unwrap_err();
    assert_eq!(retirement_phase(&marker_bytes(&audit).await), "authorized");
    append_native_entry(&audit).await;
    std::fs::rename(&source, directory.path().join("retained")).unwrap();
    let error = audit
        .import_legacy_audit(&source, "authorized-append-proof")
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("does not match the stored migration receipt")
    );
}

#[tokio::test]
async fn authorized_missing_original_and_stage_cannot_claim_completion() {
    let directory = super::super::legacy_test_directory::temporary().unwrap();
    let source = directory.path().join("source");
    let retained = directory.path().join("retained-original");
    let stage = directory.path().join("stage");
    published_legacy_source(&source);
    let before = source_files(&source);
    let store = Arc::new(InterruptedIntentStore::default());
    let key = Arc::new(KeyPair::generate());
    let audit = destination(&store, &key);
    audit
        .import_legacy_audit(&source, "missing-stage")
        .await
        .unwrap();
    store.interruption.store(2, Ordering::SeqCst);
    audit
        .retire_legacy_audit(&source, &stage, "missing-stage")
        .await
        .unwrap_err();
    let authorized = marker_bytes(&audit).await;
    assert_eq!(retirement_phase(&authorized), "authorized");
    std::fs::rename(&source, &retained).unwrap();
    audit
        .retire_legacy_audit(&source, &stage, "missing-stage")
        .await
        .unwrap_err();
    assert_eq!(marker_bytes(&audit).await, authorized);
    assert!(!stage.exists());
    assert_eq!(source_files(&retained), before);
}

#[tokio::test]
async fn move_before_staged_publication_resumes_the_captured_intact_stage() {
    let directory = super::super::legacy_test_directory::temporary().unwrap();
    let source = directory.path().join("source");
    let stage = directory.path().join("stage");
    published_legacy_source(&source);
    let store = Arc::new(InterruptedIntentStore::default());
    let key = Arc::new(KeyPair::generate());
    let audit = destination(&store, &key);
    audit
        .import_legacy_audit(&source, "move-before-staged")
        .await
        .unwrap();
    store.interruption.store(5, Ordering::SeqCst);
    let error = audit
        .retire_legacy_audit(&source, &stage, "move-before-staged")
        .await
        .unwrap_err();
    assert!(error.to_string().contains("injected"));
    assert_eq!(store.interruption.load(Ordering::SeqCst), 0);
    assert!(!source.exists());
    assert_eq!(retirement_phase(&marker_bytes(&audit).await), "authorized");
    assert_eq!(std::fs::read_dir(&stage).unwrap().count(), 1);
    audit
        .retire_legacy_audit(&source, &stage, "move-before-staged")
        .await
        .unwrap();
    assert_eq!(retirement_phase(&marker_bytes(&audit).await), "completed");
    assert!(std::fs::read_dir(&stage).unwrap().next().is_none());
}
