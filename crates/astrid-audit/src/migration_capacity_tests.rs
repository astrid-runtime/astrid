use super::*;
use astrid_storage::{KvStore, MemoryKvStore};

struct FixedAuditCapacity(Option<u64>);

impl AuditCapacityProvider for FixedAuditCapacity {
    fn available_bytes(&self) -> AuditResult<Option<u64>> {
        Ok(self.0)
    }
}

async fn append_test_entries(log: &AuditLog, session_id: &SessionId, count: u32) {
    for i in 0..count {
        log.append(
            session_id.clone(),
            AuditAction::McpToolCall {
                server: "test".to_owned(),
                tool: format!("tool_{i}"),
                args_hash: ContentHash::zero(),
            },
            AuthorizationProof::NotRequired {
                reason: "test".to_owned(),
            },
            AuditOutcome::success(),
        )
        .await
        .expect("append test entry");
    }
}

#[tokio::test]
async fn empty_released_audit_database_has_canonical_zero_chain_receipt() {
    let directory = tempfile::tempdir().expect("temporary legacy directory");
    let path = directory.path().join("audit-db");
    let key = Arc::new(KeyPair::generate());
    AuditLog::open_legacy_source(&path, Arc::clone(&key))
        .expect("open empty legacy source")
        .close()
        .await
        .expect("close empty legacy source");

    let destination_backend: Arc<dyn KvStore> = Arc::new(astrid_storage::MemoryKvStore::new());
    let destination = AuditLog::open_with_kv_store_and_capacity(
        destination_backend,
        key,
        Some(Arc::new(FixedAuditCapacity(Some(u64::MAX)))),
    )
    .expect("open system destination");

    let report = destination
        .import_legacy_audit(&path, "test-system-audit")
        .await
        .expect("empty released audit migration");

    assert_eq!(report.source_entries, 0);
    assert_eq!(report.imported_entries, 0);
    assert!(report.marker_installed);
    assert!(destination.verify_all().await.unwrap().is_empty());
    destination
        .verify_legacy_source_digest(&path, "test-system-audit", &report.source_digest)
        .await
        .expect("source lock is released for the retirement read-back");
}

#[tokio::test]
async fn legacy_import_ignores_unusable_oversized_session_index() {
    let directory = tempfile::tempdir().expect("temporary legacy directory");
    let path = directory.path().join("audit-db");
    let key = Arc::new(KeyPair::generate());
    let session = SessionId::new();
    let source = AuditLog::open_legacy_source(&path, Arc::clone(&key)).expect("open legacy source");
    append_test_entries(&source, &session, 6).await;
    source.close().await.expect("close source");

    // Deliberately replace the old one-key session index with a large,
    // malformed value. A migration that deserializes that array would either
    // fail or allocate the entire legacy projection; streaming uses paged
    // `audit:entries` records and chain heads instead.
    let source_store =
        KvAuditStorage::open_legacy_source_writable(&path).expect("reopen source store");
    source_store
        .test_set_legacy_session_index(&session, vec![b'['; 4 * 1024 * 1024])
        .await
        .expect("write oversized legacy index fixture");
    source_store.close().await.expect("close source store");

    let destination_backend: Arc<dyn KvStore> = Arc::new(astrid_storage::MemoryKvStore::new());
    let destination = AuditLog::open_with_kv_store_and_capacity(
        destination_backend,
        key,
        Some(Arc::new(FixedAuditCapacity(Some(u64::MAX)))),
    )
    .expect("open system destination");
    let report = destination
        .import_legacy_audit(&path, "test-system-audit")
        .await
        .expect("streaming migration");
    assert_eq!(report.source_entries, 6);
    assert_eq!(report.imported_entries, 6);
    assert_eq!(destination.count_session(&session).await.unwrap(), 6);
    assert!(destination.verify_chain(&session).await.unwrap().valid);
}

#[test]
fn legacy_migration_capacity_estimate_has_exact_boundary() {
    let required = super::migration::estimated_migration_bytes(8_192, 4).unwrap();
    assert_eq!(required, 8_192 + 4 * 768 + 4 * 1024 * 1024);
    assert!(required.checked_sub(1).unwrap() < required);
}

#[tokio::test]
async fn oversized_prior_receipt_is_rejected_before_serde_allocation() {
    let destination = AuditLog::in_memory(KeyPair::generate());
    let fragment = r#"{"session":"00000000-0000-0000-0000-000000000000","principal":null,"count":1,"terminal_hash":"00"}"#;
    let mut chains = String::with_capacity(super::migration::MAX_LEGACY_RECEIPT_BYTES + 1);
    for index in 0..100_000 {
        if index != 0 {
            chains.push(',');
        }
        chains.push_str(fragment);
    }
    let marker = format!(
        "{{\"schema\":1,\"destination\":\"test-system-audit\",\"source_entries\":0,\"source_bytes\":0,\"source_digest\":\"\",\"chains\":[{chains}]}}"
    )
    .into_bytes();
    assert!(marker.len() > super::migration::MAX_LEGACY_RECEIPT_BYTES);
    destination
        .storage()
        .compare_and_swap_migration_marker(None, marker)
        .await
        .expect("install oversized prior marker");

    let directory = tempfile::tempdir().expect("temporary source directory");
    let error = destination
        .import_legacy_audit(directory.path().join("missing"), "test-system-audit")
        .await
        .expect_err("oversized marker must fail closed");
    assert!(error.to_string().contains("exceeds bounded size"));
}

#[cfg(unix)]
#[tokio::test]
async fn legacy_import_rejects_redirected_source_before_destination_mutation() {
    let directory = tempfile::tempdir().expect("temporary legacy directory");
    let real_source = directory.path().join("real-audit-db");
    std::fs::create_dir(&real_source).expect("real source directory");
    let redirected = directory.path().join("audit-db");
    std::os::unix::fs::symlink(&real_source, &redirected).expect("redirected source fixture");

    let destination_backend: Arc<dyn KvStore> = Arc::new(astrid_storage::MemoryKvStore::new());
    let destination =
        AuditLog::open_with_kv_store(Arc::clone(&destination_backend), KeyPair::generate())
            .expect("open destination");
    let error = destination
        .import_legacy_audit(&redirected, "test-system-audit")
        .await
        .expect_err("redirected source must fail before opening the legacy engine");
    assert!(error.to_string().contains("redirected"));
    assert!(
        destination_backend
            .list_keys("system:control:audit")
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn legacy_import_refuses_unobservable_capacity_before_destination_mutation() {
    let directory = tempfile::tempdir().expect("temporary legacy directory");
    let path = directory.path().join("audit-db");
    let key = Arc::new(KeyPair::generate());
    let session = SessionId::new();
    let source = AuditLog::open_legacy_source(&path, Arc::clone(&key)).expect("open legacy source");
    append_test_entries(&source, &session, 1).await;
    source.close().await.expect("close source");

    let destination_backend: Arc<dyn KvStore> = Arc::new(astrid_storage::MemoryKvStore::new());
    let destination = AuditLog::open_with_kv_store(Arc::clone(&destination_backend), key)
        .expect("open destination");
    let error = destination
        .import_legacy_audit(&path, "test-system-audit")
        .await
        .expect_err("unobservable capacity must fail closed");
    assert!(error.to_string().contains("capacity is unobservable"));
    assert!(
        destination_backend
            .list_keys("system:control:audit")
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn legacy_import_refuses_insufficient_capacity_before_destination_mutation() {
    let directory = tempfile::tempdir().expect("temporary legacy directory");
    let path = directory.path().join("audit-db");
    let key = Arc::new(KeyPair::generate());
    let session = SessionId::new();
    let source = AuditLog::open_legacy_source(&path, Arc::clone(&key)).expect("open legacy source");
    append_test_entries(&source, &session, 1).await;
    source.close().await.expect("close source");
    let source_store = KvAuditStorage::open_legacy_source(&path).expect("reopen source store");
    let source_receipt = super::migration::digest_legacy_source(&source_store, "test-system-audit")
        .await
        .expect("digest source");
    let required = super::migration::estimated_migration_bytes(
        source_receipt.source_bytes,
        source_receipt.source_entries,
    )
    .expect("estimate");
    source_store.close().await.expect("close source store");

    let destination_backend: Arc<dyn KvStore> = Arc::new(astrid_storage::MemoryKvStore::new());
    let destination = AuditLog::open_with_kv_store_and_capacity(
        Arc::clone(&destination_backend),
        key,
        Some(Arc::new(FixedAuditCapacity(Some(required - 1)))),
    )
    .expect("open destination");
    let error = destination
        .import_legacy_audit(&path, "test-system-audit")
        .await
        .expect_err("insufficient capacity must fail closed");
    assert!(
        error
            .to_string()
            .contains("insufficient destination capacity")
    );
    assert!(
        destination_backend
            .list_keys("system:control:audit")
            .await
            .unwrap()
            .is_empty()
    );
}

struct CountingKvStore {
    inner: MemoryKvStore,
    publishes: std::sync::atomic::AtomicU64,
}

impl CountingKvStore {
    fn new() -> Self {
        Self {
            inner: MemoryKvStore::new(),
            publishes: std::sync::atomic::AtomicU64::new(0),
        }
    }

    fn publishes(&self) -> u64 {
        self.publishes.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn record_publish(&self) {
        self.publishes
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

#[async_trait::async_trait]
impl KvStore for CountingKvStore {
    fn supports_atomic_batch(&self) -> bool {
        true
    }

    async fn get(
        &self,
        namespace: &str,
        key: &str,
    ) -> astrid_storage::StorageResult<Option<Vec<u8>>> {
        self.inner.get(namespace, key).await
    }

    async fn set(
        &self,
        namespace: &str,
        key: &str,
        value: Vec<u8>,
    ) -> astrid_storage::StorageResult<()> {
        self.inner.set(namespace, key, value).await
    }

    async fn delete(&self, namespace: &str, key: &str) -> astrid_storage::StorageResult<bool> {
        self.inner.delete(namespace, key).await
    }

    async fn exists(&self, namespace: &str, key: &str) -> astrid_storage::StorageResult<bool> {
        self.inner.exists(namespace, key).await
    }

    async fn list_keys(&self, namespace: &str) -> astrid_storage::StorageResult<Vec<String>> {
        self.inner.list_keys(namespace).await
    }

    async fn list_keys_with_prefix(
        &self,
        namespace: &str,
        prefix: &str,
    ) -> astrid_storage::StorageResult<Vec<String>> {
        self.inner.list_keys_with_prefix(namespace, prefix).await
    }

    async fn compare_and_swap(
        &self,
        namespace: &str,
        key: &str,
        expected: Option<&[u8]>,
        new: Vec<u8>,
    ) -> astrid_storage::StorageResult<bool> {
        self.record_publish();
        self.inner
            .compare_and_swap(namespace, key, expected, new)
            .await
    }

    async fn apply_batch(
        &self,
        batch: &astrid_storage::KvMutationBatch,
    ) -> astrid_storage::StorageResult<astrid_storage::KvBatchOutcome> {
        self.record_publish();
        self.inner.apply_batch(batch).await
    }

    async fn clear_namespace(&self, namespace: &str) -> astrid_storage::StorageResult<u64> {
        self.inner.clear_namespace(namespace).await
    }

    async fn clear_prefix(
        &self,
        namespace: &str,
        prefix: &str,
    ) -> astrid_storage::StorageResult<u64> {
        self.inner.clear_prefix(namespace, prefix).await
    }
}

#[tokio::test]
async fn legacy_move_batches_destination_publishes_by_page_not_entry() {
    const ENTRIES: u32 = 400;
    let directory = tempfile::tempdir().expect("temporary legacy directory");
    let path = directory.path().join("audit-db");
    let key = Arc::new(KeyPair::generate());
    let session = SessionId::new();
    let source = AuditLog::open_legacy_source(&path, Arc::clone(&key)).expect("open legacy source");
    append_test_entries(&source, &session, ENTRIES).await;
    source.close().await.expect("close source");

    let backend = Arc::new(CountingKvStore::new());
    let destination = AuditLog::open_with_kv_store_and_capacity(
        Arc::clone(&backend) as Arc<dyn KvStore>,
        Arc::clone(&key),
        Some(Arc::new(FixedAuditCapacity(Some(u64::MAX)))),
    )
    .expect("open destination");
    let report = destination
        .import_legacy_audit(&path, "test-system-audit")
        .await
        .expect("native bulk move");
    assert_eq!(report.source_entries, u64::from(ENTRIES));
    assert_eq!(report.imported_entries, u64::from(ENTRIES));
    assert_eq!(
        destination.count_session(&session).await.unwrap(),
        ENTRIES as usize
    );

    let pages = u64::from(ENTRIES).div_ceil(256);
    let publishes = backend.publishes();
    assert!(
        publishes <= pages.saturating_mul(8).saturating_add(16),
        "destination publishes {publishes} must stay O(pages) ({pages} pages), not O(entries)"
    );
    assert!(
        publishes < u64::from(ENTRIES) / 4,
        "destination publishes {publishes} scaled with entry count"
    );

    let smoke = destination
        .append(
            session.clone(),
            AuditAction::McpToolCall {
                server: "test".to_owned(),
                tool: "post-move".to_owned(),
                args_hash: ContentHash::zero(),
            },
            AuthorizationProof::NotRequired {
                reason: "test".to_owned(),
            },
            AuditOutcome::success(),
        )
        .await
        .expect("native append after move");
    let reopened = AuditLog::open_with_kv_store(Arc::clone(&backend) as Arc<dyn KvStore>, key)
        .expect("reopen destination");
    assert!(reopened.storage().get(&smoke).await.unwrap().is_some());
}

#[tokio::test]
async fn legacy_move_does_not_recertify_historical_signatures() {
    let directory = tempfile::tempdir().expect("temporary legacy directory");
    let path = directory.path().join("audit-db");
    let key = Arc::new(KeyPair::generate());
    let session = SessionId::new();
    let source = AuditLog::open_legacy_source(&path, Arc::clone(&key)).expect("open legacy source");
    append_test_entries(&source, &session, 2).await;
    source.close().await.expect("close source");

    let store = astrid_storage::SurrealKvStore::open(&path).expect("open source kv");
    let keys = store
        .list_keys("audit:entries")
        .await
        .expect("list source entries");
    let key_name = keys.first().cloned().expect("source entry");
    let raw = store
        .get("audit:entries", &key_name)
        .await
        .expect("load entry")
        .expect("entry bytes");
    let mut entry: AuditEntry = serde_json::from_slice(&raw).expect("decode entry");
    entry.signature = astrid_crypto::Signature::from_bytes([0x11; 64]);
    let rewritten = serde_json::to_vec(&entry).expect("encode entry");
    store
        .set("audit:entries", &key_name, rewritten)
        .await
        .expect("rewrite unsigned historical bytes");
    store.close().await.expect("close source kv");

    let destination_backend: Arc<dyn KvStore> = Arc::new(astrid_storage::MemoryKvStore::new());
    let destination = AuditLog::open_with_kv_store_and_capacity(
        destination_backend,
        key,
        Some(Arc::new(FixedAuditCapacity(Some(u64::MAX)))),
    )
    .expect("open destination");
    let report = destination
        .import_legacy_audit(&path, "test-system-audit")
        .await
        .expect("historical bytes move without signature recertification");
    assert_eq!(report.source_entries, 2);
    assert_eq!(report.imported_entries, 2);
    let page = destination
        .storage()
        .all_entries_page(None, 10)
        .await
        .expect("page dest entries without recertify");
    assert_eq!(page.len(), 2);
}

#[tokio::test]
async fn legacy_move_fails_closed_when_destination_cannot_reopen() {
    let directory = tempfile::tempdir().expect("temporary legacy directory");
    let path = directory.path().join("audit-db");
    let key = Arc::new(KeyPair::generate());
    let session = SessionId::new();
    let source = AuditLog::open_legacy_source(&path, Arc::clone(&key)).expect("open legacy source");
    append_test_entries(&source, &session, 2).await;
    source.close().await.expect("close source");

    let destination =
        AuditLog::in_memory(key).with_capacity_oracle(Arc::new(FixedAuditCapacity(Some(u64::MAX))));
    let error = destination
        .import_legacy_audit(&path, "test-system-audit")
        .await
        .expect_err("move must fail closed without a reopenable destination");
    assert!(error.to_string().contains("cannot be reopened"));
    assert_eq!(destination.count().await.unwrap(), 2);
}

#[tokio::test]
async fn legacy_move_refuses_nonempty_destination() {
    let directory = tempfile::tempdir().expect("temporary legacy directory");
    let path = directory.path().join("audit-db");
    let key = std::sync::Arc::new(astrid_crypto::KeyPair::generate());
    let session = SessionId::new();
    let source =
        AuditLog::open_legacy_source(&path, std::sync::Arc::clone(&key)).expect("open source");
    append_test_entries(&source, &session, 1).await;
    source.close().await.expect("close source");

    let destination_backend: std::sync::Arc<dyn KvStore> =
        std::sync::Arc::new(astrid_storage::MemoryKvStore::new());
    let destination = AuditLog::open_with_kv_store_and_capacity(
        std::sync::Arc::clone(&destination_backend),
        std::sync::Arc::clone(&key),
        Some(std::sync::Arc::new(FixedAuditCapacity(Some(u64::MAX)))),
    )
    .expect("open destination");
    append_test_entries(&destination, &session, 1).await;
    let error = destination
        .import_legacy_audit(&path, "test-system-audit")
        .await
        .expect_err("occupied destination must fail closed");
    assert!(error.to_string().contains("not empty"));
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "local frozen Surreal copy; set ASTRID_AUDIT_MOVE_SRC"]
async fn local_blind_move_onto_volume() {
    use astrid_core::dirs::AstridHome;
    use astrid_storage::{KvQuotaResolver, StateOwner, open_runtime_principal_store};
    use std::time::Instant;

    let source = std::env::var("ASTRID_AUDIT_MOVE_SRC").expect("ASTRID_AUDIT_MOVE_SRC");
    let dest_root = std::env::var("ASTRID_AUDIT_MOVE_DEST")
        .unwrap_or_else(|_| "/private/tmp/astrid-audit-blind-dest".to_owned());
    let _ = std::fs::remove_dir_all(&dest_root);
    std::fs::create_dir_all(&dest_root).expect("dest root");
    let home = AstridHome::from_path(&dest_root);
    home.ensure().expect("ensure throwaway home");

    let quota: std::sync::Arc<dyn KvQuotaResolver<StateOwner>> =
        std::sync::Arc::new(|owner: &StateOwner| {
            Ok(match owner {
                StateOwner::System => None,
                StateOwner::Principal(_) | StateOwner::Fleet(_) | StateOwner::User(_) => {
                    Some(u64::MAX)
                },
            })
        });
    let store = open_runtime_principal_store(&home, quota)
        .await
        .expect("open throwaway principal store");
    let audit_store = store
        .system_control_kv("audit")
        .expect("audit projection")
        .backend();
    let key = std::sync::Arc::new(KeyPair::generate());
    let destination = AuditLog::open_with_kv_store_and_capacity(
        audit_store,
        key,
        Some(std::sync::Arc::new(FixedAuditCapacity(Some(u64::MAX)))),
    )
    .expect("open dest audit");

    let started = Instant::now();
    let report = destination
        .import_legacy_audit(&source, "astrid-system-audit-v1")
        .await
        .expect("blind MOVE");
    let elapsed = started.elapsed();
    destination.flush().await.expect("flush dest");
    store.kv().close().await.expect("close store");

    let report_path = std::path::Path::new("/private/tmp/astrid-audit-blind-move-report.txt");
    let body = format!(
        "source={source}\n dest={dest_root}\n entries={}\n imported={}\n digest={}\n elapsed_ms={}\n",
        report.source_entries,
        report.imported_entries,
        report.source_digest,
        elapsed.as_millis()
    );
    std::fs::write(report_path, body).expect("write report");
    assert_eq!(report.source_entries, report.imported_entries);
    assert!(report.imported_entries > 0);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "reopen throwaway volume dest from local_blind_move_onto_volume"]
async fn local_blind_move_reopen_and_append() {
    use astrid_core::dirs::AstridHome;
    use astrid_storage::{KvQuotaResolver, StateOwner, open_runtime_principal_store};

    let dest_root = std::env::var("ASTRID_AUDIT_MOVE_DEST")
        .unwrap_or_else(|_| "/private/tmp/astrid-audit-blind-dest2".to_owned());
    let home = AstridHome::from_path(&dest_root);
    let quota: std::sync::Arc<dyn KvQuotaResolver<StateOwner>> =
        std::sync::Arc::new(|owner: &StateOwner| {
            Ok(match owner {
                StateOwner::System => None,
                StateOwner::Principal(_) | StateOwner::Fleet(_) | StateOwner::User(_) => {
                    Some(u64::MAX)
                },
            })
        });
    let store = open_runtime_principal_store(&home, quota)
        .await
        .expect("reopen throwaway principal store");
    let audit_store = store
        .system_control_kv("audit")
        .expect("audit projection")
        .backend();
    let key = std::sync::Arc::new(KeyPair::generate());
    let log = AuditLog::open_with_kv_store_and_capacity(
        std::sync::Arc::clone(&audit_store),
        std::sync::Arc::clone(&key),
        Some(std::sync::Arc::new(FixedAuditCapacity(Some(u64::MAX)))),
    )
    .expect("reopen dest audit");
    let before = log.count().await.expect("count after MOVE");
    assert_eq!(before, 250_282, "reopen must see the moved entries");
    let session = SessionId::new();
    let id = log
        .append(
            session.clone(),
            AuditAction::McpToolCall {
                server: "test".to_owned(),
                tool: "post-move".to_owned(),
                args_hash: ContentHash::zero(),
            },
            AuthorizationProof::NotRequired {
                reason: "post-move".to_owned(),
            },
            AuditOutcome::success(),
        )
        .await
        .expect("append after MOVE");
    log.flush().await.expect("flush append");
    let after = log.count().await.expect("count after append");
    assert_eq!(after, before + 1);
    drop(log);
    let reopened = AuditLog::open_with_kv_store(audit_store, key).expect("second reopen");
    assert_eq!(reopened.count().await.expect("reopen count"), after);
    assert!(
        reopened
            .storage()
            .get(&id)
            .await
            .expect("load appended")
            .is_some()
    );
    store.kv().close().await.expect("close store");
}

#[tokio::test]
async fn legacy_move_source_rejects_writes() {
    let directory = tempfile::tempdir().expect("temporary legacy directory");
    let path = directory.path().join("audit-db");
    let key = std::sync::Arc::new(KeyPair::generate());
    let session = SessionId::new();
    let writable = AuditLog::open_legacy_source(&path, std::sync::Arc::clone(&key)).expect("seed");
    append_test_entries(&writable, &session, 1).await;
    writable.close().await.expect("close seed");

    let frozen = KvAuditStorage::open_legacy_source(&path).expect("frozen source");
    let error = frozen
        .kv_store()
        .set("audit:entries", "nope", b"x".to_vec())
        .await
        .expect_err("frozen source must refuse writes");
    assert!(error.to_string().contains("frozen"));
}
