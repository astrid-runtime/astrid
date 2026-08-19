use super::*;
use astrid_storage::KvStore;

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
    let source_store = KvAuditStorage::open_legacy_source(&path).expect("reopen source store");
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
