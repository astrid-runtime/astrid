use super::*;

async fn append_entries(log: &AuditLog, session: &SessionId, count: u32) {
    for index in 0..count {
        log.append(
            session.clone(),
            AuditAction::McpToolCall {
                server: "test".to_owned(),
                tool: format!("tool_{index}"),
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
async fn bounded_prune_writes_signed_anchor_and_reopens_chain() {
    let key = Arc::new(KeyPair::generate());
    let log = AuditLog::in_memory(key);
    let session = SessionId::new();
    append_entries(&log, &session, 8).await;
    let global = log.global_stats().await.expect("global audit stats");
    assert_eq!(global.total_count, 8);
    assert!(!global.degraded);

    let receipt = log
        .prune_chain(
            &session,
            None,
            AuditRetentionPolicy {
                retain_entries: 3,
                retain_bytes: None,
            },
        )
        .await
        .expect("bounded prune");
    assert_eq!(receipt.retained_count, 3);
    assert_eq!(receipt.omitted_count, 5);
    assert!(receipt.signature.as_bytes().iter().any(|byte| *byte != 0));
    let stats = log
        .chain_stats(&session, None)
        .await
        .unwrap()
        .expect("metadata after prune");
    assert_eq!(stats.count, 3);
    assert_eq!(log.global_stats().await.unwrap().total_count, 3);
    assert!(log.verify_chain(&session).await.unwrap().valid);

    let next = log
        .prune_chain(
            &session,
            None,
            AuditRetentionPolicy {
                retain_entries: 2,
                retain_bytes: None,
            },
        )
        .await
        .expect("second bounded prune");
    assert_eq!(next.generation, receipt.generation + 1);
    let encoded = serde_json::to_vec(&receipt).unwrap();
    assert_eq!(
        next.prior_receipt_hash,
        Some(blake3::hash(&encoded).to_hex().to_string())
    );
    assert!(log.verify_chain(&session).await.unwrap().valid);
}

#[tokio::test]
async fn automatic_sealing_resets_segment_local_counters() {
    let log = AuditLog::in_memory(KeyPair::generate());
    let session = SessionId::new();
    append_entries(&log, &session, 2_049).await;
    let stats = log
        .chain_stats(&session, None)
        .await
        .unwrap()
        .expect("chain metadata");
    assert_eq!(stats.count, 2_049);
    assert_eq!(stats.segment, 2);
    assert_eq!(stats.segment_count, 1);
    assert!(!stats.sealed);
    let global = log.global_stats().await.unwrap();
    assert_eq!(global.sealed_segments, 2);
    assert_eq!(global.segments, 3);
    assert!(global.eligible_segments >= 2);
}

#[tokio::test]
async fn prune_oldest_removes_one_global_segment_and_keeps_active_tail() {
    let log = AuditLog::in_memory(KeyPair::generate());
    let session = SessionId::new();
    append_entries(&log, &session, 2_049).await;

    let receipt = log
        .prune_oldest(AuditRetentionPolicy {
            retain_entries: 1,
            retain_bytes: None,
        })
        .await
        .expect("oldest sealed segment prune")
        .expect("sealed segment exists");
    assert_eq!(receipt.omitted_count, 1_024);
    assert_eq!(receipt.retained_count, 1_025);
    assert_eq!(omitted(&log, &session).await, (1_025, Some(1_024), Some(0)));
    let stats = log.global_stats().await.unwrap();
    assert_eq!(stats.total_count, 1_025);
    assert_eq!(stats.sealed_segments, 1);
    assert_eq!(stats.segments, 2);
    assert!(log.verify_chain(&session).await.unwrap().valid);
}

#[tokio::test]
async fn append_auto_prunes_oldest_segment_at_global_cap() {
    let log = AuditLog::in_memory(KeyPair::generate());
    log.set_global_retention_caps(1_500, 64 * 1024 * 1024)
        .await
        .unwrap();
    let session = SessionId::new();
    append_entries(&log, &session, 2_049).await;
    let stats = log.global_stats().await.unwrap();
    assert!(stats.total_count <= 1_500);
    assert!(!stats.degraded);
    assert!(log.verify_chain(&session).await.unwrap().valid);
}

fn retain(entries: usize) -> AuditRetentionPolicy {
    AuditRetentionPolicy {
        retain_entries: entries,
        retain_bytes: None,
    }
}

/// `(count, omitted_total, omitted_generation)` of a session's system chain.
async fn omitted(log: &AuditLog, session: &SessionId) -> (u64, Option<u64>, Option<u64>) {
    let metadata = log
        .storage()
        .chain_metadata(session, None)
        .await
        .unwrap()
        .expect("chain metadata");
    (
        metadata.count,
        metadata.omitted_total,
        metadata.omitted_generation,
    )
}

#[tokio::test]
async fn prune_counts_omitted_entries_across_generations_and_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit-db");
    let key = Arc::new(KeyPair::generate());
    let session = SessionId::new();

    let store = Arc::new(astrid_storage::SurrealKvStore::open(&path).unwrap());
    let log = AuditLog::open_with_kv_store(store.clone(), Arc::clone(&key)).unwrap();
    append_entries(&log, &session, 10).await;
    assert_eq!(omitted(&log, &session).await, (10, None, None));
    log.prune_chain(&session, None, retain(6)).await.unwrap();
    assert_eq!(omitted(&log, &session).await, (6, Some(4), Some(0)));
    log.prune_chain(&session, None, retain(4)).await.unwrap();
    append_entries(&log, &session, 3).await;
    assert_eq!(omitted(&log, &session).await, (7, Some(6), Some(1)));
    drop(log);
    store.close().await.unwrap();
    drop(store);

    let store = Arc::new(astrid_storage::SurrealKvStore::open(&path).unwrap());
    let log = AuditLog::open_with_kv_store(store.clone(), key).unwrap();
    assert_eq!(omitted(&log, &session).await, (7, Some(6), Some(1)));
    log.prune_chain(&session, None, retain(2)).await.unwrap();
    assert_eq!(omitted(&log, &session).await, (2, Some(11), Some(2)));
    drop(log);
    store.close().await.unwrap();
}

#[tokio::test]
async fn prune_counts_from_the_receipt_when_metadata_predates_the_counter() {
    let log = AuditLog::in_memory(KeyPair::generate());
    let once = SessionId::new();
    let twice = SessionId::new();
    append_entries(&log, &once, 8).await;
    append_entries(&log, &twice, 8).await;
    log.prune_chain(&once, None, retain(3)).await.unwrap();
    log.prune_chain(&twice, None, retain(5)).await.unwrap();
    log.prune_chain(&twice, None, retain(3)).await.unwrap();
    let storage = log.storage().as_kv_audit_storage().unwrap();
    for session in [&once, &twice] {
        storage
            .test_forget_omitted_total(session, None)
            .await
            .unwrap();
    }

    // The installed generation-0 receipt holds the whole earlier total.
    log.prune_chain(&once, None, retain(2)).await.unwrap();
    assert_eq!(omitted(&log, &once).await, (2, Some(6), Some(1)));

    // Generation 0's count was replaced by generation 1's receipt, so the
    // total is recorded as unknown and stays unknown.
    log.prune_chain(&twice, None, retain(2)).await.unwrap();
    append_entries(&log, &twice, 1).await;
    assert_eq!(omitted(&log, &twice).await, (3, Some(u64::MAX), Some(2)));
}

#[tokio::test]
async fn resumed_prune_finalization_counts_its_receipt_once() {
    let log = AuditLog::in_memory(KeyPair::generate());
    let session = SessionId::new();
    append_entries(&log, &session, 8).await;
    let receipt = log.prune_chain(&session, None, retain(3)).await.unwrap();
    assert_eq!(omitted(&log, &session).await, (3, Some(5), Some(0)));

    // The process died after installing the receipt but before removing
    // the finished plan; the next prune call finalizes that plan again.
    let encoded = serde_json::to_vec(&receipt).unwrap();
    let storage = log.storage().as_kv_audit_storage().unwrap();
    storage
        .test_stage_finished_prune_plan(&session, None, encoded.clone())
        .await
        .unwrap();
    log.storage()
        .prune_chain(&session, None, 3, encoded)
        .await
        .unwrap();
    assert_eq!(omitted(&log, &session).await, (3, Some(5), Some(0)));
}
