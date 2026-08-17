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
