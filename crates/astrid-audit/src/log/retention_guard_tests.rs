use astrid_core::{PrincipalId, SessionId};
use astrid_crypto::{ContentHash, KeyPair};

use crate::entry::{AuditAction, AuditOutcome, AuthorizationProof};
use crate::error::AuditError;
use crate::log::{AuditLog, AuditRetentionPolicy};

async fn append(log: &AuditLog, session: &SessionId, count: u32) {
    for index in 0..count {
        log.append(
            session.clone(),
            AuditAction::McpToolCall {
                server: "retention".to_owned(),
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

fn retain(entries: usize) -> AuditRetentionPolicy {
    AuditRetentionPolicy {
        retain_entries: entries,
        retain_bytes: None,
    }
}

/// Mark a system chain anchored through `position` entries.
async fn mark(log: &AuditLog, session: &SessionId, position: u64) {
    let stats = log.chain_stats(session, None).await.unwrap().unwrap();
    let omitted = log
        .storage()
        .chain_metadata(session, None)
        .await
        .unwrap()
        .and_then(|metadata| metadata.omitted_total)
        .unwrap_or(0);
    let index = position.saturating_sub(1).saturating_sub(omitted);
    let entries = log
        .chain_entries_page(session, None, None, 10_000)
        .await
        .unwrap();
    assert!(u64::try_from(entries.len()).unwrap() == stats.count);
    let hash = entries[usize::try_from(index).unwrap()].1.content_hash();
    log.mark_anchored(session, None, position, hash, serde_json::json!({}))
        .await
        .expect("mark anchored");
}

fn refusal(result: Result<impl std::fmt::Debug, AuditError>) -> String {
    match result {
        Err(AuditError::UnanchoredPrune(reason)) => reason,
        other => panic!("expected an unanchored-prune refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn prune_never_removes_entries_past_the_watermark() {
    let log = AuditLog::in_memory(KeyPair::generate());
    let session = SessionId::new();
    append(&log, &session, 10).await;
    mark(&log, &session, 5).await;

    let reason = refusal(log.prune_chain(&session, None, retain(3)).await);
    assert!(
        reason.contains("anchored through its first 5 entries")
            && reason.contains("would remove its first 7"),
        "{reason}"
    );
    // Nothing was deleted and no receipt was written.
    assert_eq!(
        log.chain_stats(&session, None)
            .await
            .unwrap()
            .unwrap()
            .count,
        10
    );
    assert!(log.prune_state(&session, None).await.unwrap().is_none());

    let receipt = log.prune_chain(&session, None, retain(5)).await.unwrap();
    assert_eq!(receipt.omitted_count, 5);
    // The watermark is now the pruned boundary: nothing more can go.
    refusal(log.prune_chain(&session, None, retain(4)).await);
    assert!(log.verify_chain(&session).await.unwrap().valid);

    mark(&log, &session, 8).await;
    let next = log.prune_chain(&session, None, retain(2)).await.unwrap();
    assert_eq!(next.omitted_count, 3);
}

#[tokio::test]
async fn prune_requires_a_watermark_only_when_configured() {
    let log = AuditLog::in_memory(KeyPair::generate());
    let unmarked = SessionId::new();
    append(&log, &unmarked, 6).await;
    assert!(!log.require_anchor_before_prune());

    log.set_require_anchor_before_prune(true);
    let reason = refusal(log.prune_chain(&unmarked, None, retain(2)).await);
    assert!(reason.contains("has no anchored watermark"), "{reason}");
    // A prune that removes nothing needs no watermark.
    log.prune_chain(&unmarked, None, retain(6)).await.unwrap();

    mark(&log, &unmarked, 3).await;
    assert_eq!(
        log.prune_chain(&unmarked, None, retain(3))
            .await
            .unwrap()
            .omitted_count,
        3
    );

    log.set_require_anchor_before_prune(false);
    let other = SessionId::new();
    append(&log, &other, 6).await;
    assert_eq!(
        log.prune_chain(&other, None, retain(2))
            .await
            .unwrap()
            .omitted_count,
        4
    );
}

#[tokio::test]
async fn prune_oldest_skips_segments_that_are_not_anchored() {
    let log = AuditLog::in_memory(KeyPair::generate());
    log.set_require_anchor_before_prune(true);
    let first = SessionId::new();
    let second = SessionId::new();
    // Each chain seals one 1,024-entry segment; `first` seals first.
    append(&log, &first, 1_025).await;
    append(&log, &second, 1_025).await;

    let reason = refusal(log.prune_oldest(retain(1)).await);
    assert!(reason.contains(&first.0.to_string()), "{reason}");

    mark(&log, &second, 1_025).await;
    let receipt = log.prune_oldest(retain(1)).await.unwrap().unwrap();
    assert_eq!(receipt.session, second.to_string());
    assert_eq!(receipt.omitted_count, 1_024);
    assert_eq!(
        log.chain_stats(&first, None).await.unwrap().unwrap().count,
        1_025
    );
}

#[tokio::test]
async fn global_cap_keeps_unanchored_entries_and_alarms() {
    let log = AuditLog::in_memory(KeyPair::generate());
    log.set_global_retention_caps(1_500, 64 * 1024 * 1024)
        .await
        .unwrap();
    let session = SessionId::new();
    append(&log, &session, 10).await;
    // A watermark behind the first sealed segment blocks its prune.
    mark(&log, &session, 10).await;
    append(&log, &session, 2_039).await;

    let stats = log.global_stats().await.unwrap();
    assert_eq!(stats.total_count, 2_049, "every append was kept");
    assert!(stats.degraded);
    let hold = stats.retention_hold.expect("retention hold is set");
    assert!(hold.contains("unanchored"), "{hold}");
    assert_eq!(stats.last_error.as_deref(), Some(hold.as_str()));
    assert!(log.verify_chain(&session).await.unwrap().valid);

    // Anchoring the chain clears the hold; the next append prunes.
    mark(&log, &session, 2_049).await;
    assert!(log.global_stats().await.unwrap().retention_hold.is_none());
    append(&log, &session, 1).await;
    let stats = log.global_stats().await.unwrap();
    assert!(stats.total_count <= 1_500, "{stats:?}");
    assert!(!stats.degraded);
    assert!(stats.retention_hold.is_none());
    assert!(log.verify_chain(&session).await.unwrap().valid);
}

#[tokio::test]
async fn global_cap_prunes_chains_without_a_watermark_by_default() {
    let log = AuditLog::in_memory(KeyPair::generate());
    log.set_global_retention_caps(1_500, 64 * 1024 * 1024)
        .await
        .unwrap();
    let session = SessionId::new();
    append(&log, &session, 2_049).await;
    let stats = log.global_stats().await.unwrap();
    assert!(stats.total_count <= 1_500);
    assert!(stats.retention_hold.is_none());
    assert!(!stats.degraded);
}

#[tokio::test]
async fn principal_chain_watermark_limits_only_that_chain() {
    let log = AuditLog::in_memory(KeyPair::generate());
    let session = SessionId::new();
    let alice = PrincipalId::new("alice").unwrap();
    for _ in 0..6 {
        log.append_with_principal(
            session.clone(),
            alice.clone(),
            AuditAction::ConfigReloaded,
            AuthorizationProof::System {
                reason: "test".to_owned(),
            },
            AuditOutcome::success(),
        )
        .await
        .unwrap();
    }
    append(&log, &session, 6).await;
    let alice_second = log
        .chain_entries_page(&session, Some(&alice), None, 10)
        .await
        .unwrap()[1]
        .1
        .content_hash();
    log.mark_anchored(
        &session,
        Some(&alice),
        2,
        alice_second,
        serde_json::json!({}),
    )
    .await
    .unwrap();

    refusal(log.prune_chain(&session, Some(&alice), retain(3)).await);
    assert_eq!(
        log.prune_chain(&session, None, retain(1))
            .await
            .unwrap()
            .omitted_count,
        5
    );
}
