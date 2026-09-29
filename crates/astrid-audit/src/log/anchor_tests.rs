use std::sync::Arc;

use astrid_core::{PrincipalId, SessionId};
use astrid_crypto::{ContentHash, KeyPair};
use async_trait::async_trait;
use tokio::sync::Notify;

use crate::entry::{AuditAction, AuditEntry, AuditOutcome, AuthorizationProof};
use crate::error::{AuditError, AuditResult};
use crate::log::{
    AuditArchiveWriter, AuditArchiver, AuditLog, AuditPruneReceipt, AuditRetentionPolicy,
};

async fn append(log: &AuditLog, session: &SessionId, principal: Option<&str>, count: u32) {
    for index in 0..count {
        let action = AuditAction::McpToolCall {
            server: "anchor".to_owned(),
            tool: format!("tool_{index}"),
            args_hash: ContentHash::zero(),
        };
        let proof = AuthorizationProof::NotRequired {
            reason: "test".to_owned(),
        };
        let result = match principal {
            Some(alias) => {
                log.append_with_principal(
                    session.clone(),
                    PrincipalId::new(alias).unwrap(),
                    action,
                    proof,
                    AuditOutcome::success(),
                )
                .await
            },
            None => {
                log.append(session.clone(), action, proof, AuditOutcome::success())
                    .await
            },
        };
        result.expect("append test entry");
    }
}

/// Content hashes of a chain's retained entries, oldest first.
async fn retained_hashes(log: &AuditLog, session: &SessionId) -> Vec<ContentHash> {
    log.chain_entries_page(session, None, None, 10_000)
        .await
        .unwrap()
        .into_iter()
        .map(|(_, entry)| entry.content_hash())
        .collect()
}

fn evidence(link: u64) -> serde_json::Value {
    serde_json::json!({ "network": "test", "checkpoint_digest_hex": "00", "link_position": link })
}

fn rejected(result: Result<impl std::fmt::Debug, AuditError>, needle: &str) {
    match result {
        Err(AuditError::AnchorRejected(reason)) => {
            assert!(reason.contains(needle), "{reason:?} lacks {needle:?}");
        },
        other => panic!("expected a rejection containing {needle:?}, got {other:?}"),
    }
}

#[tokio::test]
async fn mark_anchored_checks_the_head_hash_and_never_lowers_the_watermark() {
    let log = AuditLog::in_memory(KeyPair::generate());
    let session = SessionId::new();
    append(&log, &session, None, 10).await;
    let hashes = retained_hashes(&log, &session).await;

    let first = log
        .mark_anchored(&session, None, 6, hashes[5], evidence(1))
        .await
        .unwrap();
    assert!(first.advanced);
    assert_eq!(first.watermark.position, 6);
    assert_eq!(first.watermark.evidence, evidence(1));

    // The same mark again is accepted without change; the evidence of the
    // first mark is kept.
    let again = log
        .mark_anchored(&session, None, 6, hashes[5], evidence(2))
        .await
        .unwrap();
    assert!(!again.advanced);
    assert_eq!(again.watermark.evidence, evidence(1));

    rejected(
        log.mark_anchored(&session, None, 4, hashes[3], evidence(3))
            .await,
        "below the anchored watermark 6",
    );
    rejected(
        log.mark_anchored(&session, None, 6, hashes[4], evidence(3))
            .await,
        "differs from the hash anchored",
    );
    rejected(
        log.mark_anchored(&session, None, 8, hashes[8], evidence(3))
            .await,
        "does not match the entry at position 7",
    );
    rejected(
        log.mark_anchored(&session, None, 11, hashes[9], evidence(3))
            .await,
        "past the chain head at position 10",
    );
    rejected(
        log.mark_anchored(&session, None, 0, ContentHash::zero(), evidence(3))
            .await,
        "anchors no entries",
    );
    rejected(
        log.mark_anchored(&SessionId::new(), None, 1, hashes[0], evidence(3))
            .await,
        "no such audit chain",
    );
    rejected(
        log.mark_anchored(&session, None, 7, hashes[6], serde_json::json!("text"))
            .await,
        "must be a JSON object",
    );
    let oversized = serde_json::json!({ "padding": "x".repeat(5_000) });
    rejected(
        log.mark_anchored(&session, None, 7, hashes[6], oversized)
            .await,
        "above the 4096-byte limit",
    );

    // Verification continues from the recorded watermark.
    let head = log
        .mark_anchored(&session, None, 10, hashes[9], evidence(4))
        .await
        .unwrap();
    assert!(head.advanced);
    let stored = log.anchor_watermark(&session, None).await.unwrap().unwrap();
    assert_eq!(stored.position, 10);
    assert_eq!(stored.head_hash, hashes[9]);
    assert_eq!(stored.evidence, evidence(4));
}

#[tokio::test]
async fn mark_anchored_counts_positions_from_genesis_across_prunes() {
    let log = AuditLog::in_memory(KeyPair::generate());
    let session = SessionId::new();
    append(&log, &session, None, 10).await;
    let receipt = log
        .prune_chain(
            &session,
            None,
            AuditRetentionPolicy {
                retain_entries: 4,
                retain_bytes: None,
            },
        )
        .await
        .unwrap();
    append(&log, &session, None, 2).await;
    let retained = retained_hashes(&log, &session).await;
    assert_eq!(retained.len(), 6);

    rejected(
        log.mark_anchored(&session, None, 5, retained[0], evidence(1))
            .await,
        "inside pruned history",
    );
    // Position 6 is the pruned boundary; the receipt holds its hash.
    let terminal = ContentHash::from_hex(&receipt.omitted_terminal_hash).unwrap();
    let boundary = log
        .mark_anchored(&session, None, 6, terminal, evidence(1))
        .await
        .unwrap();
    assert!(boundary.advanced);
    // Retained index 1 is position 7; the next mark reads on from the
    // boundary's cursor.
    let later = log
        .mark_anchored(&session, None, 8, retained[1], evidence(2))
        .await
        .unwrap();
    assert!(later.advanced);
    rejected(
        log.mark_anchored(&session, None, 12, retained[4], evidence(3))
            .await,
        "does not match the entry at position 11",
    );
    let head = log
        .mark_anchored(&session, None, 12, retained[5], evidence(3))
        .await
        .unwrap();
    assert_eq!(head.watermark.position, 12);
}

#[tokio::test]
async fn watermarks_are_per_chain() {
    let log = AuditLog::in_memory(KeyPair::generate());
    let session = SessionId::new();
    append(&log, &session, None, 3).await;
    append(&log, &session, Some("alice"), 5).await;
    let alice = PrincipalId::new("alice").unwrap();
    let alice_hashes: Vec<_> = log
        .chain_entries_page(&session, Some(&alice), None, 100)
        .await
        .unwrap()
        .into_iter()
        .map(|(_, entry)| entry.content_hash())
        .collect();
    log.mark_anchored(&session, Some(&alice), 5, alice_hashes[4], evidence(1))
        .await
        .unwrap();
    assert!(
        log.anchor_watermark(&session, None)
            .await
            .unwrap()
            .is_none()
    );

    let status = log.anchor_status().await.unwrap();
    assert_eq!(status.len(), 2);
    for chain in status {
        let expected = chain.principal.as_ref().map(|_| 5);
        assert_eq!(
            chain.watermark.map(|mark| mark.position),
            expected,
            "{:?}",
            chain.principal
        );
        assert_eq!(chain.omitted_total, Some(0));
    }
}

#[tokio::test]
async fn watermarks_survive_reopening_the_store() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit-db");
    let key = Arc::new(KeyPair::generate());
    let session = SessionId::new();

    let store = Arc::new(astrid_storage::SurrealKvStore::open(&path).unwrap());
    let log = AuditLog::open_with_kv_store(store.clone(), Arc::clone(&key)).unwrap();
    append(&log, &session, None, 6).await;
    let hashes = retained_hashes(&log, &session).await;
    log.mark_anchored(&session, None, 4, hashes[3], evidence(9))
        .await
        .unwrap();
    drop(log);
    store.close().await.unwrap();
    drop(store);

    let store = Arc::new(astrid_storage::SurrealKvStore::open(&path).unwrap());
    let log = AuditLog::open_with_kv_store(store.clone(), key).unwrap();
    let stored = log.anchor_watermark(&session, None).await.unwrap().unwrap();
    assert_eq!((stored.position, stored.head_hash), (4, hashes[3]));
    assert_eq!(stored.evidence, evidence(9));
    rejected(
        log.mark_anchored(&session, None, 3, hashes[2], evidence(10))
            .await,
        "below the anchored watermark",
    );
    // The reopened log still refuses to prune past the watermark.
    let refused = log
        .prune_chain(
            &session,
            None,
            AuditRetentionPolicy {
                retain_entries: 1,
                retain_bytes: None,
            },
        )
        .await;
    assert!(
        matches!(refused, Err(AuditError::UnanchoredPrune(_))),
        "{refused:?}"
    );
    assert!(
        log.mark_anchored(&session, None, 6, hashes[5], evidence(11))
            .await
            .unwrap()
            .advanced
    );
    drop(log);
    store.close().await.unwrap();
}

/// Holds a prune after it has checked the chain and signed its receipt, and
/// before it creates the plan that deletes entries.
struct GateArchiver {
    entered: Arc<Notify>,
    release: Arc<Notify>,
}

struct DiscardArchive;

#[async_trait]
impl AuditArchiver for GateArchiver {
    async fn begin(
        &self,
        _receipt: &AuditPruneReceipt,
        _receipt_bytes: &[u8],
    ) -> AuditResult<Box<dyn AuditArchiveWriter>> {
        self.entered.notify_one();
        self.release.notified().await;
        Ok(Box::new(DiscardArchive))
    }
}

#[async_trait]
impl AuditArchiveWriter for DiscardArchive {
    async fn write(&mut self, _entries: &[AuditEntry]) -> AuditResult<()> {
        Ok(())
    }

    async fn commit(self: Box<Self>) -> AuditResult<()> {
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn first_watermark_recorded_during_a_prune_stops_it_before_deleting() {
    let log = Arc::new(AuditLog::in_memory(KeyPair::generate()));
    let session = SessionId::new();
    append(&log, &session, None, 10).await;
    let hashes = retained_hashes(&log, &session).await;
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    log.set_prune_archiver(Some(Arc::new(GateArchiver {
        entered: Arc::clone(&entered),
        release: Arc::clone(&release),
    })));
    let prune = {
        let log = Arc::clone(&log);
        let session = session.clone();
        tokio::spawn(async move {
            log.prune_chain(
                &session,
                None,
                AuditRetentionPolicy {
                    retain_entries: 2,
                    retain_bytes: None,
                },
            )
            .await
        })
    };
    // The prune checked the chain while it had no watermark.
    entered.notified().await;
    log.mark_anchored(&session, None, 4, hashes[3], evidence(1))
        .await
        .unwrap();
    release.notify_one();

    let refused = prune.await.unwrap();
    assert!(
        matches!(refused, Err(AuditError::UnanchoredPrune(ref reason)) if reason.contains("first 4 entries")),
        "{refused:?}"
    );
    assert_eq!(
        log.chain_stats(&session, None)
            .await
            .unwrap()
            .unwrap()
            .count,
        10
    );
    assert!(log.prune_state(&session, None).await.unwrap().is_none());
    assert!(!log.prune_in_progress(&session, None).await.unwrap());
}

#[tokio::test]
async fn mark_waits_for_a_pending_prune() {
    let log = AuditLog::in_memory(KeyPair::generate());
    let session = SessionId::new();
    append(&log, &session, None, 6).await;
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
        .unwrap();
    let hashes = retained_hashes(&log, &session).await;
    // A prune whose finalization was interrupted is still pending.
    let storage = log.storage().as_kv_audit_storage().unwrap();
    storage
        .test_stage_finished_prune_plan(&session, None, serde_json::to_vec(&receipt).unwrap())
        .await
        .unwrap();
    rejected(
        log.mark_anchored(&session, None, 6, hashes[2], evidence(1))
            .await,
        "a prune is in progress",
    );
}
