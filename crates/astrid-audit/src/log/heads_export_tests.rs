use std::collections::HashMap;
use std::sync::Arc;

use astrid_core::{PrincipalId, SessionId};
use astrid_crypto::{ContentHash, KeyPair};

use crate::entry::{AuditAction, AuditOutcome, AuthorizationProof};
use crate::log::{AuditChainHead, AuditLog, AuditRetentionPolicy};

async fn append(log: &AuditLog, session: &SessionId, principal: Option<&str>, count: u32) {
    for index in 0..count {
        let action = AuditAction::McpToolCall {
            server: "test".to_owned(),
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

fn retain(entries: usize) -> AuditRetentionPolicy {
    AuditRetentionPolicy {
        retain_entries: entries,
        retain_bytes: None,
    }
}

fn pid(alias: &str) -> PrincipalId {
    PrincipalId::new(alias).unwrap()
}

/// Heads keyed by principal alias (`None` for the system chain).
async fn heads_by_principal(log: &AuditLog) -> HashMap<Option<String>, AuditChainHead> {
    log.heads_snapshot()
        .await
        .unwrap()
        .into_iter()
        .map(|head| (head.principal.as_ref().map(ToString::to_string), head))
        .collect()
}

async fn head_of(log: &AuditLog, principal: &str) -> AuditChainHead {
    heads_by_principal(log)
        .await
        .remove(&Some(principal.to_owned()))
        .expect("chain listed")
}

#[tokio::test]
async fn heads_snapshot_reports_every_chain_head_across_sessions() {
    let log = AuditLog::in_memory(Arc::new(KeyPair::generate()));
    let first = SessionId::new();
    let second = SessionId::new();
    append(&log, &first, None, 3).await;
    append(&log, &first, Some("alice"), 2).await;
    append(&log, &first, Some("bob"), 1).await;
    append(&log, &second, Some("alice"), 4).await;

    let heads = log.heads_snapshot().await.unwrap();
    assert_eq!(heads.len(), 4);
    for head in &heads {
        let entries = log
            .get_principal_entries(&head.session_id, head.principal.as_ref())
            .await
            .unwrap();
        let last = entries.last().expect("chain has entries");
        assert_eq!(head.count, u64::try_from(entries.len()).unwrap());
        assert_eq!(head.head.as_ref(), Some(&last.id));
        assert_eq!(head.head_hash, last.content_hash());
        assert_eq!(head.last_timestamp, Some(last.timestamp));
        assert!(head.prune.is_none());
        assert_eq!(head.omitted_total, Some(0));
    }
    let keys: Vec<_> = heads
        .iter()
        .map(|head| {
            (
                head.session_id.0,
                head.principal.as_ref().map(PrincipalId::as_str),
            )
        })
        .collect();
    assert!(keys.contains(&(first.0, None)));
    assert!(keys.contains(&(first.0, Some("alice"))));
    assert!(keys.contains(&(first.0, Some("bob"))));
    assert!(keys.contains(&(second.0, Some("alice"))));
}

#[tokio::test]
async fn heads_snapshot_pages_past_one_storage_page() {
    let log = AuditLog::in_memory(Arc::new(KeyPair::generate()));
    let session = SessionId::new();
    for index in 0..300 {
        append(&log, &session, Some(&format!("agent-{index:03}")), 1).await;
    }
    assert_eq!(log.heads_snapshot().await.unwrap().len(), 300);
}

#[tokio::test]
async fn omitted_total_accumulates_across_prunes() {
    let log = AuditLog::in_memory(Arc::new(KeyPair::generate()));
    let session = SessionId::new();
    append(&log, &session, None, 10).await;
    let before = log.heads_snapshot().await.unwrap().remove(0);

    let receipt = log.prune_chain(&session, None, retain(6)).await.unwrap();
    let first = log.heads_snapshot().await.unwrap().remove(0);
    assert_eq!((first.count, first.omitted_total), (6, Some(4)));
    assert_eq!(first.head_hash, before.head_hash);
    let state = first.prune.expect("prune receipt");
    assert_eq!(state.receipt, receipt);
    assert_eq!(state.receipt.generation, 0);
    assert_eq!(state.receipt_hash, ContentHash::hash(&state.stored_bytes));

    log.prune_chain(&session, None, retain(4)).await.unwrap();
    let second = log.heads_snapshot().await.unwrap().remove(0);
    assert_eq!((second.count, second.omitted_total), (4, Some(6)));

    append(&log, &session, None, 3).await;
    let appended = log.heads_snapshot().await.unwrap().remove(0);
    assert_eq!((appended.count, appended.omitted_total), (7, Some(6)));

    log.prune_chain(&session, None, retain(2)).await.unwrap();
    let third = log.heads_snapshot().await.unwrap().remove(0);
    assert_eq!((third.count, third.omitted_total), (2, Some(11)));
    assert_eq!(third.prune.as_ref().unwrap().receipt.generation, 2);
    // Every entry ever appended is either retained or counted as omitted.
    assert_eq!(third.count + third.omitted_total.unwrap(), 13);
}

#[tokio::test]
async fn metadata_without_the_counter_derives_it_from_the_latest_receipt() {
    let log = AuditLog::in_memory(Arc::new(KeyPair::generate()));
    let session = SessionId::new();
    append(&log, &session, Some("never"), 3).await;
    append(&log, &session, Some("once"), 8).await;
    append(&log, &session, Some("twice"), 8).await;
    log.prune_chain(&session, Some(&pid("once")), retain(3))
        .await
        .unwrap();
    for keep in [5, 3] {
        log.prune_chain(&session, Some(&pid("twice")), retain(keep))
            .await
            .unwrap();
    }
    let storage = log.storage().as_kv_audit_storage().unwrap();
    for alias in ["never", "once", "twice"] {
        storage
            .test_forget_omitted_total(&session, Some(&pid(alias)))
            .await
            .unwrap();
    }

    let heads = heads_by_principal(&log).await;
    let omitted = |alias: &str| heads[&Some(alias.to_owned())].omitted_total;
    assert_eq!(omitted("never"), Some(0));
    assert_eq!(omitted("once"), Some(5));
    assert_eq!(omitted("twice"), None);

    // The next prune counts from the derived total. An unknown total stays
    // unknown through later prunes and appends.
    log.prune_chain(&session, Some(&pid("once")), retain(2))
        .await
        .unwrap();
    log.prune_chain(&session, Some(&pid("twice")), retain(2))
        .await
        .unwrap();
    append(&log, &session, Some("twice"), 1).await;
    let once = head_of(&log, "once").await;
    assert_eq!((once.count, once.omitted_total), (2, Some(6)));
    let twice = head_of(&log, "twice").await;
    assert_eq!((twice.count, twice.omitted_total), (3, None));
}

#[tokio::test]
async fn uncounted_total_is_unknown_while_a_finished_prune_is_pending() {
    let log = AuditLog::in_memory(Arc::new(KeyPair::generate()));
    let session = SessionId::new();
    append(&log, &session, Some("legacy"), 6).await;
    append(&log, &session, Some("counted"), 6).await;
    for alias in ["legacy", "counted"] {
        log.prune_chain(&session, Some(&pid(alias)), retain(4))
            .await
            .unwrap();
    }
    let storage = log.storage().as_kv_audit_storage().unwrap();
    storage
        .test_forget_omitted_total(&session, Some(&pid("legacy")))
        .await
        .unwrap();
    for alias in ["legacy", "counted"] {
        storage
            .test_stage_finished_prune_plan(&session, Some(&pid(alias)), Vec::new())
            .await
            .unwrap();
    }

    // An older binary may have lowered the legacy count before crashing,
    // so its receipt no longer accounts for it. A counted total is exact.
    assert_eq!(head_of(&log, "legacy").await.omitted_total, None);
    assert_eq!(head_of(&log, "counted").await.omitted_total, Some(2));
}

#[tokio::test]
async fn prune_in_progress_tracks_a_pending_prune_plan() {
    let log = AuditLog::in_memory(Arc::new(KeyPair::generate()));
    let session = SessionId::new();
    let alice = pid("alice");
    append(&log, &session, Some("alice"), 4).await;
    assert!(!log.prune_in_progress(&session, Some(&alice)).await.unwrap());
    log.prune_chain(&session, Some(&alice), retain(2))
        .await
        .unwrap();
    assert!(!log.prune_in_progress(&session, Some(&alice)).await.unwrap());

    log.storage()
        .as_kv_audit_storage()
        .unwrap()
        .test_stage_finished_prune_plan(&session, Some(&alice), Vec::new())
        .await
        .unwrap();
    assert!(log.prune_in_progress(&session, Some(&alice)).await.unwrap());
    assert!(!log.prune_in_progress(&session, None).await.unwrap());
}

#[tokio::test]
async fn chain_entries_page_resumes_in_chain_order_for_one_principal() {
    let log = AuditLog::in_memory(Arc::new(KeyPair::generate()));
    let session = SessionId::new();
    append(&log, &session, Some("alice"), 3).await;
    append(&log, &session, Some("bob"), 2).await;
    append(&log, &session, Some("alice"), 4).await;
    let alice = PrincipalId::new("alice").unwrap();

    let mut exported = Vec::new();
    let mut after: Option<String> = None;
    loop {
        let page = log
            .chain_entries_page(&session, Some(&alice), after.as_deref(), 3)
            .await
            .unwrap();
        let Some((cursor, _)) = page.last() else {
            break;
        };
        after = Some(cursor.clone());
        exported.extend(page.into_iter().map(|(_, entry)| entry));
    }
    assert_eq!(exported.len(), 7);
    assert!(exported[0].previous_hash.is_zero());
    for pair in exported.windows(2) {
        assert!(pair[1].follows(&pair[0]));
    }
    for entry in &exported {
        assert_eq!(entry.principal.as_ref(), Some(&alice));
        entry.verify_signature().unwrap();
    }

    append(&log, &session, Some("alice"), 1).await;
    let tail = log
        .chain_entries_page(&session, Some(&alice), after.as_deref(), 3)
        .await
        .unwrap();
    assert_eq!(tail.len(), 1);
    assert!(tail[0].1.follows(exported.last().unwrap()));
}

#[tokio::test]
async fn chain_cursor_entry_accepts_only_stored_index_keys() {
    let log = AuditLog::in_memory(Arc::new(KeyPair::generate()));
    let session = SessionId::new();
    append(&log, &session, None, 4).await;
    let page = log
        .chain_entries_page(&session, None, None, 4)
        .await
        .unwrap();
    let (first_key, first) = &page[0];
    let (last_key, last) = &page[3];
    assert_eq!(
        log.chain_cursor_entry(last_key)
            .await
            .unwrap()
            .map(|entry| entry.id),
        Some(last.id.clone())
    );

    let (prefix, id) = last_key.rsplit_once(':').unwrap();
    let (session_key, _) = prefix.rsplit_once(':').unwrap();
    let altered = format!("{session_key}:{:020}:{id}", 999_u64);
    assert!(log.chain_cursor_entry(&altered).await.unwrap().is_none());
    assert!(log.chain_cursor_entry("garbage").await.unwrap().is_none());

    log.prune_chain(&session, None, retain(2)).await.unwrap();
    assert!(log.chain_cursor_entry(first_key).await.unwrap().is_none());
    assert_eq!(
        log.chain_cursor_entry(last_key)
            .await
            .unwrap()
            .map(|entry| entry.id),
        Some(last.id.clone())
    );
    assert_ne!(first.id, last.id);
}
