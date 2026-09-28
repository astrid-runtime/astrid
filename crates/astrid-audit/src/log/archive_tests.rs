use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use astrid_core::SessionId;
use astrid_crypto::{ContentHash, KeyPair};
use async_trait::async_trait;
use tokio::sync::Notify;

use crate::entry::{AuditAction, AuditEntry, AuditOutcome, AuthorizationProof};
use crate::error::{AuditError, AuditResult};
use crate::log::{
    AuditArchiveWriter, AuditArchiver, AuditLog, AuditPruneReceipt, AuditRetentionPolicy,
};

async fn append(log: &AuditLog, session: &SessionId, count: u32) {
    for index in 0..count {
        log.append(
            session.clone(),
            AuditAction::McpToolCall {
                server: "archive".to_owned(),
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

/// One committed archive: the receipt bytes and the archived entries.
type Archived = (Vec<u8>, Vec<AuditEntry>);

/// Collects committed archives; fails the commit when `fail` is set.
#[derive(Default)]
struct MemoryArchiver {
    committed: Arc<Mutex<Vec<Archived>>>,
    fail: bool,
}

struct MemoryArchive {
    receipt: Vec<u8>,
    entries: Vec<AuditEntry>,
    committed: Arc<Mutex<Vec<Archived>>>,
    fail: bool,
}

#[async_trait]
impl AuditArchiver for MemoryArchiver {
    async fn begin(
        &self,
        _receipt: &AuditPruneReceipt,
        receipt_bytes: &[u8],
    ) -> AuditResult<Box<dyn AuditArchiveWriter>> {
        Ok(Box::new(MemoryArchive {
            receipt: receipt_bytes.to_vec(),
            entries: Vec::new(),
            committed: Arc::clone(&self.committed),
            fail: self.fail,
        }))
    }
}

#[async_trait]
impl AuditArchiveWriter for MemoryArchive {
    async fn write(&mut self, entries: &[AuditEntry]) -> AuditResult<()> {
        self.entries.extend_from_slice(entries);
        Ok(())
    }

    async fn commit(self: Box<Self>) -> AuditResult<()> {
        if self.fail {
            return Err(AuditError::StorageError("archive medium full".to_owned()));
        }
        self.committed
            .lock()
            .unwrap()
            .push((self.receipt, self.entries));
        Ok(())
    }
}

#[tokio::test]
async fn archive_holds_every_pruned_entry_before_it_is_deleted() {
    let log = AuditLog::in_memory(KeyPair::generate());
    let session = SessionId::new();
    append(&log, &session, 150).await;
    let before: Vec<_> = log
        .chain_entries_page(&session, None, None, 1_000)
        .await
        .unwrap()
        .into_iter()
        .map(|(_, entry)| entry)
        .collect();
    let archiver = Arc::new(MemoryArchiver::default());
    log.set_prune_archiver(Some(Arc::clone(&archiver) as Arc<dyn AuditArchiver>));

    let receipt = log.prune_chain(&session, None, retain(20)).await.unwrap();
    let committed = archiver.committed.lock().unwrap().clone();
    assert_eq!(committed.len(), 1);
    let (receipt_bytes, entries) = &committed[0];
    assert_eq!(receipt_bytes, &serde_json::to_vec(&receipt).unwrap());
    assert_eq!(entries.len(), 130);
    for (archived, original) in entries.iter().zip(&before) {
        assert_eq!(archived.id, original.id);
        assert!(archived.verify_signature().is_ok());
    }
    // The archive links to the retained chain.
    assert_eq!(
        entries.last().unwrap().content_hash().to_hex(),
        receipt.omitted_terminal_hash
    );
    let retained = log.get_session_entries(&session).await.unwrap();
    assert_eq!(
        retained[0].previous_hash,
        entries.last().unwrap().content_hash()
    );

    // A prune that removes nothing archives nothing.
    log.prune_chain(&session, None, retain(20)).await.unwrap();
    assert_eq!(archiver.committed.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn failed_archive_aborts_the_prune_before_deleting_anything() {
    let log = AuditLog::in_memory(KeyPair::generate());
    let session = SessionId::new();
    append(&log, &session, 12).await;
    log.set_prune_archiver(Some(Arc::new(MemoryArchiver {
        fail: true,
        ..MemoryArchiver::default()
    })));

    let failed = log.prune_chain(&session, None, retain(2)).await;
    assert!(
        matches!(failed, Err(AuditError::StorageError(ref error)) if error.contains("medium full")),
        "{failed:?}"
    );
    assert_eq!(
        log.chain_stats(&session, None)
            .await
            .unwrap()
            .unwrap()
            .count,
        12
    );
    assert!(log.prune_state(&session, None).await.unwrap().is_none());
    assert!(!log.prune_in_progress(&session, None).await.unwrap());

    log.set_prune_archiver(None);
    assert_eq!(
        log.prune_chain(&session, None, retain(2))
            .await
            .unwrap()
            .omitted_count,
        10
    );
}

#[tokio::test]
async fn every_prune_receipt_is_kept_in_generation_order() {
    let log = AuditLog::in_memory(KeyPair::generate());
    let session = SessionId::new();
    append(&log, &session, 12).await;
    let mut receipts = Vec::new();
    for keep in [9, 6, 3] {
        receipts.push(log.prune_chain(&session, None, retain(keep)).await.unwrap());
    }

    let history = log.prune_receipts(&session, None, 0, 16).await.unwrap();
    assert_eq!(history.len(), 3);
    for (index, (state, receipt)) in history.iter().zip(&receipts).enumerate() {
        assert_eq!(state.receipt, *receipt);
        assert_eq!(state.receipt.generation, u64::try_from(index).unwrap());
        assert_eq!(
            state.receipt_hash,
            ContentHash::hash(&serde_json::to_vec(receipt).unwrap())
        );
    }
    for pair in history.windows(2) {
        assert_eq!(
            pair[1].receipt.prior_receipt_hash.as_deref(),
            Some(pair[0].receipt_hash.to_hex().as_str())
        );
    }
    let later = log.prune_receipts(&session, None, 1, 1).await.unwrap();
    assert_eq!(later.len(), 1);
    assert_eq!(later[0].receipt.generation, 1);
    assert!(
        log.prune_receipts(&session, None, 3, 16)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn receipt_installed_before_history_existed_is_listed_and_kept() {
    let log = AuditLog::in_memory(KeyPair::generate());
    let session = SessionId::new();
    append(&log, &session, 8).await;
    let first = log.prune_chain(&session, None, retain(5)).await.unwrap();
    let storage = log.storage().as_kv_audit_storage().unwrap();
    storage
        .test_forget_receipt_history(&session, None)
        .await
        .unwrap();

    // The installed receipt is still listed.
    let listed = log.prune_receipts(&session, None, 0, 16).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].receipt, first);

    // The next prune records it in the history with its successor.
    let second = log.prune_chain(&session, None, retain(2)).await.unwrap();
    let recorded: Vec<AuditPruneReceipt> = storage
        .receipt_history_page(&session, None, 0, 16)
        .await
        .unwrap()
        .iter()
        .map(|bytes| serde_json::from_slice(bytes).unwrap())
        .collect();
    assert_eq!(recorded, vec![first, second]);
}

/// Holds the first archive open until released; later ones pass through.
#[derive(Default)]
struct HoldFirstArchiver {
    inner: MemoryArchiver,
    begun: AtomicUsize,
    entered: Notify,
    release: Notify,
}

#[async_trait]
impl AuditArchiver for HoldFirstArchiver {
    async fn begin(
        &self,
        receipt: &AuditPruneReceipt,
        receipt_bytes: &[u8],
    ) -> AuditResult<Box<dyn AuditArchiveWriter>> {
        if self.begun.fetch_add(1, Ordering::SeqCst) == 0 {
            self.entered.notify_one();
            self.release.notified().await;
        }
        self.inner.begin(receipt, receipt_bytes).await
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_prunes_of_a_chain_archive_one_at_a_time() {
    let log = Arc::new(AuditLog::in_memory(KeyPair::generate()));
    let session = SessionId::new();
    append(&log, &session, 10).await;
    let archiver = Arc::new(HoldFirstArchiver::default());
    log.set_prune_archiver(Some(Arc::clone(&archiver) as Arc<dyn AuditArchiver>));
    let prune = |entries| {
        let log = Arc::clone(&log);
        let session = session.clone();
        tokio::spawn(async move { log.prune_chain(&session, None, retain(entries)).await })
    };

    // The first prune has signed generation 0 and is archiving it.
    let first = prune(2);
    archiver.entered.notified().await;
    // A second prune of the chain would sign generation 0 too. It must not
    // archive until the first has installed its plan.
    let second = prune(5);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(archiver.begun.load(Ordering::SeqCst), 1);
    archiver.release.notify_one();

    let first = first.await.unwrap().unwrap();
    let second = second.await.unwrap().unwrap();
    assert_eq!(first.generation, 0);
    assert_eq!(first.omitted_count, 8);
    assert_eq!(second.generation, 1);
    assert_eq!(second.omitted_count, 0);
    // Only the installed generation-0 receipt was archived; the second prune
    // removed nothing.
    let committed = archiver.inner.committed.lock().unwrap().clone();
    assert_eq!(committed.len(), 1);
    assert_eq!(committed[0].0, serde_json::to_vec(&first).unwrap());
    assert_eq!(committed[0].1.len(), 8);
}
