use super::*;
#[expect(
    clippy::unnecessary_wraps,
    reason = "quota resolver trait requires a fallible callback"
)]
fn no_quota(_: &astrid_storage::StateOwner) -> astrid_storage::StorageResult<Option<u64>> {
    Ok(None)
}
/// Append `count` test entries to the log, returning their IDs.
async fn append_test_entries(
    log: &AuditLog,
    session_id: &SessionId,
    count: u32,
) -> Vec<AuditEntryId> {
    let mut ids = Vec::with_capacity(count as usize);
    for i in 0..count {
        let id = log
            .append(
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
            )
            .await
            .unwrap();
        ids.push(id);
    }
    ids
}
/// Regression: `AuditLog::close` releases the persistent surrealkv `LOCK` so
/// the same directory can be re-opened afterwards.
///
/// Without the close (the pre-fix behaviour), the first `AuditLog` handle holds
/// the exclusive `LOCK` for its whole lifetime — only released on process death
/// — so a second open of the same path while the first is still alive fails
/// with `Database ... LOCK is already locked`. This is the mechanism that left
/// a terminating daemon holding the audit lock until `SIGKILL`. Closing first
/// must let the re-open succeed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn close_releases_lock_so_same_dir_reopens() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit-db");
    let keypair = Arc::new(KeyPair::generate());

    // Sanity: while a handle is open and NOT closed, a second open of the same
    // path is rejected — this is the lock the fix must release.
    let log =
        AuditLog::open_legacy_source(&path, Arc::clone(&keypair)).expect("first open succeeds");
    append_test_entries(&log, &SessionId::new(), 2).await;
    assert!(
        AuditLog::open_legacy_source(&path, Arc::clone(&keypair)).is_err(),
        "a still-open persistent audit log must hold the surrealkv LOCK"
    );

    // After an explicit close the LOCK is released, so a fresh handle opens.
    log.close()
        .await
        .expect("close releases the surrealkv LOCK");
    let reopened = AuditLog::open_legacy_source(&path, keypair)
        .expect("re-open after close must succeed (lock released)");
    // The re-opened handle is usable (chain head resolves from storage).
    assert_eq!(reopened.count().await.unwrap(), 2);
}
#[tokio::test]
async fn test_append_and_retrieve() {
    let keypair = KeyPair::generate();
    let user_id = keypair.key_id();
    let log = AuditLog::in_memory(keypair);
    let session_id = SessionId::new();

    let entry_id = log
        .append(
            session_id.clone(),
            AuditAction::SessionStarted {
                user_id,
                platform: "cli".to_string(),
            },
            AuthorizationProof::System {
                reason: "test".to_string(),
            },
            AuditOutcome::success(),
        )
        .await
        .unwrap();

    let entry = log.get(&entry_id).await.unwrap().unwrap();
    assert_eq!(entry.id, entry_id);
}

#[tokio::test]
async fn runtime_principal_store_system_audit_projection_reopens_durably() {
    let directory = tempfile::tempdir().expect("temporary home");
    let home = astrid_core::dirs::AstridHome::from_path(directory.path().join(".astrid"));
    home.ensure().expect("home layout");
    let quota: std::sync::Arc<dyn astrid_storage::KvQuotaResolver<astrid_storage::StateOwner>> =
        std::sync::Arc::new(no_quota);
    let store = astrid_storage::open_runtime_principal_store(&home, quota)
        .await
        .expect("runtime principal store");
    let backend = store
        .system_control_kv("audit")
        .expect("system audit projection")
        .backend();
    let key = std::sync::Arc::new(KeyPair::generate());
    let session = SessionId::new();
    let first = AuditLog::open_with_kv_store(backend.clone(), key.clone());
    let first = first.expect("open system audit log");
    first
        .append(
            session.clone(),
            AuditAction::ConfigReloaded,
            AuthorizationProof::System {
                reason: "runtime-store".into(),
            },
            AuditOutcome::success(),
        )
        .await
        .expect("append system audit entry");
    let reopened = AuditLog::open_with_kv_store(backend, key).expect("reopen system audit log");
    assert_eq!(reopened.count_session(&session).await.unwrap(), 1);
    assert!(reopened.verify_chain(&session).await.unwrap().valid);
}

#[tokio::test]
async fn sealed_segment_rolls_forward_with_bounded_stats() {
    let key = KeyPair::generate();
    let log = AuditLog::in_memory(key);
    let session = SessionId::new();
    append_test_entries(&log, &session, 2).await;

    let before = log
        .chain_stats(&session, None)
        .await
        .unwrap()
        .expect("metadata after append");
    assert_eq!(before.segment, 0);
    assert_eq!(before.count, 2);
    assert!(!before.sealed);
    log.seal_chain(&session, None).await.unwrap();
    assert!(
        log.chain_stats(&session, None)
            .await
            .unwrap()
            .unwrap()
            .sealed
    );

    append_test_entries(&log, &session, 1).await;
    let after = log
        .chain_stats(&session, None)
        .await
        .unwrap()
        .expect("metadata after rollover");
    assert_eq!(after.segment, 1);
    assert_eq!(after.count, 3);
    assert!(!after.sealed);
    assert!(log.verify_chain(&session).await.unwrap().valid);
}

#[tokio::test]
async fn test_chain_verification() {
    let keypair = KeyPair::generate();
    let log = AuditLog::in_memory(keypair);
    let session_id = SessionId::new();

    append_test_entries(&log, &session_id, 5).await;

    let result = log.verify_chain(&session_id).await.unwrap();
    assert!(result.valid);
    assert_eq!(result.entries_verified, 5);
}

#[tokio::test]
async fn test_audit_builder() {
    let keypair = KeyPair::generate();
    let user_id = keypair.key_id();
    let log = AuditLog::in_memory(keypair);
    let session_id = SessionId::new();

    let entry_id = AuditBuilder::new(&log, session_id.clone())
        .action(AuditAction::SessionStarted {
            user_id,
            platform: "cli".to_string(),
        })
        .authorization(AuthorizationProof::System {
            reason: "test".to_string(),
        })
        .success()
        .await
        .unwrap();

    assert!(log.get(&entry_id).await.unwrap().is_some());

    // Also verify success_with and failure builders to prevent dead code.
    let entry_id2 = AuditBuilder::new(&log, session_id.clone())
        .action(AuditAction::ConfigReloaded)
        .success_with("custom-details")
        .await
        .unwrap();
    assert!(log.get(&entry_id2).await.unwrap().is_some());

    let entry_id3 = AuditBuilder::new(&log, session_id)
        .action(AuditAction::ConfigReloaded)
        .failure("custom-error")
        .await
        .unwrap();
    assert!(log.get(&entry_id3).await.unwrap().is_some());
}

#[tokio::test]
async fn test_verify_detects_tampered_signature() {
    let keypair = KeyPair::generate();
    let log = AuditLog::in_memory(keypair);
    let session_id = SessionId::new();
    let ids = append_test_entries(&log, &session_id, 3).await;

    // Tamper: corrupt the signature of the second entry.
    let mut entry = log.get(&ids[1]).await.unwrap().unwrap();
    let mut bad_sig = *entry.signature.as_bytes();
    bad_sig[0] ^= 0xFF;
    entry.signature = astrid_crypto::Signature::from_bytes(bad_sig);
    log.storage.store(&entry).await.unwrap();

    let result = log.verify_chain(&session_id).await.unwrap();
    assert!(!result.valid);
    assert!(result.issues.iter().any(|issue| matches!(
        issue,
        ChainIssue::InvalidSignature { entry_id } if *entry_id == ids[1]
    )));
}

#[tokio::test]
async fn test_verify_detects_broken_link() {
    let keypair = KeyPair::generate();
    // Keep secret bytes to reconstruct the key for re-signing tampered entries.
    let secret = keypair.secret_key_bytes();
    let log = AuditLog::in_memory(keypair);
    let session_id = SessionId::new();
    let ids = append_test_entries(&log, &session_id, 3).await;

    // Tamper: change the previous_hash of the third entry to break the link.
    let mut entry = log.get(&ids[2]).await.unwrap().unwrap();
    entry.previous_hash = ContentHash::from_bytes([0xAB; 32]);
    // Re-sign so the signature is valid - only the link is broken.
    let signer = KeyPair::from_secret_key(&secret).unwrap();
    let signing_data = entry.signing_data();
    entry.signature = signer.sign(&signing_data);
    log.storage.store(&entry).await.unwrap();

    let result = log.verify_chain(&session_id).await.unwrap();
    assert!(!result.valid);
    // The re-sign must succeed - no InvalidSignature, only BrokenLink.
    assert!(
        !result
            .issues
            .iter()
            .any(|issue| matches!(issue, ChainIssue::InvalidSignature { .. })),
        "re-signed entry should not trigger InvalidSignature"
    );
    assert!(result.issues.iter().any(|issue| matches!(
        issue,
        ChainIssue::BrokenLink { entry_id, .. } if *entry_id == ids[2]
    )));
}

#[tokio::test]
async fn test_verify_detects_invalid_genesis() {
    let keypair = KeyPair::generate();
    let secret = keypair.secret_key_bytes();
    let log = AuditLog::in_memory(keypair);
    let session_id = SessionId::new();

    // Create one entry then tamper its previous_hash to be non-zero.
    let id = log
        .append(
            session_id.clone(),
            AuditAction::McpToolCall {
                server: "test".to_string(),
                tool: "tool_0".to_string(),
                args_hash: ContentHash::zero(),
            },
            AuthorizationProof::NotRequired {
                reason: "test".to_string(),
            },
            AuditOutcome::success(),
        )
        .await
        .unwrap();

    let mut entry = log.get(&id).await.unwrap().unwrap();
    entry.previous_hash = ContentHash::from_bytes([0x01; 32]);
    // Re-sign with the tampered previous_hash.
    let signer = KeyPair::from_secret_key(&secret).unwrap();
    let signing_data = entry.signing_data();
    entry.signature = signer.sign(&signing_data);
    log.storage.store(&entry).await.unwrap();

    let result = log.verify_chain(&session_id).await.unwrap();
    assert!(!result.valid);
    // The re-sign must succeed - no InvalidSignature, only InvalidGenesis.
    assert!(
        !result
            .issues
            .iter()
            .any(|issue| matches!(issue, ChainIssue::InvalidSignature { .. })),
        "re-signed entry should not trigger InvalidSignature"
    );
    assert!(result.issues.iter().any(|issue| matches!(
        issue,
        ChainIssue::InvalidGenesis { entry_id } if *entry_id == id
    )));
}

#[tokio::test]
async fn test_verify_all_detects_tampered_session() {
    let keypair = KeyPair::generate();
    let log = AuditLog::in_memory(keypair);

    // Session A: valid chain.
    let session_a = SessionId::new();
    append_test_entries(&log, &session_a, 3).await;

    // Session B: tampered chain (single entry).
    let session_b = SessionId::new();
    let tampered_ids = append_test_entries(&log, &session_b, 1).await;
    let tampered_id = tampered_ids[0].clone();

    // Corrupt session B's entry signature.
    let mut entry = log.get(&tampered_id).await.unwrap().unwrap();
    let mut bad_sig = *entry.signature.as_bytes();
    bad_sig[0] ^= 0xFF;
    entry.signature = astrid_crypto::Signature::from_bytes(bad_sig);
    log.storage.store(&entry).await.unwrap();

    let results = log.verify_all().await.unwrap();
    assert_eq!(results.len(), 2);

    let a_result = results.iter().find(|(sid, _)| *sid == session_a).unwrap();
    assert!(a_result.1.valid);

    let b_result = results.iter().find(|(sid, _)| *sid == session_b).unwrap();
    assert!(!b_result.1.valid);
}

#[tokio::test]
async fn test_verify_empty_log_is_valid() {
    let keypair = KeyPair::generate();
    let log = AuditLog::in_memory(keypair);

    let results = log.verify_all().await.unwrap();
    assert!(results.is_empty());

    // Also verify an empty session.
    let session_id = SessionId::new();
    let result = log.verify_chain(&session_id).await.unwrap();
    assert!(result.valid);
    assert_eq!(result.entries_verified, 0);
}

#[tokio::test]
async fn test_key_rotation_entries_verify_via_embedded_pubkey() {
    // Entries embed the public key they were signed with, so verification
    // works even when the log's runtime key has changed (key rotation).
    let keypair_a = KeyPair::generate();
    let log_a = AuditLog::in_memory(keypair_a);
    let session_id = SessionId::new();

    // Write entries signed by key A.
    append_test_entries(&log_a, &session_id, 3).await;

    // Extract the entries and replay them into a log with key B.
    let entries = log_a.get_session_entries(&session_id).await.unwrap();
    let keypair_b = KeyPair::generate();
    let log_b = AuditLog::in_memory(keypair_b);

    for entry in &entries {
        log_b.storage.store(entry).await.unwrap();
    }

    // Key B log should still verify entries signed by key A because
    // verify_signature uses the entry's embedded public key.
    let result = log_b.verify_chain(&session_id).await.unwrap();
    assert!(
        result.valid,
        "entries signed by key A should verify in key B log, issues: {:?}",
        result.issues
    );
    assert_eq!(result.entries_verified, 3);
}

// ── Per-principal chain tests ────────────────────────────────

#[tokio::test]
async fn test_principal_chains_are_independent() {
    let keypair = KeyPair::generate();
    let log = AuditLog::in_memory(keypair);
    let session_id = SessionId::new();
    let alice = astrid_core::PrincipalId::new("alice").unwrap();
    let bob = astrid_core::PrincipalId::new("bob").unwrap();

    // Alice: 2 entries
    log.append_with_principal(
        session_id.clone(),
        alice.clone(),
        AuditAction::McpToolCall {
            server: "test".into(),
            tool: "alice_tool_1".into(),
            args_hash: ContentHash::zero(),
        },
        AuthorizationProof::NotRequired {
            reason: "test".into(),
        },
        AuditOutcome::success(),
    )
    .await
    .unwrap();
    log.append_with_principal(
        session_id.clone(),
        alice.clone(),
        AuditAction::McpToolCall {
            server: "test".into(),
            tool: "alice_tool_2".into(),
            args_hash: ContentHash::zero(),
        },
        AuthorizationProof::NotRequired {
            reason: "test".into(),
        },
        AuditOutcome::success(),
    )
    .await
    .unwrap();

    // Bob: 1 entry
    log.append_with_principal(
        session_id.clone(),
        bob.clone(),
        AuditAction::McpToolCall {
            server: "test".into(),
            tool: "bob_tool_1".into(),
            args_hash: ContentHash::zero(),
        },
        AuthorizationProof::NotRequired {
            reason: "test".into(),
        },
        AuditOutcome::success(),
    )
    .await
    .unwrap();

    // System: 1 entry
    log.append(
        session_id.clone(),
        AuditAction::SessionStarted {
            user_id: [0; 8],
            platform: "test".into(),
        },
        AuthorizationProof::System {
            reason: "test".into(),
        },
        AuditOutcome::success(),
    )
    .await
    .unwrap();

    // Each chain verifies independently.
    let alice_result = log
        .verify_principal_chain(&session_id, Some(&alice))
        .await
        .unwrap();
    assert!(alice_result.valid, "alice chain: {:?}", alice_result.issues);
    assert_eq!(alice_result.entries_verified, 2);

    let bob_result = log
        .verify_principal_chain(&session_id, Some(&bob))
        .await
        .unwrap();
    assert!(bob_result.valid, "bob chain: {:?}", bob_result.issues);
    assert_eq!(bob_result.entries_verified, 1);

    let system_result = log.verify_principal_chain(&session_id, None).await.unwrap();
    assert!(
        system_result.valid,
        "system chain: {:?}",
        system_result.issues
    );
    assert_eq!(system_result.entries_verified, 1);

    // Full session verification covers all 4 entries.
    let full = log.verify_chain(&session_id).await.unwrap();
    assert!(full.valid, "full session: {:?}", full.issues);
    assert_eq!(full.entries_verified, 4);
}

#[tokio::test]
async fn test_get_principal_entries_filters_correctly() {
    let keypair = KeyPair::generate();
    let log = AuditLog::in_memory(keypair);
    let session_id = SessionId::new();
    let alice = astrid_core::PrincipalId::new("alice").unwrap();

    // 2 alice entries + 1 system entry
    log.append_with_principal(
        session_id.clone(),
        alice.clone(),
        AuditAction::FileRead {
            path: "a.txt".into(),
        },
        AuthorizationProof::NotRequired { reason: "t".into() },
        AuditOutcome::success(),
    )
    .await
    .unwrap();
    log.append(
        session_id.clone(),
        AuditAction::ConfigReloaded,
        AuthorizationProof::System { reason: "t".into() },
        AuditOutcome::success(),
    )
    .await
    .unwrap();
    log.append_with_principal(
        session_id.clone(),
        alice.clone(),
        AuditAction::FileRead {
            path: "b.txt".into(),
        },
        AuthorizationProof::NotRequired { reason: "t".into() },
        AuditOutcome::success(),
    )
    .await
    .unwrap();

    let alice_entries = log
        .get_principal_entries(&session_id, Some(&alice))
        .await
        .unwrap();
    assert_eq!(alice_entries.len(), 2);

    let system_entries = log.get_principal_entries(&session_id, None).await.unwrap();
    assert_eq!(system_entries.len(), 1);

    // Total session still has 3
    let all = log.get_session_entries(&session_id).await.unwrap();
    assert_eq!(all.len(), 3);
}

#[tokio::test]
async fn test_mixed_session_verify_chain_passes() {
    // A session with interleaved principal and system entries
    // should verify cleanly — each chain is independent.
    let keypair = KeyPair::generate();
    let log = AuditLog::in_memory(keypair);
    let session_id = SessionId::new();
    let alice = astrid_core::PrincipalId::new("alice").unwrap();

    // Interleave: system, alice, system, alice
    log.append(
        session_id.clone(),
        AuditAction::ConfigReloaded,
        AuthorizationProof::System { reason: "t".into() },
        AuditOutcome::success(),
    )
    .await
    .unwrap();
    log.append_with_principal(
        session_id.clone(),
        alice.clone(),
        AuditAction::FileRead {
            path: "a.txt".into(),
        },
        AuthorizationProof::NotRequired { reason: "t".into() },
        AuditOutcome::success(),
    )
    .await
    .unwrap();
    log.append(
        session_id.clone(),
        AuditAction::ConfigReloaded,
        AuthorizationProof::System { reason: "t".into() },
        AuditOutcome::success(),
    )
    .await
    .unwrap();
    log.append_with_principal(
        session_id.clone(),
        alice.clone(),
        AuditAction::FileRead {
            path: "b.txt".into(),
        },
        AuthorizationProof::NotRequired { reason: "t".into() },
        AuditOutcome::success(),
    )
    .await
    .unwrap();

    let result = log.verify_chain(&session_id).await.unwrap();
    assert!(result.valid, "mixed chain: {:?}", result.issues);
    assert_eq!(result.entries_verified, 4);
}

/// Concurrent appends to the SAME `(session, principal)` chain must not fork it.
///
/// Regression for the pre-fix `append_inner`, which read the chain head under a
/// short read lock, released it, then signed + stored + advanced the head as
/// separate steps. Two appends racing on the same chain both read the same
/// parent hash before either stored, then signed two entries claiming the same
/// predecessor — forking the signed chain so that `verify_chain` reported
/// `valid = false` (`BrokenLink` / duplicate genesis) under nothing more than
/// ordinary concurrent host-call load.
///
/// A [`tokio::sync::Barrier`] aligns every task on its first append to force the
/// race, and each task appends several entries to widen the collision window.
/// The atomic per-chain critical section (the whole append under that chain's
/// mutex, held across the persist `.await`) must make the chain verify cleanly
/// with every entry present. This test fails on the pre-fix code.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_concurrent_same_chain_appends_do_not_fork() {
    const TASKS: usize = 8;
    const PER_TASK: usize = 16;
    const TOTAL: usize = TASKS * PER_TASK;

    let keypair = KeyPair::generate();
    let log = std::sync::Arc::new(AuditLog::in_memory(keypair));
    let session_id = SessionId::new();
    let principal = astrid_core::PrincipalId::new("alice").unwrap();

    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(TASKS));

    let handles: Vec<_> = (0..TASKS)
        .map(|t| {
            let log = std::sync::Arc::clone(&log);
            let barrier = std::sync::Arc::clone(&barrier);
            let session_id = session_id.clone();
            let principal = principal.clone();
            tokio::spawn(async move {
                // Align every task on the first append to force the race.
                barrier.wait().await;
                for i in 0..PER_TASK {
                    log.append_with_principal(
                        session_id.clone(),
                        principal.clone(),
                        AuditAction::FileRead {
                            path: format!("t{t}-{i}.txt"),
                        },
                        AuthorizationProof::NotRequired {
                            reason: "race".into(),
                        },
                        AuditOutcome::success(),
                    )
                    .await
                    .expect("append must succeed");
                }
            })
        })
        .collect();

    for h in handles {
        h.await.expect("append task panicked");
    }

    // Every append landed...
    assert_eq!(
        log.count_session(&session_id).await.unwrap(),
        TOTAL,
        "every concurrent append must be persisted"
    );

    // ...and the single principal chain is intact — no fork.
    let result = log.verify_chain(&session_id).await.unwrap();
    assert!(
        result.valid,
        "concurrent same-chain appends forked the signed chain: {:?}",
        result.issues
    );
    assert_eq!(result.entries_verified, TOTAL);
}

struct BlockingPrincipalStorage {
    inner: KvAuditStorage,
    blocked_principal: astrid_core::PrincipalId,
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}

struct BlockAfterCommitStorage {
    inner: KvAuditStorage,
    block_next: Arc<std::sync::atomic::AtomicBool>,
    committed: Arc<tokio::sync::Notify>,
}

/// Gate the first archive-receipt read after the retention scan.  The gate is
/// deliberately placed after `scan_retention` and before `persist_prune`
/// acquires the durable append lock, so a test can append a successor in the
/// exact window in which the old planner used a stale head/count snapshot.
struct PruneScanGateStorage {
    inner: KvAuditStorage,
    scan_finished: Arc<tokio::sync::Notify>,
    append_started: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
    gate_once: Arc<std::sync::atomic::AtomicBool>,
}

#[async_trait::async_trait]
impl AuditStorage for PruneScanGateStorage {
    async fn store(&self, entry: &AuditEntry) -> AuditResult<()> {
        self.inner.store(entry).await
    }

    async fn append_if_head(
        &self,
        entry: &AuditEntry,
        expected: Option<&AuditEntryId>,
    ) -> AuditResult<bool> {
        self.inner.append_if_head(entry, expected).await
    }

    async fn append_batch_if_heads(
        &self,
        entries: &[(&AuditEntry, Option<&AuditEntryId>)],
    ) -> AuditResult<Vec<bool>> {
        self.append_started.notify_one();
        self.inner.append_batch_if_heads(entries).await
    }

    async fn seal_chain(
        &self,
        session_id: &SessionId,
        principal: Option<&astrid_core::PrincipalId>,
    ) -> AuditResult<()> {
        self.inner.seal_chain(session_id, principal).await
    }

    async fn chain_metadata(
        &self,
        session_id: &SessionId,
        principal: Option<&astrid_core::PrincipalId>,
    ) -> AuditResult<Option<crate::storage::TestChainMetadata>> {
        self.inner.chain_metadata(session_id, principal).await
    }

    async fn global_metadata(&self) -> AuditResult<crate::storage::TestGlobalMetadata> {
        self.inner.global_metadata().await
    }

    async fn oldest_sealed_segment(
        &self,
    ) -> AuditResult<
        Option<(
            SessionId,
            Option<astrid_core::PrincipalId>,
            crate::storage::TestChainMetadata,
        )>,
    > {
        self.inner.oldest_sealed_segment().await
    }

    async fn prune_chain(
        &self,
        session_id: &SessionId,
        principal: Option<&astrid_core::PrincipalId>,
        keep_entries: usize,
        receipt: Vec<u8>,
    ) -> AuditResult<()> {
        self.inner
            .prune_chain(session_id, principal, keep_entries, receipt)
            .await
    }

    async fn prune_receipt(
        &self,
        session_id: &SessionId,
        principal: Option<&astrid_core::PrincipalId>,
    ) -> AuditResult<Option<Vec<u8>>> {
        if self
            .gate_once
            .compare_exchange(
                true,
                false,
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
            )
            .is_ok()
        {
            self.scan_finished.notify_one();
            self.release.notified().await;
        }
        self.inner.prune_receipt(session_id, principal).await
    }

    async fn get(&self, id: &AuditEntryId) -> AuditResult<Option<AuditEntry>> {
        self.inner.get(id).await
    }

    async fn get_chain_head(
        &self,
        session_id: &SessionId,
        principal: Option<&astrid_core::PrincipalId>,
    ) -> AuditResult<Option<AuditEntryId>> {
        self.inner.get_chain_head(session_id, principal).await
    }

    async fn get_session_entries(&self, session_id: &SessionId) -> AuditResult<Vec<AuditEntry>> {
        self.inner.get_session_entries(session_id).await
    }

    async fn get_session_entries_page(
        &self,
        session_id: &SessionId,
        after: Option<&str>,
        limit: usize,
    ) -> AuditResult<Vec<(String, AuditEntry)>> {
        self.inner
            .get_session_entries_page(session_id, after, limit)
            .await
    }

    async fn count(&self) -> AuditResult<usize> {
        self.inner.count().await
    }

    async fn count_session(&self, session_id: &SessionId) -> AuditResult<usize> {
        self.inner.count_session(session_id).await
    }

    async fn list_sessions(&self) -> AuditResult<Vec<SessionId>> {
        self.inner.list_sessions().await
    }

    async fn flush(&self) -> AuditResult<()> {
        self.inner.flush().await
    }

    async fn close(&self) -> AuditResult<()> {
        self.inner.close().await
    }
}

/// A concurrent append that starts after the retention scan must survive the
/// prune and remain the durable chain head.  The storage gate makes the race
/// deterministic: prune has completed its scan, then an append is admitted,
/// and only then is prune allowed to enter its durable commit phase.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_append_after_prune_scan_preserves_head_and_accounting() {
    const SEALED_ENTRIES: u32 = 1_024;

    let backing = Arc::new(astrid_storage::MemoryKvStore::new());
    let keypair = Arc::new(KeyPair::generate());
    let session_id = SessionId::new();
    let setup = AuditLog::with_test_storage(
        Box::new(KvAuditStorage::from_test_store(
            Arc::clone(&backing) as Arc<dyn astrid_storage::KvStore>
        )),
        Arc::clone(&keypair),
    );
    append_test_entries(&setup, &session_id, SEALED_ENTRIES).await;

    let scan_finished = Arc::new(tokio::sync::Notify::new());
    let append_started = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let gated = Arc::new(AuditLog::with_test_storage(
        Box::new(PruneScanGateStorage {
            inner: KvAuditStorage::from_test_store(
                Arc::clone(&backing) as Arc<dyn astrid_storage::KvStore>
            ),
            scan_finished: Arc::clone(&scan_finished),
            append_started: Arc::clone(&append_started),
            release: Arc::clone(&release),
            gate_once: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        }),
        Arc::clone(&keypair),
    ));

    let prune_task = {
        let gated = Arc::clone(&gated);
        tokio::spawn(async move {
            gated
                .prune_oldest(AuditRetentionPolicy {
                    retain_entries: 1,
                    retain_bytes: None,
                })
                .await
        })
    };
    scan_finished.notified().await;

    let append_task = {
        let gated = Arc::clone(&gated);
        let session_id = session_id.clone();
        tokio::spawn(async move {
            gated
                .append(
                    session_id,
                    AuditAction::ConfigReloaded,
                    AuthorizationProof::System {
                        reason: "append during prune scan".into(),
                    },
                    AuditOutcome::success(),
                )
                .await
        })
    };
    append_started.notified().await;
    // If prune already owns the durable lock, the append waits here; if the
    // pre-fix planner has not acquired it yet, the append commits before this
    // release.  Either schedule must produce the same canonical projection.
    release.notify_one();

    let appended = append_task
        .await
        .expect("append task must not panic")
        .expect("append during prune must succeed");
    prune_task
        .await
        .expect("prune task must not panic")
        .expect("prune must complete");

    let entries = gated
        .get_session_entries(&session_id)
        .await
        .expect("read retained session entries");
    assert_eq!(entries.len(), 2, "retained suffix plus concurrent append");
    assert_eq!(entries.last().map(|entry| &entry.id), Some(&appended));

    let chain = gated
        .chain_stats(&session_id, None)
        .await
        .expect("read chain stats")
        .expect("chain metadata must remain present");
    assert_eq!(chain.count, 2, "prune must not roll back the append count");
    assert_eq!(chain.head, Some(appended.clone()));
    assert!(!chain.sealed, "the concurrent append is the active tail");

    let global = gated.global_stats().await.expect("read global stats");
    assert_eq!(
        global.total_count, 2,
        "global count must include the append"
    );
    assert_eq!(global.segments, 1, "only the active tail segment remains");
    assert_eq!(global.sealed_segments, 0);
    assert!(
        gated
            .verify_chain(&session_id)
            .await
            .expect("verify retained chain")
            .valid,
        "concurrent append must not fork or lose the archive anchor"
    );
}

#[async_trait::async_trait]
impl AuditStorage for BlockAfterCommitStorage {
    async fn store(&self, entry: &AuditEntry) -> AuditResult<()> {
        self.inner.store(entry).await?;
        if self
            .block_next
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            self.committed.notify_one();
            std::future::pending::<()>().await;
        }
        Ok(())
    }

    async fn get(&self, id: &AuditEntryId) -> AuditResult<Option<AuditEntry>> {
        self.inner.get(id).await
    }

    async fn get_chain_head(
        &self,
        session_id: &SessionId,
        principal: Option<&astrid_core::PrincipalId>,
    ) -> AuditResult<Option<AuditEntryId>> {
        self.inner.get_chain_head(session_id, principal).await
    }

    async fn get_session_entries(&self, session_id: &SessionId) -> AuditResult<Vec<AuditEntry>> {
        self.inner.get_session_entries(session_id).await
    }

    async fn count(&self) -> AuditResult<usize> {
        self.inner.count().await
    }

    async fn count_session(&self, session_id: &SessionId) -> AuditResult<usize> {
        self.inner.count_session(session_id).await
    }

    async fn list_sessions(&self) -> AuditResult<Vec<SessionId>> {
        self.inner.list_sessions().await
    }

    async fn flush(&self) -> AuditResult<()> {
        self.inner.flush().await
    }

    async fn close(&self) -> AuditResult<()> {
        self.inner.close().await
    }
}

#[async_trait::async_trait]
impl AuditStorage for BlockingPrincipalStorage {
    async fn store(&self, entry: &AuditEntry) -> AuditResult<()> {
        if entry.principal.as_ref() == Some(&self.blocked_principal) {
            self.entered.notify_one();
            self.release.notified().await;
        }
        self.inner.store(entry).await
    }

    async fn get(&self, id: &AuditEntryId) -> AuditResult<Option<AuditEntry>> {
        self.inner.get(id).await
    }

    async fn get_chain_head(
        &self,
        session_id: &SessionId,
        principal: Option<&astrid_core::PrincipalId>,
    ) -> AuditResult<Option<AuditEntryId>> {
        self.inner.get_chain_head(session_id, principal).await
    }

    async fn get_session_entries(&self, session_id: &SessionId) -> AuditResult<Vec<AuditEntry>> {
        self.inner.get_session_entries(session_id).await
    }

    async fn count(&self) -> AuditResult<usize> {
        self.inner.count().await
    }

    async fn count_session(&self, session_id: &SessionId) -> AuditResult<usize> {
        self.inner.count_session(session_id).await
    }

    async fn list_sessions(&self) -> AuditResult<Vec<SessionId>> {
        self.inner.list_sessions().await
    }

    async fn flush(&self) -> AuditResult<()> {
        self.inner.flush().await
    }

    async fn close(&self) -> AuditResult<()> {
        self.inner.close().await
    }
}

/// A persist blocked on Alice's chain must not hold Bob's independent chain.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blocked_principal_store_does_not_block_another_principal() {
    let alice = astrid_core::PrincipalId::new("alice").unwrap();
    let bob = astrid_core::PrincipalId::new("bob").unwrap();
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let storage = BlockingPrincipalStorage {
        inner: KvAuditStorage::in_memory(),
        blocked_principal: alice.clone(),
        entered: Arc::clone(&entered),
        release: Arc::clone(&release),
    };
    let log = Arc::new(AuditLog {
        storage: Box::new(storage),
        runtime_key: Arc::new(KeyPair::generate()),
        chain_heads: std::sync::Mutex::new(std::collections::HashMap::new()),
        append_coordinator: Arc::new(Mutex::new(())),
        migration_capacity: None,
        destination_kv: None,
    });
    let session_id = SessionId::new();

    let alice_append = {
        let log = Arc::clone(&log);
        let session_id = session_id.clone();
        tokio::spawn(async move {
            log.append_with_principal(
                session_id,
                alice,
                AuditAction::FileRead {
                    path: "alice.txt".into(),
                },
                AuthorizationProof::NotRequired {
                    reason: "independent chain test".into(),
                },
                AuditOutcome::success(),
            )
            .await
        })
    };
    entered.notified().await;

    let bob_append = {
        let log = Arc::clone(&log);
        let session_id = session_id.clone();
        tokio::spawn(async move {
            log.append_with_principal(
                session_id,
                bob,
                AuditAction::FileRead {
                    path: "bob.txt".into(),
                },
                AuthorizationProof::NotRequired {
                    reason: "independent chain test".into(),
                },
                AuditOutcome::success(),
            )
            .await
        })
    };

    tokio::time::timeout(std::time::Duration::from_secs(1), bob_append)
        .await
        .expect("Bob's independent chain must not wait for Alice's blocked store")
        .expect("Bob task must not panic")
        .expect("Bob append must succeed");
    release.notify_one();
    alice_append
        .await
        .expect("Alice task must not panic")
        .expect("Alice append must succeed");

    assert_eq!(log.count_session(&session_id).await.unwrap(), 2);
    assert!(log.verify_chain(&session_id).await.unwrap().valid);
}

#[tokio::test]
async fn verification_uses_append_order_when_wall_clock_moves_backward() {
    use chrono::TimeZone;

    let keypair = Arc::new(KeyPair::generate());
    let session_id = SessionId::new();
    let mut first = AuditEntry::create(
        session_id.clone(),
        AuditAction::ConfigReloaded,
        AuthorizationProof::System {
            reason: "clock test".into(),
        },
        AuditOutcome::success(),
        ContentHash::zero(),
        &keypair,
    );
    first.timestamp = astrid_core::Timestamp::from_datetime(
        chrono::Utc.timestamp_opt(2_000, 0).single().unwrap(),
    );
    first.signature = keypair.sign(&first.signing_data());

    let mut second = AuditEntry::create(
        session_id.clone(),
        AuditAction::ConfigReloaded,
        AuthorizationProof::System {
            reason: "clock test".into(),
        },
        AuditOutcome::success(),
        first.content_hash(),
        &keypair,
    );
    second.timestamp = astrid_core::Timestamp::from_datetime(
        chrono::Utc.timestamp_opt(1_000, 0).single().unwrap(),
    );
    second.signature = keypair.sign(&second.signing_data());

    let storage = KvAuditStorage::in_memory();
    storage.store(&first).await.unwrap();
    storage.store(&second).await.unwrap();
    let log = AuditLog {
        storage: Box::new(storage),
        runtime_key: keypair,
        chain_heads: std::sync::Mutex::new(std::collections::HashMap::new()),
        append_coordinator: Arc::new(Mutex::new(())),
        migration_capacity: None,
        destination_kv: None,
    };

    let result = log.verify_chain(&session_id).await.unwrap();
    assert!(result.valid, "clock rollback must not reorder the chain");
    assert_eq!(result.entries_verified, 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_after_durable_commit_recovers_head_without_fork() {
    let block_next = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let committed = Arc::new(tokio::sync::Notify::new());
    let log = Arc::new(AuditLog::with_test_storage(
        Box::new(BlockAfterCommitStorage {
            inner: KvAuditStorage::in_memory(),
            block_next: Arc::clone(&block_next),
            committed: Arc::clone(&committed),
        }),
        KeyPair::generate(),
    ));
    let session_id = SessionId::new();
    let append = |reason: &'static str| {
        let log = Arc::clone(&log);
        let session_id = session_id.clone();
        async move {
            log.append(
                session_id,
                AuditAction::ConfigReloaded,
                AuthorizationProof::System {
                    reason: reason.into(),
                },
                AuditOutcome::success(),
            )
            .await
        }
    };

    append("first").await.unwrap();
    block_next.store(true, std::sync::atomic::Ordering::SeqCst);
    let second = tokio::spawn(append("second"));
    committed.notified().await;
    second.abort();
    assert!(second.await.unwrap_err().is_cancelled());

    append("third").await.unwrap();
    assert_eq!(log.count_session(&session_id).await.unwrap(), 3);
    let verification = log.verify_chain(&session_id).await.unwrap();
    assert!(
        verification.valid,
        "post-commit cancellation left a stale cached head: {:?}",
        verification.issues
    );
    assert_eq!(verification.entries_verified, 3);
}
