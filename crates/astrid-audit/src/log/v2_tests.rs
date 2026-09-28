//! Format v2 through the audit log: enabling, migration from v1, restart,
//! rotation, principal binding and archive receipts.

use super::*;
use crate::entry::AuditEntryFormat;
use crate::entry_v2::{AuditActor, ChainStart, ChainVerifier, KeyRole};
use astrid_core::PrincipalId;
use astrid_core::identity::PrincipalUid;
use astrid_storage::MemoryKvStore;

fn key(seed: u8) -> Arc<KeyPair> {
    Arc::new(KeyPair::from_secret_key(&[seed; 32]).unwrap())
}

fn runtime() -> Arc<KeyPair> {
    key(2)
}

fn config(audit: &Arc<KeyPair>) -> EntryV2Config {
    EntryV2Config {
        audit_key: Arc::clone(audit),
        genesis_roles: vec![
            (KeyRole::Capability, runtime()),
            (KeyRole::Build, runtime()),
            (KeyRole::AuditV1, runtime()),
        ],
        principals: None,
    }
}

fn alice() -> PrincipalId {
    PrincipalId::new("alice").unwrap()
}

async fn record(log: &AuditLog, session: &SessionId, principal: Option<&PrincipalId>, n: u32) {
    for index in 0..n {
        let action = AuditAction::FileRead {
            path: format!("/{index}"),
        };
        let authorization = AuthorizationProof::System {
            reason: "test".into(),
        };
        let outcome = AuditOutcome::success_with(format!("read {index}"));
        match principal {
            Some(principal) => log
                .append_with_principal(
                    session.clone(),
                    principal.clone(),
                    action,
                    authorization,
                    outcome,
                )
                .await
                .unwrap(),
            None => log
                .append(session.clone(), action, authorization, outcome)
                .await
                .unwrap(),
        };
    }
}

fn seqs(entries: &[AuditEntry]) -> Vec<Option<u64>> {
    entries
        .iter()
        .map(|entry| entry.v2.as_ref().map(|seal| seal.seq))
        .collect()
}

#[tokio::test]
async fn enabling_v2_on_a_fresh_store_signs_v2_entries_with_the_audit_key() {
    let log = AuditLog::in_memory(runtime());
    assert_eq!(log.entry_format(), AuditEntryFormat::V1);
    let audit = key(1);
    let registry = log.enable_entry_v2(config(&audit)).await.unwrap();
    assert_eq!(log.entry_format(), AuditEntryFormat::V2);
    assert_eq!(log.signing_public_key(), audit.export_public_key());
    assert_eq!(
        registry.active_key(KeyRole::Capability, 0),
        Some(runtime().export_public_key())
    );

    let session = SessionId::new();
    record(&log, &session, Some(&alice()), 3).await;
    record(&log, &session, None, 2).await;
    let alice_chain = log
        .get_principal_entries(&session, Some(&alice()))
        .await
        .unwrap();
    assert_eq!(seqs(&alice_chain), [Some(1), Some(2), Some(3)]);
    assert!(
        alice_chain
            .iter()
            .all(|entry| entry.runtime_key == audit.export_public_key())
    );
    let system_chain = log.get_principal_entries(&session, None).await.unwrap();
    assert_eq!(seqs(&system_chain), [Some(1), Some(2)]);
    assert_ne!(
        alice_chain[0].v2.as_ref().unwrap().chain_id,
        system_chain[0].v2.as_ref().unwrap().chain_id
    );
    let result = log.verify_chain(&session).await.unwrap();
    assert!(result.valid, "{:?}", result.issues);
    assert_eq!(result.entries_verified, 5);
}

#[tokio::test]
async fn v1_history_stays_as_it_is_and_links_into_the_v2_chain() {
    let store: Arc<dyn KvStore> = Arc::new(MemoryKvStore::new());
    let session = SessionId::new();
    let v1_hashes = {
        let log = AuditLog::open_with_kv_store(Arc::clone(&store), runtime()).unwrap();
        record(&log, &session, Some(&alice()), 3).await;
        record(&log, &session, None, 1).await;
        log.get_principal_entries(&session, Some(&alice()))
            .await
            .unwrap()
            .iter()
            .map(AuditEntry::content_hash)
            .collect::<Vec<_>>()
    };

    // Restart with v2 enabled.
    let log = AuditLog::open_with_kv_store(Arc::clone(&store), runtime()).unwrap();
    log.enable_entry_v2(config(&key(1))).await.unwrap();
    record(&log, &session, Some(&alice()), 2).await;
    record(&log, &session, None, 1).await;

    let chain = log
        .get_principal_entries(&session, Some(&alice()))
        .await
        .unwrap();
    assert_eq!(seqs(&chain), [None, None, None, Some(1), Some(2)]);
    let kept: Vec<_> = chain[..3].iter().map(AuditEntry::content_hash).collect();
    assert_eq!(
        kept, v1_hashes,
        "v1 entries are never rewritten or re-signed"
    );
    assert_eq!(chain[3].previous_hash, v1_hashes[2]);
    let system = log.get_principal_entries(&session, None).await.unwrap();
    assert_eq!(seqs(&system), [None, Some(1)]);

    let result = log.verify_chain(&session).await.unwrap();
    assert!(result.valid, "{:?}", result.issues);
    let registry = log.key_registry().await.unwrap().unwrap();
    let strict = ChainVerifier::new(Some(&registry)).require_registered_v1_keys(true);
    assert!(strict.verify(&chain, ChainStart::Genesis).valid);
}

#[tokio::test]
async fn restart_resumes_the_registry_and_every_chain() {
    let store: Arc<dyn KvStore> = Arc::new(MemoryKvStore::new());
    let session = SessionId::new();
    let audit = key(1);
    let registry_id = {
        let log = AuditLog::open_with_kv_store(Arc::clone(&store), runtime()).unwrap();
        let registry = log.enable_entry_v2(config(&audit)).await.unwrap();
        record(&log, &session, Some(&alice()), 3).await;
        log.close().await.unwrap();
        registry.registry_id()
    };

    let log = AuditLog::open_with_kv_store(Arc::clone(&store), runtime()).unwrap();
    let registry = log.enable_entry_v2(config(&audit)).await.unwrap();
    assert_eq!(registry.registry_id(), registry_id, "no second genesis");
    assert_eq!(registry.records().len(), 1);
    record(&log, &session, Some(&alice()), 2).await;
    let chain = log
        .get_principal_entries(&session, Some(&alice()))
        .await
        .unwrap();
    assert_eq!(seqs(&chain), [Some(1), Some(2), Some(3), Some(4), Some(5)]);
    assert!(log.verify_chain(&session).await.unwrap().valid);
}

#[tokio::test]
async fn a_store_with_a_registry_refuses_v1_appends() {
    let store: Arc<dyn KvStore> = Arc::new(MemoryKvStore::new());
    let session = SessionId::new();
    {
        let log = AuditLog::open_with_kv_store(Arc::clone(&store), runtime()).unwrap();
        log.enable_entry_v2(config(&key(1))).await.unwrap();
        record(&log, &session, Some(&alice()), 1).await;
    }
    // Reopened without enabling v2 (for example with the switch set back).
    let log = AuditLog::open_with_kv_store(Arc::clone(&store), runtime()).unwrap();
    for principal in [Some(alice()), None] {
        let error = log
            .append_inner(EntryRequest {
                session_id: session.clone(),
                principal,
                actor: None,
                action: AuditAction::ConfigReloaded,
                authorization: AuthorizationProof::System {
                    reason: "test".into(),
                },
                outcome: AuditOutcome::success(),
            })
            .await
            .unwrap_err();
        assert!(matches!(error, AuditError::V1Closed { .. }), "{error}");
    }
    // Verification still works without the signing key.
    assert!(log.verify_chain(&session).await.unwrap().valid);
}

#[tokio::test]
async fn an_unregistered_audit_key_cannot_be_enabled() {
    let store: Arc<dyn KvStore> = Arc::new(MemoryKvStore::new());
    AuditLog::open_with_kv_store(Arc::clone(&store), runtime())
        .unwrap()
        .enable_entry_v2(config(&key(1)))
        .await
        .unwrap();
    let log = AuditLog::open_with_kv_store(Arc::clone(&store), runtime()).unwrap();
    let error = log.enable_entry_v2(config(&key(0x55))).await.unwrap_err();
    assert!(
        matches!(error, AuditError::KeyNotRegistered { .. }),
        "{error}"
    );
    assert_eq!(log.entry_format(), AuditEntryFormat::V1);
}

#[tokio::test]
async fn rotating_the_audit_key_persists_and_keeps_history_valid() {
    let store: Arc<dyn KvStore> = Arc::new(MemoryKvStore::new());
    let session = SessionId::new();
    let old = key(1);
    let new = key(0x11);
    {
        let log = AuditLog::open_with_kv_store(Arc::clone(&store), runtime()).unwrap();
        log.enable_entry_v2(config(&old)).await.unwrap();
        record(&log, &session, Some(&alice()), 2).await;
        let record_ = log.rotate_audit_key(Arc::clone(&new)).await.unwrap();
        assert_eq!(record_.seq, 1);
        assert_eq!(log.signing_public_key(), new.export_public_key());
        record(&log, &session, Some(&alice()), 2).await;
        assert!(
            log.rotate_audit_key(Arc::clone(&old)).await.is_err(),
            "no reuse"
        );
    }
    let log = AuditLog::open_with_kv_store(Arc::clone(&store), runtime()).unwrap();
    assert!(matches!(
        log.enable_entry_v2(config(&old)).await,
        Err(AuditError::KeyNotRegistered { .. })
    ));
    log.enable_entry_v2(config(&new)).await.unwrap();
    record(&log, &session, Some(&alice()), 1).await;

    let chain = log
        .get_principal_entries(&session, Some(&alice()))
        .await
        .unwrap();
    let epochs: Vec<u64> = chain
        .iter()
        .map(|e| e.v2.as_ref().unwrap().key_epoch)
        .collect();
    assert_eq!(epochs, [0, 0, 1, 1, 1]);
    assert_eq!(seqs(&chain), [Some(1), Some(2), Some(3), Some(4), Some(5)]);
    let result = log.verify_chain(&session).await.unwrap();
    assert!(result.valid, "{:?}", result.issues);
}

struct Uids(std::sync::Mutex<Option<PrincipalUid>>);

impl PrincipalUidResolver for Uids {
    fn resolve_uid(&self, _principal: &PrincipalId) -> Option<PrincipalUid> {
        *self.0.lock().unwrap()
    }
}

#[tokio::test]
async fn the_chain_is_bound_to_the_principal_uid() {
    let log = AuditLog::in_memory(runtime());
    let uids = Arc::new(Uids(std::sync::Mutex::new(Some(PrincipalUid::from_bytes(
        [7; 32],
    )))));
    let mut enabled = config(&key(1));
    enabled.principals = Some(Arc::clone(&uids) as Arc<dyn PrincipalUidResolver>);
    log.enable_entry_v2(enabled).await.unwrap();
    let session = SessionId::new();
    record(&log, &session, Some(&alice()), 2).await;
    // The alias now names a different durable principal: a new chain opens.
    *uids.0.lock().unwrap() = Some(PrincipalUid::from_bytes([8; 32]));
    record(&log, &session, Some(&alice()), 1).await;

    let chain = log
        .get_principal_entries(&session, Some(&alice()))
        .await
        .unwrap();
    assert_eq!(seqs(&chain), [Some(1), Some(2), Some(1)]);
    let first = chain[0].v2.as_ref().unwrap();
    assert_eq!(first.principal_uid, Some(PrincipalUid::from_bytes([7; 32])));
    assert_ne!(first.chain_id, chain[2].v2.as_ref().unwrap().chain_id);
    assert_eq!(chain[2].previous_hash, chain[1].content_hash());
    assert!(log.verify_chain(&session).await.unwrap().valid);
}

#[tokio::test]
async fn batch_appends_and_actors_are_signed_in_sequence() {
    let log = AuditLog::in_memory(runtime());
    log.enable_entry_v2(config(&key(1))).await.unwrap();
    let session = SessionId::new();
    let batch = (0..4)
        .map(|index| {
            (
                session.clone(),
                alice(),
                AuditAction::FileWrite {
                    path: format!("/{index}"),
                    content_hash: ContentHash::zero(),
                },
                AuthorizationProof::System {
                    reason: "batch".into(),
                },
                AuditOutcome::success(),
            )
        })
        .collect();
    assert!(
        log.append_batch_with_principal(batch)
            .await
            .iter()
            .all(Result::is_ok)
    );
    let actor = AuditActor {
        capsule_id: "aos-fs".into(),
        wasm_sha256: Some([8; 32]),
    };
    let id = log
        .append_with_actor(
            session.clone(),
            Some(alice()),
            actor.clone(),
            AuditAction::FileRead { path: "/a".into() },
            AuthorizationProof::System { reason: "a".into() },
            AuditOutcome::success(),
        )
        .await
        .unwrap();
    let chain = log
        .get_principal_entries(&session, Some(&alice()))
        .await
        .unwrap();
    assert_eq!(seqs(&chain), [Some(1), Some(2), Some(3), Some(4), Some(5)]);
    let with_actor = log.get(&id).await.unwrap().unwrap();
    assert_eq!(with_actor.v2.as_ref().unwrap().actor, Some(actor));
    assert!(log.verify_chain(&session).await.unwrap().valid);
}

#[tokio::test]
async fn an_entry_deleted_from_the_store_shows_as_a_sequence_gap() {
    let log = AuditLog::in_memory(runtime());
    log.enable_entry_v2(config(&key(1))).await.unwrap();
    let session = SessionId::new();
    record(&log, &session, None, 4).await;
    let victim = log.get_principal_entries(&session, None).await.unwrap()[1].clone();
    let kv = log.storage().as_kv_audit_storage().unwrap().kv_store();
    kv.delete("audit:entries", &victim.id.0.to_string())
        .await
        .unwrap();
    let index_keys = kv
        .list_keys_with_prefix("audit:session_entries", &format!("{}:", session.0))
        .await
        .unwrap();
    let index_key = index_keys
        .iter()
        .find(|key| key.ends_with(&victim.id.0.to_string()))
        .unwrap();
    kv.delete("audit:session_entries", index_key).await.unwrap();

    let result = log.verify_chain(&session).await.unwrap();
    assert!(!result.valid);
    assert!(result.issues.iter().any(|issue| matches!(
        issue,
        ChainIssue::SequenceGap {
            expected: 2,
            actual: 3,
            ..
        }
    )));
}

#[tokio::test]
async fn prune_receipts_are_signed_by_the_audit_key_and_forgeries_fail() {
    let log = AuditLog::in_memory(runtime());
    let audit = key(1);
    log.enable_entry_v2(config(&audit)).await.unwrap();
    let session = SessionId::new();
    record(&log, &session, None, 6).await;
    let receipt = log
        .prune_chain(
            &session,
            None,
            AuditRetentionPolicy {
                retain_entries: 2,
                retain_bytes: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(receipt.public_key, audit.export_public_key());
    let result = log.verify_chain(&session).await.unwrap();
    assert!(result.valid, "{:?}", result.issues);

    // Someone who deletes history and plants a receipt under their own key
    // produces a self-consistent receipt, which v2 verification rejects.
    let rogue = key(0x55);
    let mut forged = receipt;
    forged.public_key = rogue.export_public_key();
    forged.signature = rogue.sign(&forged.signing_bytes().unwrap());
    assert!(forged.verify().is_ok());
    let kv = log.storage().as_kv_audit_storage().unwrap().kv_store();
    kv.set(
        "audit:prune_receipts",
        &session.0.to_string(),
        serde_json::to_vec(&forged).unwrap(),
    )
    .await
    .unwrap();
    let result = log.verify_chain(&session).await.unwrap();
    assert!(
        result
            .issues
            .iter()
            .any(|issue| matches!(issue, ChainIssue::InvalidGenesis { .. }))
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_single_and_batch_appends_keep_one_gapless_sequence() {
    let log = Arc::new(AuditLog::in_memory(runtime()));
    log.enable_entry_v2(config(&key(1))).await.unwrap();
    let session = SessionId::new();
    let mut tasks = Vec::new();
    for task in 0..8 {
        let log = Arc::clone(&log);
        let session = session.clone();
        tasks.push(tokio::spawn(async move {
            for index in 0..4 {
                if (task ^ index) & 1 == 0 {
                    record(&log, &session, Some(&alice()), 1).await;
                } else {
                    let batch = vec![
                        (
                            session.clone(),
                            alice(),
                            AuditAction::ConfigReloaded,
                            AuthorizationProof::System {
                                reason: "batch".into(),
                            },
                            AuditOutcome::success(),
                        );
                        2
                    ];
                    assert!(
                        log.append_batch_with_principal(batch)
                            .await
                            .iter()
                            .all(Result::is_ok)
                    );
                }
            }
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    let chain = log
        .get_principal_entries(&session, Some(&alice()))
        .await
        .unwrap();
    let expected: Vec<Option<u64>> = (1..=48).map(Some).collect();
    assert_eq!(seqs(&chain), expected);
    let result = log.verify_chain(&session).await.unwrap();
    assert!(result.valid, "{:?}", result.issues);
}

#[tokio::test]
async fn a_retired_audit_key_cannot_anchor_a_suffix_written_after_its_retirement() {
    let log = AuditLog::in_memory(runtime());
    let old = key(1);
    let new = key(0x11);
    log.enable_entry_v2(config(&old)).await.unwrap();
    let session = SessionId::new();
    record(&log, &session, None, 3).await;
    log.rotate_audit_key(Arc::clone(&new)).await.unwrap();
    record(&log, &session, None, 3).await;
    let receipt = log
        .prune_chain(
            &session,
            None,
            AuditRetentionPolicy {
                retain_entries: 2,
                retain_bytes: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(receipt.public_key, new.export_public_key());
    assert_eq!(receipt.key_epoch, Some(1));
    let result = log.verify_chain(&session).await.unwrap();
    assert!(result.valid, "{:?}", result.issues);

    // The retired key forges a self-consistent receipt, naming the epoch in
    // which it was current and then the current epoch; both are rejected
    // because the retained suffix was signed at epoch 1.
    let kv = log.storage().as_kv_audit_storage().unwrap().kv_store();
    for epoch in [0, 1] {
        let mut forged = receipt.clone();
        forged.public_key = old.export_public_key();
        forged.key_epoch = Some(epoch);
        forged.signature = old.sign(&forged.signing_bytes().unwrap());
        assert!(forged.verify().is_ok());
        kv.set(
            "audit:prune_receipts",
            &session.0.to_string(),
            serde_json::to_vec(&forged).unwrap(),
        )
        .await
        .unwrap();
        let result = log.verify_chain(&session).await.unwrap();
        assert!(
            result
                .issues
                .iter()
                .any(|issue| matches!(issue, ChainIssue::InvalidGenesis { .. })),
            "epoch {epoch}: {:?}",
            result.issues
        );
    }

    // A v2 receipt without a key epoch is not accepted either.
    let mut unepoched = receipt;
    unepoched.key_epoch = None;
    unepoched.signature = new.sign(&unepoched.signing_bytes().unwrap());
    kv.set(
        "audit:prune_receipts",
        &session.0.to_string(),
        serde_json::to_vec(&unepoched).unwrap(),
    )
    .await
    .unwrap();
    assert!(!log.verify_chain(&session).await.unwrap().valid);
}

fn request(session: &SessionId, principal: Option<PrincipalId>) -> EntryRequest {
    EntryRequest {
        session_id: session.clone(),
        principal,
        actor: None,
        action: AuditAction::ConfigReloaded,
        authorization: AuthorizationProof::System {
            reason: "test".into(),
        },
        outcome: AuditOutcome::success(),
    }
}

#[tokio::test]
async fn a_second_opener_enabling_v2_closes_v1_for_the_first() {
    let store: Arc<dyn KvStore> = Arc::new(MemoryKvStore::new());
    let session = SessionId::new();
    let first = AuditLog::open_with_kv_store(Arc::clone(&store), runtime()).unwrap();
    record(&first, &session, Some(&alice()), 1).await;

    let second = AuditLog::open_with_kv_store(Arc::clone(&store), runtime()).unwrap();
    second.enable_entry_v2(config(&key(1))).await.unwrap();

    // Neither the existing v1 chain nor a new chain accepts v1 any more.
    for principal in [Some(alice()), None] {
        let error = first
            .append_inner(request(&session, principal))
            .await
            .unwrap_err();
        assert!(matches!(error, AuditError::V1Closed { .. }), "{error}");
    }
    record(&second, &session, Some(&alice()), 1).await;
    let chain = first
        .get_principal_entries(&session, Some(&alice()))
        .await
        .unwrap();
    assert_eq!(seqs(&chain), [None, Some(1)]);
    assert!(second.verify_chain(&session).await.unwrap().valid);
}

#[tokio::test]
async fn an_entry_signed_before_a_rotation_cannot_commit_after_it() {
    let log = AuditLog::in_memory(runtime());
    let old = key(1);
    let new = key(0x11);
    log.enable_entry_v2(config(&old)).await.unwrap();
    let session = SessionId::new();
    let stale = log
        .sign_entry(request(&session, None), ContentHash::zero(), None)
        .unwrap();
    assert_eq!(stale.v2.as_ref().unwrap().key_epoch, 0);
    log.rotate_audit_key(Arc::clone(&new)).await.unwrap();

    let error = log
        .storage()
        .append_batch_if_heads(&[(&stale, None)])
        .await
        .unwrap_err();
    assert!(
        matches!(error, AuditError::StaleAuditKey { key_epoch: 0 }),
        "{error}"
    );
    // This log holds the new key, so an append re-signs instead of failing.
    assert!(log.can_resign(&error, [&stale]));
    record(&log, &session, None, 1).await;
    let chain = log.get_principal_entries(&session, None).await.unwrap();
    assert_eq!(chain.len(), 1);
    let seal = chain[0].v2.as_ref().unwrap();
    assert_eq!((seal.seq, seal.key_epoch), (1, 1));
    assert_eq!(chain[0].runtime_key, new.export_public_key());
}

#[tokio::test]
async fn a_writer_left_behind_by_another_openers_rotation_fails_closed() {
    let store: Arc<dyn KvStore> = Arc::new(MemoryKvStore::new());
    let session = SessionId::new();
    let old = key(1);
    let behind = AuditLog::open_with_kv_store(Arc::clone(&store), runtime()).unwrap();
    behind.enable_entry_v2(config(&old)).await.unwrap();
    record(&behind, &session, None, 1).await;

    let rotating = AuditLog::open_with_kv_store(Arc::clone(&store), runtime()).unwrap();
    rotating.enable_entry_v2(config(&old)).await.unwrap();
    rotating.rotate_audit_key(key(0x11)).await.unwrap();

    // The retired key cannot extend the chain at its old epoch.
    let error = behind
        .append_inner(request(&session, None))
        .await
        .unwrap_err();
    assert!(
        matches!(error, AuditError::StaleAuditKey { key_epoch: 0 }),
        "{error}"
    );
    assert_eq!(behind.count().await.unwrap(), 1);
    assert!(rotating.verify_chain(&session).await.unwrap().valid);
}
