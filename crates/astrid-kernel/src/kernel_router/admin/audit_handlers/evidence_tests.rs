//! Delivery of compaction evidence must not mistake a digest for the bundle.

use std::sync::Arc;

use astrid_core::dirs::AstridHome;
use astrid_crypto::KeyPair;
use astrid_storage::storage_model::{
    ObjectClass, ObjectFormatVersion, ObjectId, ObjectKind, ObjectRecord,
};
use astrid_storage::{KvQuotaResolver, StateOwner, open_runtime_principal_store};

use super::{
    AuditAction, AuditLog, AuditOutcome, AuthorizationProof, SessionId, deliver_compaction_evidence,
};

#[tokio::test]
async fn digest_only_audit_delivery_retains_complete_compaction_evidence() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|_: &StateOwner| Ok(None));
    let store = open_runtime_principal_store(&home, Arc::clone(&quota))
        .await
        .unwrap();
    let key = Arc::new(KeyPair::generate());
    let audit = AuditLog::open_with_kv_store(store.kv(), Arc::clone(&key)).unwrap();
    let session = SessionId::new();
    audit
        .append(
            session.clone(),
            AuditAction::ConfigReloaded,
            AuthorizationProof::System {
                reason: "fixture".to_owned(),
            },
            AuditOutcome::success(),
        )
        .await
        .unwrap();
    let policy = ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        b"retain-current-roots".to_vec(),
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let report = store
        .compact_with_deterministic_proof(ObjectId::new([0x71; 32]), policy.clone(), Vec::new())
        .await
        .unwrap();
    let before = store.pending_compaction_evidence().unwrap();
    assert_eq!(before.len(), 1);

    // Use the real durable audit projection, not an in-memory fake sink.
    let (_, pending) = deliver_compaction_evidence(&audit, &store, &session, &report).await;
    let entries = audit.get_session_entries(&session).await.unwrap();
    assert_eq!(entries.len(), 2);
    entries[1].verify_signature().unwrap();
    let AuditAction::AdminRequest {
        params: Some(params),
        ..
    } = &entries[1].action
    else {
        panic!("expected the compaction audit summary");
    };
    assert!(params.get("evidence_digest").is_some());

    // A later compaction must not re-log old bundles with the latest report's
    // counters. Both complete bundles must remain available after restart.
    let second = store
        .compact_with_deterministic_proof(ObjectId::new([0x72; 32]), policy, Vec::new())
        .await
        .unwrap();
    let (_, second_pending) = deliver_compaction_evidence(&audit, &store, &session, &second).await;
    assert!(second_pending);
    assert_eq!(audit.get_session_entries(&session).await.unwrap().len(), 3);
    let complete = store.pending_compaction_evidence().unwrap();
    assert_eq!(complete.len(), 2);
    assert!(complete.contains(&before[0]));

    audit.close().await.unwrap();
    drop(audit);
    drop(store);
    let reopened = open_runtime_principal_store(&home, quota).await.unwrap();
    assert!(
        reopened.pending_compaction_evidence().unwrap() == complete,
        "a digest-only audit entry discarded the complete compaction evidence"
    );
    assert!(pending, "digest-only delivery must remain pending");
    reopened.kv().close().await.unwrap();
}
