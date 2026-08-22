use super::*;
use crate::storage::AuditStorage;

#[tokio::test]
async fn grouped_principal_append_preserves_chain_order() {
    let log = AuditLog::in_memory(KeyPair::generate());
    let session = SessionId::new();
    let principal = astrid_core::PrincipalId::new("batch-user").unwrap();
    let requests = (0..8)
        .map(|_| {
            (
                session.clone(),
                principal.clone(),
                AuditAction::ConfigReloaded,
                AuthorizationProof::System {
                    reason: "batch-test".to_owned(),
                },
                AuditOutcome::success(),
            )
        })
        .collect();

    let results = log.append_batch_with_principal(requests).await;
    assert_eq!(results.len(), 8);
    assert!(results.iter().all(Result::is_ok));
    let entries = log
        .get_principal_entries(&session, Some(&principal))
        .await
        .unwrap();
    assert_eq!(entries.len(), 8);
    assert!(
        log.verify_principal_chain(&session, Some(&principal))
            .await
            .unwrap()
            .valid
    );
    for pair in entries.windows(2) {
        assert_eq!(pair[1].previous_hash, pair[0].content_hash());
    }
}

#[tokio::test]
async fn append_does_not_exhaust_cas_when_chain_heads_bytes_disagree() {
    let backend = std::sync::Arc::new(astrid_storage::MemoryKvStore::new());
    let storage = crate::storage::KvAuditStorage::from_test_store(
        std::sync::Arc::clone(&backend) as std::sync::Arc<dyn astrid_storage::KvStore>
    );
    let log = AuditLog::with_test_storage(Box::new(storage), KeyPair::generate());
    let session = SessionId::new();
    let principal = astrid_core::PrincipalId::new("alice").unwrap();
    log.append_with_principal(
        session.clone(),
        principal.clone(),
        AuditAction::ConfigReloaded,
        AuthorizationProof::System {
            reason: "cas-heal".to_owned(),
        },
        AuditOutcome::success(),
    )
    .await
    .expect("first append");

    let inspect = crate::storage::KvAuditStorage::from_test_store(
        std::sync::Arc::clone(&backend) as std::sync::Arc<dyn astrid_storage::KvStore>
    );
    let head = inspect
        .get_chain_head(&session, Some(&principal))
        .await
        .expect("head")
        .expect("head exists");
    inspect
        .test_set_chain_head(
            &session,
            Some(&principal),
            head.0.to_string().to_ascii_uppercase().into_bytes(),
        )
        .await
        .expect("corrupt encoding");

    log.append_with_principal(
        session.clone(),
        principal.clone(),
        AuditAction::ConfigReloaded,
        AuthorizationProof::System {
            reason: "cas-heal".to_owned(),
        },
        AuditOutcome::success(),
    )
    .await
    .expect("leftover heads encoding must not exhaust head CAS");
    assert_eq!(log.count_session(&session).await.unwrap(), 2);
    assert!(
        log.verify_principal_chain(&session, Some(&principal))
            .await
            .unwrap()
            .valid
    );
}
