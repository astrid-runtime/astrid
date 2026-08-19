use super::*;

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
