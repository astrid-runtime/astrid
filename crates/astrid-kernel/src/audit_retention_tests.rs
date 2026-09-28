use std::sync::Arc;

use astrid_audit::{
    AuditAction, AuditEntry, AuditLog, AuditOutcome, AuditPruneReceipt, AuditRetentionPolicy,
    AuthorizationProof,
};
use astrid_config::types::AuditRetentionConfig;
use astrid_core::{PrincipalId, SessionId};
use astrid_crypto::KeyPair;

use super::apply_retention_config;

async fn append(log: &AuditLog, session: &SessionId, principal: &PrincipalId, count: usize) {
    for _ in 0..count {
        log.append_with_principal(
            session.clone(),
            principal.clone(),
            AuditAction::ConfigReloaded,
            AuthorizationProof::System {
                reason: "test".to_owned(),
            },
            AuditOutcome::success(),
        )
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn file_archive_holds_the_receipt_and_every_pruned_entry() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("archive");
    let log = AuditLog::in_memory(KeyPair::generate());
    apply_retention_config(
        &log,
        &AuditRetentionConfig {
            require_anchor: false,
            archive_dir: Some(root.to_string_lossy().into_owned()),
        },
    );
    let session = SessionId::new();
    let alice = PrincipalId::new("alice").unwrap();
    append(&log, &session, &alice, 9).await;

    let receipt = log
        .prune_chain(
            &session,
            Some(&alice),
            AuditRetentionPolicy {
                retain_entries: 4,
                retain_bytes: None,
            },
        )
        .await
        .unwrap();
    let file = root
        .join(session.0.to_string())
        .join("principal.alice")
        .join(format!("{:020}.jsonl", receipt.generation));
    let contents = std::fs::read_to_string(&file).unwrap();
    let mut lines = contents.lines();
    let stored: AuditPruneReceipt = serde_json::from_str(lines.next().unwrap()).unwrap();
    assert_eq!(stored, receipt);
    let entries: Vec<AuditEntry> = lines
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(entries.len(), 5);
    assert!(entries[0].previous_hash.is_zero());
    for pair in entries.windows(2) {
        assert!(pair[1].follows(&pair[0]));
    }
    assert_eq!(
        entries.last().unwrap().content_hash().to_hex(),
        receipt.omitted_terminal_hash
    );
    // No temporary file is left behind.
    let names: Vec<_> = std::fs::read_dir(file.parent().unwrap())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(names.len(), 1, "{names:?}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode =
            |path: &std::path::Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&root), 0o700);
        assert_eq!(mode(file.parent().unwrap()), 0o700);
        assert_eq!(mode(&file), 0o600);
    }
}

#[tokio::test]
async fn unwritable_archive_leaves_the_chain_intact() {
    let dir = tempfile::tempdir().unwrap();
    // A regular file where the archive directory should be.
    let root = dir.path().join("not-a-directory");
    std::fs::write(&root, b"x").unwrap();
    let log = Arc::new(AuditLog::in_memory(KeyPair::generate()));
    apply_retention_config(
        &log,
        &AuditRetentionConfig {
            require_anchor: true,
            archive_dir: Some(root.to_string_lossy().into_owned()),
        },
    );
    assert!(log.require_anchor_before_prune());
    log.set_require_anchor_before_prune(false);
    let session = SessionId::new();
    let bob = PrincipalId::new("bob").unwrap();
    append(&log, &session, &bob, 6).await;

    let failed = log
        .prune_chain(
            &session,
            Some(&bob),
            AuditRetentionPolicy {
                retain_entries: 2,
                retain_bytes: None,
            },
        )
        .await;
    assert!(failed.is_err(), "{failed:?}");
    assert_eq!(
        log.chain_stats(&session, Some(&bob))
            .await
            .unwrap()
            .unwrap()
            .count,
        6
    );
}
