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

#[test]
fn audit_policy_follows_captured_home() {
    let workspace = tempfile::tempdir().unwrap();
    for class in ["file_delete", "process_spawn"] {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join("config.toml"),
            format!("[audit]\nhost_fail_closed = [\"{class}\"]\nentry_format = \"v2\"\n"),
        )
        .unwrap();
        let config = super::load_audit_config(
            &astrid_core::dirs::AstridHome::from_path(root.path()),
            workspace.path(),
            &astrid_core::dirs::WorkspaceLayout::default(),
        )
        .unwrap();
        assert_eq!(config.host_fail_closed, [class]);
        assert_eq!(
            config.entry_format,
            astrid_config::types::AuditEntryFormat::V2
        );
    }
}

#[test]
fn workspace_audit_tightening_is_preserved() {
    let root = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let state = workspace.path().join(".astrid");
    std::fs::create_dir(&state).unwrap();
    std::fs::write(
        root.path().join("config.toml"),
        "[audit]\nhost_fail_closed = [\"process_spawn\"]\n[audit.retention]\nrequire_anchor = true\n",
    )
    .unwrap();
    std::fs::write(
        state.join("config.toml"),
        "[audit]\nhost_fail_closed = [\"file_delete\"]\n",
    )
    .unwrap();
    let config = super::load_audit_config(
        &astrid_core::dirs::AstridHome::from_path(root.path()),
        workspace.path(),
        &astrid_core::dirs::WorkspaceLayout::default(),
    )
    .unwrap();
    assert!(config.retention.require_anchor);
    for class in ["process_spawn", "file_delete"] {
        assert!(config.host_fail_closed.iter().any(|value| value == class));
    }
}

#[test]
fn invalid_audit_layers_cannot_fall_back_to_weaker_policy() {
    for (operator, workspace_config) in [
        (
            "[audit]\nhost_fail_closed = [\"process_spawn\"]\n",
            "[[[invalid",
        ),
        (
            "[audit.retention]\nrequire_anchor = true\n",
            "[audit]\nhost_queue_capacity = 1\n",
        ),
        (
            "[[[invalid",
            "[audit]\nhost_fail_closed = [\"file_delete\"]\n",
        ),
    ] {
        let root = tempfile::tempdir().unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let state = workspace.path().join(".astrid");
        std::fs::create_dir(&state).unwrap();
        std::fs::write(root.path().join("config.toml"), operator).unwrap();
        std::fs::write(state.join("config.toml"), workspace_config).unwrap();
        let error = super::load_audit_config(
            &astrid_core::dirs::AstridHome::from_path(root.path()),
            workspace.path(),
            &astrid_core::dirs::WorkspaceLayout::default(),
        )
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("cannot load audit policy"));
        assert!(error.to_string().contains(root.path().to_str().unwrap()));
    }
}

#[cfg(unix)]
#[test]
fn invalid_workspace_prevents_native_kernel_boot() {
    // A subprocess supplies the native boot environment without racing other
    // tests or changing this process's environment. Keep the Unix socket short.
    let root = tempfile::Builder::new()
        .prefix("audit-boot-")
        .tempdir_in("/tmp")
        .unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "audit_retention::tests::native_audit_boot_probe",
            "--ignored",
            "--nocapture",
        ])
        .env("ASTRID_HOME", root.path())
        .env("ASTRID_AUDIT_BOOT_PROBE", root.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "subprocess fixture for invalid_workspace_prevents_native_kernel_boot"]
async fn native_audit_boot_probe() {
    let Some(expected_home) = std::env::var_os("ASTRID_AUDIT_BOOT_PROBE") else {
        return;
    };
    assert_eq!(
        astrid_core::dirs::AstridHome::resolve().unwrap().root(),
        std::path::PathBuf::from(expected_home)
    );
    let workspace = tempfile::tempdir().unwrap();
    let state = workspace.path().join(".astrid");
    std::fs::create_dir(&state).unwrap();
    std::fs::write(
        state.join("config.toml"),
        "[audit]\nhost_queue_capacity = 1\n",
    )
    .unwrap();
    let result = crate::Kernel::new(
        astrid_core::SessionId::new(),
        workspace.path().to_owned(),
        astrid_capsule_types::CapsuleRuntimeLimits::default(),
        std::collections::HashMap::new(),
        astrid_capsule_types::HttpLimits::default(),
    )
    .await;
    let error = result
        .err()
        .expect("invalid workspace must refuse kernel boot");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert!(
        error.to_string().contains("cannot load audit policy"),
        "{error}"
    );
    assert!(error.to_string().contains("host_queue_capacity"), "{error}");
}
