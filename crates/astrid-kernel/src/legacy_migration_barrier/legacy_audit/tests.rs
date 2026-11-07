//! Public audit import followed by the production boot-retirement path.

use std::sync::Arc;

use base64::Engine as _;

use super::super::migrate_legacy_audit;
use astrid_audit::{AuditCapacityProvider, AuditLog, AuditResult};
use astrid_core::dirs::AstridHome;
use astrid_crypto::KeyPair;

struct Capacity;

impl AuditCapacityProvider for Capacity {
    fn available_bytes(&self) -> AuditResult<Option<u64>> {
        Ok(Some(u64::MAX))
    }
}

#[tokio::test]
async fn boot_imports_old_format_audit_and_retires_only_the_verified_source() {
    let root = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(root.path().join("home"));
    home.ensure().unwrap();
    // The component barrier creates this before writing its capsule-authority
    // receipt and invoking audit migration. Storage never creates an arbitrary
    // missing ancestor chain as part of moving a verified source.
    astrid_core::platform_fs::ensure_private_directory(&home.migrations_dir()).unwrap();
    let source = home
        .principal_home(&astrid_core::PrincipalId::default())
        .audit_dir();
    astrid_core::platform_fs::ensure_private_directory(&source).unwrap();
    let fixture: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../../astrid-audit/fixtures/surrealkv-0.21.3-audit.json"
    ))
    .unwrap();
    for file in fixture["files"].as_array().unwrap() {
        let target = source.join(file["path"].as_str().unwrap());
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::write(
            target,
            base64::engine::general_purpose::STANDARD
                .decode(file["base64"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
    }
    let audit = Arc::new(
        AuditLog::open_with_kv_store_and_capacity(
            Arc::new(astrid_storage::MemoryKvStore::new()),
            KeyPair::generate(),
            Some(Arc::new(Capacity)),
        )
        .unwrap(),
    );
    migrate_legacy_audit(&home, &audit).await.unwrap();
    assert_eq!(audit.count().await.unwrap(), 1);
    assert!(!source.exists());
    assert!(
        std::fs::read_dir(home.migrations_dir())
            .unwrap()
            .all(|entry| {
                !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with("legacy-retire-")
            })
    );
    // Legitimate native writes after MOVE must not invalidate the persisted
    // source retirement intent on the next boot.
    audit
        .append(
            astrid_core::SessionId::new(),
            astrid_audit::AuditAction::McpToolCall {
                server: "native-after-migration".to_owned(),
                tool: "append".to_owned(),
                args_hash: astrid_crypto::ContentHash::zero(),
            },
            astrid_audit::AuthorizationProof::NotRequired {
                reason: "fixture".to_owned(),
            },
            astrid_audit::AuditOutcome::success(),
        )
        .await
        .unwrap();
    // Restart-style retry sees absence and preserves the imported projection.
    migrate_legacy_audit(&home, &audit).await.unwrap();
    assert_eq!(audit.count().await.unwrap(), 2);
}
