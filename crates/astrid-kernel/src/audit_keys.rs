//! Audit entry format selection and the audit signing key.
//!
//! Format v2 signs audit entries with a key of its own, `keys/audit.key`,
//! separate from `keys/runtime.key`, which keeps signing capability tokens
//! and local builds. The key registry created on first enablement binds the
//! audit key to the audit role and records the runtime key as the
//! capability, build and v1-audit key, so each role can later move to a key
//! of its own through a cross-signed rotation.

use std::path::Path;
use std::sync::Arc;

use astrid_audit::{AuditLog, EntryV2Config, KeyRole, PrincipalUidResolver};
use astrid_config::types::AuditEntryFormat;
use astrid_crypto::KeyPair;

/// File name of the audit signing key inside `keys/`.
pub(crate) const AUDIT_KEY_FILE: &str = "audit.key";

/// Switch `audit_log` to the configured entry format.
///
/// `configured` is the operator's `audit.entry_format`, or why the
/// configuration could not be read. Format v2 stays on once the store holds a
/// key registry, whatever `configured` says: a v1 entry after a v2 entry would
/// reopen a chain under the weaker format, so the audit log refuses v1
/// appends on such a store.
///
/// # Errors
///
/// Fails when the configuration cannot be read and the store is not already
/// on v2 (the operator may have chosen v2, so v1 is not assumed), when the key
/// registry does not verify, when the audit key is missing although a
/// registry exists, or when the audit key is not the registry's active audit
/// key. The audit log cannot record entries in the intended, verifiable
/// format in any of those states, so boot stops rather than continue.
pub(crate) async fn apply_entry_format(
    audit_log: &AuditLog,
    keys_dir: &Path,
    configured: Result<AuditEntryFormat, String>,
    runtime_key: &Arc<KeyPair>,
    principals: Arc<dyn PrincipalUidResolver>,
) -> std::io::Result<()> {
    let registry_exists = audit_log
        .key_registry()
        .await
        .map_err(|error| std::io::Error::other(format!("audit key registry: {error}")))?
        .is_some();
    let configured = match configured {
        Ok(format) => format,
        Err(reason) if registry_exists => {
            tracing::warn!(
                error = %reason,
                "cannot read audit.entry_format; this node already writes audit format v2 and stays on it"
            );
            AuditEntryFormat::V2
        },
        Err(reason) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "cannot read audit.entry_format from the configuration ({reason}); \
                     refusing to choose an audit entry format the operator did not select"
                ),
            ));
        },
    };
    if !registry_exists && configured == AuditEntryFormat::V1 {
        return Ok(());
    }
    if configured == AuditEntryFormat::V1 {
        tracing::warn!(
            "audit.entry_format is \"v1\", but this node already writes audit format v2; \
             v1 is closed once enabled, so audit entries stay in format v2"
        );
    }
    let audit_key = Arc::new(load_audit_key(keys_dir, registry_exists)?);
    let registry = audit_log
        .enable_entry_v2(EntryV2Config {
            audit_key,
            genesis_roles: vec![
                (KeyRole::Capability, Arc::clone(runtime_key)),
                (KeyRole::Build, Arc::clone(runtime_key)),
                (KeyRole::AuditV1, Arc::clone(runtime_key)),
            ],
            principals: Some(principals),
        })
        .await
        .map_err(|error| {
            std::io::Error::other(format!("cannot enable audit entry format v2: {error}"))
        })?;
    tracing::info!(
        registry_id = %hex::encode(registry.registry_id()),
        key_epoch = registry.head_seq(),
        "audit entry format v2 enabled"
    );
    Ok(())
}

/// Load `keys/audit.key`, generating it only while no key registry exists.
///
/// Once a registry names an audit key, a replacement key cannot be
/// registered without the old one (rotation is cross-signed), so a missing
/// key file is an error rather than a reason to generate a new key.
fn load_audit_key(keys_dir: &Path, registry_exists: bool) -> std::io::Result<KeyPair> {
    astrid_core::platform_fs::ensure_private_directory(keys_dir)?;
    let key_path = keys_dir.join(AUDIT_KEY_FILE);
    if key_path.exists() {
        astrid_core::platform_fs::validate_private_file(&key_path)?;
    } else if registry_exists {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!(
                "audit signing key {} is missing, but the audit log already has a key registry \
                 naming it; restore the key file (a replacement key can only be registered by \
                 the current one)",
                key_path.display()
            ),
        ));
    }
    let keypair = astrid_crypto::load_or_generate_keypair(&key_path).map_err(|error| {
        let message = error
            .to_string()
            .replacen("invalid signing key", "invalid audit key", 1);
        std::io::Error::new(error.kind(), message)
    })?;
    astrid_core::platform_fs::restrict_private_file(&key_path)?;
    Ok(keypair)
}

#[cfg(test)]
mod tests {
    use super::*;
    use astrid_audit::{AuditAction, AuditEntryFormat as Format, AuditOutcome, AuthorizationProof};
    use astrid_core::{PrincipalId, SessionId};
    use astrid_storage::{KvStore, MemoryKvStore, PrincipalDirectory};

    fn principals() -> Arc<dyn PrincipalUidResolver> {
        Arc::new(PrincipalDirectory::default())
    }

    async fn append(log: &AuditLog, session: &SessionId) -> astrid_audit::AuditResult<()> {
        log.append_with_principal(
            session.clone(),
            PrincipalId::default(),
            AuditAction::ConfigReloaded,
            AuthorizationProof::System {
                reason: "test".into(),
            },
            AuditOutcome::success(),
        )
        .await
        .map(|_| ())
    }

    #[tokio::test]
    async fn v1_leaves_the_log_and_the_keys_directory_alone() {
        let home = tempfile::tempdir().unwrap();
        let keys = home.path().join("keys");
        let runtime = Arc::new(KeyPair::generate());
        let log = AuditLog::in_memory(Arc::clone(&runtime));
        apply_entry_format(
            &log,
            &keys,
            Ok(AuditEntryFormat::V1),
            &runtime,
            principals(),
        )
        .await
        .unwrap();
        assert_eq!(log.entry_format(), Format::V1);
        assert!(!keys.join(AUDIT_KEY_FILE).exists());
    }

    #[tokio::test]
    async fn v2_creates_a_separate_private_audit_key_and_registers_roles() {
        let home = tempfile::tempdir().unwrap();
        let keys = home.path().join("keys");
        let runtime = Arc::new(KeyPair::generate());
        let store: Arc<dyn KvStore> = Arc::new(MemoryKvStore::new());
        let log = AuditLog::open_with_kv_store(Arc::clone(&store), Arc::clone(&runtime)).unwrap();
        apply_entry_format(
            &log,
            &keys,
            Ok(AuditEntryFormat::V2),
            &runtime,
            principals(),
        )
        .await
        .unwrap();
        assert_eq!(log.entry_format(), Format::V2);
        let key_path = keys.join(AUDIT_KEY_FILE);
        astrid_core::platform_fs::validate_private_file(&key_path).unwrap();
        let audit = astrid_crypto::load_or_generate_keypair(&key_path).unwrap();
        assert_ne!(audit.export_public_key(), runtime.export_public_key());
        assert_eq!(log.signing_public_key(), audit.export_public_key());
        let registry = log.key_registry().await.unwrap().unwrap();
        assert_eq!(
            registry.active_key(KeyRole::Audit, 0),
            Some(audit.export_public_key())
        );
        for role in [KeyRole::Capability, KeyRole::Build, KeyRole::AuditV1] {
            assert_eq!(
                registry.active_key(role, 0),
                Some(runtime.export_public_key())
            );
        }
        let session = SessionId::new();
        append(&log, &session).await.unwrap();
        assert!(log.verify_chain(&session).await.unwrap().valid);
    }

    #[tokio::test]
    async fn v2_stays_on_after_the_switch_is_set_back() {
        let home = tempfile::tempdir().unwrap();
        let keys = home.path().join("keys");
        let runtime = Arc::new(KeyPair::generate());
        let store: Arc<dyn KvStore> = Arc::new(MemoryKvStore::new());
        let session = SessionId::new();
        {
            let log =
                AuditLog::open_with_kv_store(Arc::clone(&store), Arc::clone(&runtime)).unwrap();
            apply_entry_format(
                &log,
                &keys,
                Ok(AuditEntryFormat::V2),
                &runtime,
                principals(),
            )
            .await
            .unwrap();
            append(&log, &session).await.unwrap();
        }
        let log = AuditLog::open_with_kv_store(Arc::clone(&store), Arc::clone(&runtime)).unwrap();
        apply_entry_format(
            &log,
            &keys,
            Ok(AuditEntryFormat::V1),
            &runtime,
            principals(),
        )
        .await
        .unwrap();
        assert_eq!(log.entry_format(), Format::V2);
        append(&log, &session).await.unwrap();
        assert!(log.verify_chain(&session).await.unwrap().valid);
    }

    #[tokio::test]
    async fn a_lost_or_replaced_audit_key_stops_boot() {
        let home = tempfile::tempdir().unwrap();
        let keys = home.path().join("keys");
        let runtime = Arc::new(KeyPair::generate());
        let store: Arc<dyn KvStore> = Arc::new(MemoryKvStore::new());
        let log = AuditLog::open_with_kv_store(Arc::clone(&store), Arc::clone(&runtime)).unwrap();
        apply_entry_format(
            &log,
            &keys,
            Ok(AuditEntryFormat::V2),
            &runtime,
            principals(),
        )
        .await
        .unwrap();
        let key_path = keys.join(AUDIT_KEY_FILE);

        std::fs::remove_file(&key_path).unwrap();
        let reopened =
            AuditLog::open_with_kv_store(Arc::clone(&store), Arc::clone(&runtime)).unwrap();
        let error = apply_entry_format(
            &reopened,
            &keys,
            Ok(AuditEntryFormat::V2),
            &runtime,
            principals(),
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
        assert!(!key_path.exists(), "no replacement key is generated");

        // A different key in place of the registered one is refused too.
        astrid_crypto::load_or_generate_keypair(&key_path).unwrap();
        astrid_core::platform_fs::restrict_private_file(&key_path).unwrap();
        let error = apply_entry_format(
            &reopened,
            &keys,
            Ok(AuditEntryFormat::V2),
            &runtime,
            principals(),
        )
        .await
        .unwrap_err();
        assert!(
            error.to_string().contains("not the active audit key"),
            "{error}"
        );
        assert_eq!(reopened.entry_format(), Format::V1);
    }
    #[tokio::test]
    async fn an_unreadable_configuration_stops_boot_unless_already_on_v2() {
        let home = tempfile::tempdir().unwrap();
        let keys = home.path().join("keys");
        let runtime = Arc::new(KeyPair::generate());
        let store: Arc<dyn KvStore> = Arc::new(MemoryKvStore::new());
        let unreadable = || Err("parse error in config.toml".to_owned());

        // Fresh store: the operator's choice is unknown, so no format is assumed.
        let log = AuditLog::open_with_kv_store(Arc::clone(&store), Arc::clone(&runtime)).unwrap();
        let error = apply_entry_format(&log, &keys, unreadable(), &runtime, principals())
            .await
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("parse error"), "{error}");
        assert!(!keys.join(AUDIT_KEY_FILE).exists());

        // A store already on v2 keeps v2 whatever the configuration says.
        apply_entry_format(
            &log,
            &keys,
            Ok(AuditEntryFormat::V2),
            &runtime,
            principals(),
        )
        .await
        .unwrap();
        let reopened =
            AuditLog::open_with_kv_store(Arc::clone(&store), Arc::clone(&runtime)).unwrap();
        apply_entry_format(&reopened, &keys, unreadable(), &runtime, principals())
            .await
            .unwrap();
        assert_eq!(reopened.entry_format(), Format::V2);
    }
}
