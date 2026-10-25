use super::*;
use crate::principal_state::{
    PrincipalDirectory, open_runtime_principal_store_from_fresh_admission,
};
use crate::{KvQuotaResolver, open_runtime_principal_store};
use std::sync::Arc;

fn quota() -> Arc<dyn KvQuotaResolver<StateOwner>> {
    Arc::new(|_: &StateOwner| Ok(None))
}

#[tokio::test]
async fn fresh_retry_recovers_before_first_layout_sentinel_without_replacing_host_identity() {
    for host_key in [false, true] {
        for partial_etc in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let home = AstridHome::from_path(root.path());
            home.ensure().unwrap();
            if host_key {
                astrid_core::platform_fs::atomic_write_private_file(
                    &home.runtime_key_path(),
                    &[9; 32],
                )
                .unwrap();
            }
            let (engine, _) = crate::principal_state::volume_migration::initialize_volume(
                &home,
                crate::engine::DurableEnginePolicy::default(),
            )
            .unwrap();
            engine.close().unwrap();
            drop(engine);
            if partial_etc {
                astrid_core::platform_fs::ensure_private_directory(&home.etc_dir()).unwrap();
            }
            assert_eq!(home.layout_version().unwrap(), None);
            let store = open_runtime_principal_store_from_fresh_admission(
                &home,
                quota(),
                PrincipalDirectory::default(),
            )
            .await
            .unwrap();
            assert_eq!(home.layout_version().unwrap().as_deref(), Some("2"));
            if host_key {
                assert_eq!(std::fs::read(home.runtime_key_path()).unwrap(), [9; 32]);
            } else {
                assert!(!home.runtime_key_path().exists());
            }
            assert_eq!(
                active::read(&home, &store).unwrap().unwrap().phase(),
                ReceiptPhase::Active
            );
        }
    }
}

#[tokio::test]
async fn fresh_retry_preserves_identity_with_or_without_active_receipt() {
    for (durable_key, receipt) in [(false, false), (false, true), (true, false), (true, true)] {
        let root = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(root.path());
        home.ensure().unwrap();
        if durable_key {
            astrid_core::platform_fs::atomic_write_private_file(&home.runtime_key_path(), &[7; 32])
                .unwrap();
        }
        let store = open_runtime_principal_store(&home, quota()).await.unwrap();
        if durable_key {
            astrid_core::platform_fs::atomic_write_private_file(&home.runtime_key_path(), &[9; 32])
                .unwrap();
        }
        if !durable_key {
            astrid_core::platform_fs::atomic_write_private_file(&home.runtime_key_path(), &[7; 32])
                .unwrap();
        }
        if !receipt {
            active::clear(&store, &home).unwrap();
        }
        drop(store);
        for _ in 0..2 {
            let retry = open_runtime_principal_store_from_fresh_admission(
                &home,
                quota(),
                PrincipalDirectory::default(),
            )
            .await
            .unwrap();
            assert_eq!(std::fs::read(home.runtime_key_path()).unwrap(), [7; 32]);
            assert_eq!(
                active::read(&home, &retry).unwrap().unwrap().phase(),
                ReceiptPhase::Active
            );
            drop(retry);
        }
    }
}

#[tokio::test]
async fn fresh_retry_rejects_current_application_authority_before_restoring() {
    for case in [
        "system-kv",
        "system-content",
        "principal-content",
        "ledger",
        "retiring",
        "relocated",
        "host-config",
        "invalid-layout",
        "missing-layout",
    ] {
        let root = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(root.path());
        home.ensure().unwrap();
        let store = open_runtime_principal_store(&home, quota()).await.unwrap();
        add_refused_authority(case, &home, &store).await;
        drop(store);
        std::fs::write(home.root().join("etc/layout-version"), b"2").unwrap();
        let before = std::fs::read(home.root().join("etc/layout-version")).unwrap();
        assert!(
            open_runtime_principal_store_from_fresh_admission(
                &home,
                quota(),
                PrincipalDirectory::default(),
            )
            .await
            .is_err(),
            "{case} accepted"
        );
        assert_eq!(
            std::fs::read(home.root().join("etc/layout-version")).unwrap(),
            before
        );
    }
}

async fn add_refused_authority(case: &str, home: &AstridHome, store: &RuntimePrincipalStore) {
    let receipt_name = active::active_projection_name().unwrap();
    match case {
        "host-config" => {
            astrid_core::platform_fs::atomic_write_private_file(
                &home.config_path(),
                b"[capsule]\ninstance_pool_size = 999\n",
            )
            .unwrap();
        },
        "invalid-layout" | "missing-layout" => {
            let name = ContentName::new("etc/layout-version").unwrap();
            if case == "invalid-layout" {
                store.content.put(&StateOwner::System, &name, b"7").unwrap();
            } else {
                store.content.delete(&StateOwner::System, &name).unwrap();
            }
        },
        "system-kv" => store
            .system_control_kv("audit")
            .unwrap()
            .set("state", b"application".to_vec())
            .await
            .unwrap(),
        "system-content" | "ledger" | "principal-content" => {
            let name = ContentName::new(if case == "ledger" {
                "var/migrations/components.v1.json"
            } else {
                "app/data"
            })
            .unwrap();
            let owner = if case == "principal-content" {
                StateOwner::Principal(astrid_core::PrincipalUid::from_bytes([7; 32]))
            } else {
                StateOwner::System
            };
            store.content.put(&owner, &name, b"application").unwrap();
        },
        "retiring" | "relocated" => {
            let mut receipt: serde_json::Value = serde_json::from_slice(
                &store
                    .content
                    .read(&StateOwner::System, &receipt_name)
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
            if case == "retiring" {
                receipt["phase"] = serde_json::json!("retiring");
            } else {
                receipt["root"] = serde_json::json!("/different-root");
            }
            store
                .content
                .put(
                    &StateOwner::System,
                    &receipt_name,
                    &serde_json::to_vec(&receipt).unwrap(),
                )
                .unwrap();
        },
        _ => unreachable!(),
    }
}

#[tokio::test]
async fn fresh_retry_preserves_unpublished_boot_diagnostics_without_ingesting_them() {
    let root = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(root.path());
    home.ensure().unwrap();
    let store = open_runtime_principal_store(&home, quota()).await.unwrap();
    drop(store);
    let log = home.root().join("log/boot.log");
    astrid_core::platform_fs::ensure_private_directory(log.parent().unwrap()).unwrap();
    astrid_core::platform_fs::atomic_write_private_file(&log, b"boot diagnostics").unwrap();
    let store = open_runtime_principal_store_from_fresh_admission(
        &home,
        quota(),
        PrincipalDirectory::default(),
    )
    .await
    .unwrap();
    assert_eq!(std::fs::read(&log).unwrap(), b"boot diagnostics");
    assert!(
        store
            .content
            .describe(
                &StateOwner::System,
                &ContentName::new("log/boot.log").unwrap()
            )
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn unsentinelled_opener_requires_bootstrap_proof_before_host_restore() {
    use crate::{
        RecoveredProjectionOrigin, open_runtime_principal_store_from_unsentinelled_projection,
    };
    for lock in [false, true] {
        for foreign_config in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let home = AstridHome::from_path(root.path());
            home.ensure().unwrap();
            let (engine, _) = crate::principal_state::volume_migration::initialize_volume(
                &home,
                crate::engine::DurableEnginePolicy::default(),
            )
            .unwrap();
            engine.close().unwrap();
            drop(engine);
            if lock {
                astrid_core::platform_fs::atomic_write_private_file(
                    &home.root().join("run/system.lock"),
                    b"",
                )
                .unwrap();
            }
            if foreign_config {
                astrid_core::platform_fs::atomic_write_private_file(
                    &home.config_path(),
                    b"unadmitted host policy",
                )
                .unwrap();
            }
            let result = open_runtime_principal_store_from_unsentinelled_projection(
                &home,
                quota(),
                PrincipalDirectory::default(),
            )
            .await;
            if foreign_config {
                let error = result
                    .err()
                    .expect("foreign configuration must fail closed");
                assert!(error.to_string().contains("unadmitted host files"));
                assert_eq!(
                    std::fs::read(home.config_path()).unwrap(),
                    b"unadmitted host policy"
                );
                assert_eq!(home.layout_version().unwrap(), None);
            } else {
                let (_store, origin) = result.unwrap();
                assert_eq!(origin, RecoveredProjectionOrigin::FreshAdmission);
                assert_eq!(home.layout_version().unwrap().as_deref(), Some("2"));
            }
            assert!(!home.runtime_key_path().exists());
        }
    }
}
