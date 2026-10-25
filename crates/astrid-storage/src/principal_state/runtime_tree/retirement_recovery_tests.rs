use std::sync::Arc;

use super::*;
use crate::principal_state::{
    PrincipalDirectory, open_runtime_principal_store_from_retiring_projection,
};
use crate::{KvQuotaResolver, open_runtime_principal_store};

fn quota() -> Arc<dyn KvQuotaResolver<StateOwner>> {
    Arc::new(|_: &StateOwner| Ok(None))
}

async fn fixture(home: &AstridHome) -> RuntimePrincipalStore {
    home.ensure().unwrap();
    let store = open_runtime_principal_store(home, quota()).await.unwrap();
    for name in [
        "bin/tool",
        "etc/config.toml",
        "etc/profiles/retained.toml",
        "keys/runtime.key",
        "log/audit",
        "var/agent/state",
        "wit/component",
    ] {
        let path = home.root().join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        astrid_core::platform_fs::atomic_write_private_file(&path, &[7; 32]).unwrap();
    }
    store.publish_runtime_projection(home).unwrap();
    store
}

#[tokio::test]
async fn sentinel_free_retirement_prefixes_restore_only_volume_authority() {
    let roots = ["bin", "etc", "keys", "log", "var", "wit"];
    for (cut, dedicated) in (2..=roots.len()).flat_map(|cut| [(cut, false), (cut, true)]) {
        let root = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(root.path());
        let store = fixture(&home).await;
        transition_retiring_projection(&home, &store).unwrap();
        drop(store);
        for name in &roots[..cut] {
            std::fs::remove_dir_all(home.root().join(name)).unwrap();
        }
        if home.log_dir().exists() {
            std::fs::write(home.log_dir().join("audit"), b"tampered leftover").unwrap();
        }
        if cut < roots.len() {
            assert!(
                home.ensure().is_err(),
                "generic fresh-root admission must remain strict"
            );
        }
        home.validate_volume_recovery_candidate().unwrap();
        let reopened = if dedicated {
            open_runtime_principal_store_from_retiring_projection(
                &home,
                quota(),
                PrincipalDirectory::default(),
            )
            .await
        } else {
            open_runtime_principal_store(&home, quota()).await
        }
        .unwrap();
        for name in [
            "bin/tool",
            "etc/config.toml",
            "keys/runtime.key",
            "log/audit",
            "var/agent/state",
            "wit/component",
        ] {
            assert_eq!(
                std::fs::read(home.root().join(name)).unwrap(),
                [7; 32],
                "cut={cut}, name={name}"
            );
        }
        assert_eq!(
            active::read(&home, &reopened).unwrap().unwrap().phase(),
            ReceiptPhase::Active
        );
        reopened.pack_and_retire_runtime_projection(&home).unwrap();
        drop(reopened);
        assert_eq!(std::fs::read_dir(home.root()).unwrap().count(), 1);
    }
}

#[tokio::test]
async fn recovery_rejects_missing_active_relocated_and_corrupt_receipts_before_restore() {
    for failure in ["missing", "active", "relocated", "corrupt", "unreceipted"] {
        let root = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(root.path());
        let store = fixture(&home).await;
        if failure != "active" {
            transition_retiring_projection(&home, &store).unwrap();
        }
        let name = active::active_projection_name().unwrap();
        match failure {
            "missing" => {
                active::clear(&store, &home).unwrap();
            },
            "relocated" => {
                let bytes = store
                    .content()
                    .read(&StateOwner::System, &name)
                    .unwrap()
                    .unwrap();
                let mut receipt: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                receipt["root"] = serde_json::json!("/a-different-durable-root");
                store
                    .content()
                    .put(
                        &StateOwner::System,
                        &name,
                        &serde_json::to_vec(&receipt).unwrap(),
                    )
                    .unwrap();
            },
            "corrupt" => {
                store
                    .content()
                    .put(&StateOwner::System, &name, b"invalid receipt")
                    .unwrap();
            },
            "unreceipted" => {
                std::fs::write(home.log_dir().join("foreign"), b"preserve evidence").unwrap();
            },
            "active" => {},
            _ => unreachable!(),
        }
        store.content().flush().unwrap();
        drop(store);
        std::fs::remove_dir_all(home.etc_dir()).unwrap();
        assert!(
            open_runtime_principal_store(&home, quota()).await.is_err(),
            "ordinary restore must reject {failure}"
        );
        assert!(
            open_runtime_principal_store_from_retiring_projection(
                &home,
                quota(),
                PrincipalDirectory::default()
            )
            .await
            .is_err(),
            "{failure}"
        );
        assert!(
            !home.etc_dir().exists(),
            "{failure}: no host restoration before authentication"
        );
        assert_eq!(
            std::fs::read(home.log_dir().join("audit")).unwrap(),
            [7; 32]
        );
        if failure == "unreceipted" {
            assert_eq!(
                std::fs::read(home.log_dir().join("foreign")).unwrap(),
                b"preserve evidence"
            );
        }
    }
}

#[tokio::test]
async fn mid_etc_retirement_ignores_tampered_key_and_profile_without_quota_reads() {
    let root = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(root.path());
    let store = fixture(&home).await;
    transition_retiring_projection(&home, &store).unwrap();
    drop(store);
    std::fs::remove_file(home.layout_version_path()).unwrap();
    std::fs::write(home.runtime_key_path(), [9; 32]).unwrap();
    let profile = home.etc_dir().join("profiles/retained.toml");
    std::fs::write(&profile, b"untrusted quota and policy").unwrap();
    let spy: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|owner: &StateOwner| {
        assert_eq!(
            *owner,
            StateOwner::System,
            "recovery cannot resolve host principal quotas"
        );
        Ok(None)
    });
    let reopened = open_runtime_principal_store_from_retiring_projection(
        &home,
        spy,
        PrincipalDirectory::default(),
    )
    .await
    .unwrap();
    assert_eq!(std::fs::read(home.runtime_key_path()).unwrap(), [7; 32]);
    assert_eq!(std::fs::read(profile).unwrap(), [7; 32]);
    let names = reopened.content().list(&StateOwner::System).unwrap();
    assert!(!names.iter().any(|entry| {
        entry
            .name()
            .as_str()
            .starts_with("run/.recovered-runtime-keys/")
    }));
}

#[tokio::test]
async fn missing_volume_identity_cannot_allow_kernel_key_regeneration() {
    let root = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(root.path());
    let store = fixture(&home).await;
    let key = ContentName::new(RUNTIME_KEY_PROJECTION).unwrap();
    store.content().delete(&StateOwner::System, &key).unwrap();
    let entries = active_projection_entries(&home, &store).unwrap();
    let intent = receipt_ingest(&home, ReceiptPhase::Retiring, &entries).unwrap();
    store
        .replace_contiguous_files_removing_exact(StateOwner::System, [intent], &[], None)
        .unwrap();
    store.content().flush().unwrap();
    drop(store);
    std::fs::remove_dir_all(home.etc_dir()).unwrap();
    std::fs::remove_dir_all(home.keys_dir()).unwrap();
    assert!(
        open_runtime_principal_store_from_retiring_projection(
            &home,
            quota(),
            PrincipalDirectory::default()
        )
        .await
        .is_err()
    );
    assert!(!home.runtime_key_path().exists());
    assert!(!home.etc_dir().exists());
}

#[cfg(unix)]
#[tokio::test]
async fn excluded_runtime_sockets_do_not_block_authenticated_retirement_recovery() {
    let root = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(root.path());
    let store = fixture(&home).await;
    transition_retiring_projection(&home, &store).unwrap();
    drop(store);
    std::fs::remove_dir_all(home.etc_dir()).unwrap();
    let legacy_run = home.root().join("run");
    std::fs::create_dir_all(legacy_run.join("principals/example")).unwrap();
    let _socket = std::os::unix::net::UnixListener::bind(legacy_run.join("system.sock")).unwrap();
    let _scratch =
        std::os::unix::net::UnixListener::bind(legacy_run.join("principals/example/sock")).unwrap();
    std::fs::write(legacy_run.join("system.lock"), b"lockfile").unwrap();
    assert!(home.ensure().is_err());
    assert!(home.validate_runtime_identity_provisioning().is_err());
    home.validate_volume_recovery_candidate().unwrap();
    let reopened = open_runtime_principal_store_from_retiring_projection(
        &home,
        quota(),
        PrincipalDirectory::default(),
    )
    .await
    .unwrap();
    assert_eq!(
        std::fs::read(home.log_dir().join("audit")).unwrap(),
        [7; 32]
    );
    drop(reopened);
}

#[tokio::test]
async fn unsentinelled_opener_preserves_existing_origin_for_packed_and_retiring_media() {
    use crate::{
        RecoveredProjectionOrigin, open_runtime_principal_store_from_unsentinelled_projection,
    };
    for retiring in [false, true] {
        for lock in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let home = AstridHome::from_path(root.path());
            let store = fixture(&home).await;
            if retiring {
                transition_retiring_projection(&home, &store).unwrap();
                std::fs::remove_dir_all(home.etc_dir()).unwrap();
            } else {
                store.pack_and_retire_runtime_projection(&home).unwrap();
            }
            drop(store);
            if lock {
                astrid_core::platform_fs::atomic_write_private_file(
                    &home.root().join("run/system.lock"),
                    b"",
                )
                .unwrap();
            }
            let (store, origin) = open_runtime_principal_store_from_unsentinelled_projection(
                &home,
                quota(),
                PrincipalDirectory::default(),
            )
            .await
            .unwrap();
            assert_eq!(origin, RecoveredProjectionOrigin::Existing);
            assert_eq!(std::fs::read(home.config_path()).unwrap(), [7; 32]);
            assert_eq!(std::fs::read(home.runtime_key_path()).unwrap(), [7; 32]);
            assert_eq!(
                active::read(&home, &store).unwrap().unwrap().phase(),
                ReceiptPhase::Active
            );
        }
    }
}
