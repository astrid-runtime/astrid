//! Recovery must not reinterpret a cut-over home as a fresh initialization.

use super::*;
use astrid_storage::{ContentName, KvQuotaResolver, StateOwner, open_runtime_principal_store};

#[tokio::test]
async fn recovered_v2_layout_requires_its_complete_volume_owned_migration_ledger() {
    for case in [
        "missing",
        "incomplete",
        "corrupt",
        "missing-provenance",
        "complete",
    ] {
        let root = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(root.path());
        let quota = interrupted_home(&home, case).await;
        let admission = crate::home_admission::validate(&home).unwrap();
        assert!(matches!(
            admission,
            crate::home_admission::HomeAdmission::Retiring
        ));
        let result = admission
            .open_store(&home, quota, PrincipalDirectory::default())
            .await;
        if case == "complete" {
            let reopened = result.unwrap();
            reject_incomplete_layout_v2(&home).unwrap();
            assert_eq!(
                std::fs::read(home.keys_dir().join("runtime.key")).unwrap(),
                [7; 32]
            );
            drop(reopened);
        } else {
            let error = result
                .err()
                .expect("an incomplete existing layout cannot initialize afresh");
            assert!(
                error.to_string().contains(if case == "missing" {
                    "ledger is missing"
                } else if case == "incomplete" {
                    "ledger is incomplete"
                } else if case == "missing-provenance" {
                    "no durable cutover record"
                } else {
                    "ledger"
                }),
                "{case}: {error}"
            );
        }
    }
}

async fn interrupted_home(home: &AstridHome, case: &str) -> Arc<dyn KvQuotaResolver<StateOwner>> {
    home.ensure().unwrap();
    let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|_: &StateOwner| Ok(None));
    let store = open_runtime_principal_store(home, Arc::clone(&quota))
        .await
        .unwrap();
    astrid_core::platform_fs::ensure_private_directory(&home.keys_dir()).unwrap();
    astrid_core::platform_fs::atomic_write_private_file(
        &home.keys_dir().join("runtime.key"),
        &[7; 32],
    )
    .unwrap();
    astrid_core::platform_fs::ensure_private_directory(&home.log_dir()).unwrap();
    astrid_core::platform_fs::atomic_write_private_file(
        &home.log_dir().join("audit"),
        b"retirement recovery fixture",
    )
    .unwrap();
    if case != "missing" {
        let mut ledger = tests::fresh_retirement_ledger(SourceIdentity::absent());
        if case == "incomplete" {
            ledger.complete = false;
        }
        if case == "missing-provenance" {
            ledger
                .components
                .retain(|component| component.name != "system:fresh-layout");
        }
        let bytes = if case == "corrupt" {
            b"invalid ledger".to_vec()
        } else {
            canonical_json(&ledger).unwrap()
        };
        astrid_core::platform_fs::ensure_private_directory(&home.migrations_dir()).unwrap();
        astrid_core::platform_fs::atomic_write_private_file(&ledger_path(home), &bytes).unwrap();
    }
    store.publish_runtime_projection(home).unwrap();
    // Model the durable RETIRING publication with the exact inventoried
    // objects, then an interrupted unlink of the sentinel and ledger tree.
    let name = ContentName::new("run/.active-projection-v1.json").unwrap();
    let mut receipt: serde_json::Value = serde_json::from_slice(
        &store
            .content()
            .read(&StateOwner::System, &name)
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    receipt["phase"] = serde_json::json!("retiring");
    store
        .content()
        .put(
            &StateOwner::System,
            &name,
            &serde_json::to_vec(&receipt).unwrap(),
        )
        .unwrap();
    store.content().flush().unwrap();
    drop(store);
    std::fs::remove_dir_all(home.etc_dir()).unwrap();
    std::fs::remove_dir_all(home.var_dir()).unwrap();
    quota
}
