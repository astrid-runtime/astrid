use std::sync::Arc;

use super::*;
use crate::principal_state::runtime_tree::{
    ReceiptPhase, publish_active_projection, transition_retiring_projection,
};
use crate::{KvQuotaResolver, StateOwner, open_runtime_principal_store};

async fn retiring_fixture() -> (tempfile::TempDir, AstridHome, RuntimePrincipalStore) {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path().join("home"));
    let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|_: &StateOwner| Ok(None));
    let store = open_runtime_principal_store(&home, quota).await.unwrap();
    std::fs::create_dir_all(home.root().join("etc")).unwrap();
    std::fs::write(home.root().join("etc/receipted.conf"), b"published").unwrap();
    publish_active_projection(&home, &store).unwrap();
    transition_retiring_projection(&home, &store).unwrap();
    (directory, home, store)
}

fn require_retiring_receipt(home: &AstridHome, store: &RuntimePrincipalStore) {
    assert_eq!(
        active::read(home, store).unwrap().unwrap().phase(),
        ReceiptPhase::Retiring
    );
}

#[tokio::test]
async fn late_file_before_core_preflight_never_acquires_retirement_authority() {
    for relative in ["late", "late-dir/child", "etc/late", "etc/late-dir/child"] {
        let (_directory, home, store) = retiring_fixture().await;
        let extra = home.root().join(relative);
        let error = retire_current_with_hook(&home, &store, || {
            std::fs::create_dir_all(extra.parent().unwrap()).unwrap();
            std::fs::write(&extra, b"unreceipted").unwrap();
            Ok(())
        })
        .unwrap_err();
        assert!(
            error.to_string().contains("unreceipted host file"),
            "{error}"
        );
        assert_eq!(std::fs::read(extra).unwrap(), b"unreceipted");
        assert!(home.root().join("etc/receipted.conf").exists());
        require_retiring_receipt(&home, &store);
    }
}

#[tokio::test]
async fn replacement_before_preflight_cannot_replace_engine_held_survivor() {
    let (directory, home, store) = retiring_fixture().await;
    let volume = home.storage_volume_path();
    let retained = directory.path().join("retained.volume");
    let error = retire_current_with_hook(&home, &store, || {
        std::fs::rename(&volume, &retained).unwrap();
        std::fs::write(&volume, b"replacement").unwrap();
        Ok(())
    })
    .unwrap_err();
    assert!(error.to_string().contains("identity"), "{error}");
    assert!(retained.is_file());
    assert_eq!(std::fs::read(volume).unwrap(), b"replacement");
    assert!(home.root().join("etc/receipted.conf").exists());
    require_retiring_receipt(&home, &store);
}

#[tokio::test]
async fn captured_receipted_projection_retires_and_keeps_durable_receipt_for_caller() {
    let (_directory, home, store) = retiring_fixture().await;
    retire_current_projection(&home, &store).unwrap();
    let names = std::fs::read_dir(home.root())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    assert_eq!(names, [std::ffi::OsString::from("astrid.volume")]);
    require_retiring_receipt(&home, &store);
}

#[tokio::test]
async fn legacy_retirement_accepts_published_sources_omitted_from_current_projection() {
    let (_directory, home, store) = retiring_fixture().await;
    let source = home.state_db_path();
    std::fs::create_dir_all(source.parent().unwrap()).unwrap();
    std::fs::write(&source, b"published legacy state").unwrap();
    let name = content_name_from_relative(&source, home.root()).unwrap();
    assert!(super::super::is_retired_legacy_projection(
        &home,
        name.as_str()
    ));
    store
        .content()
        .put(&StateOwner::System, &name, b"published legacy state")
        .unwrap();
    store.content().flush().unwrap();
    retire_legacy_projection(&home, &store).unwrap();
    assert!(!source.exists());
    assert_eq!(
        store.content().read(&StateOwner::System, &name).unwrap(),
        Some(b"published legacy state".to_vec())
    );
}
