//! An error after handoff must not replace exclusive retirement custody.
use super::*;
use astrid_core::dirs::AstridHome;
use astrid_storage::principal_state::RuntimeLifecycleGuard;
use astrid_storage::{KvQuotaResolver, StateOwner, StorageError, open_runtime_principal_store};

#[tokio::test]
async fn close_errors_retain_transferred_owner_until_finalization() {
    let parent = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(parent.path().join("runtime"));
    let guard = RuntimeLifecycleGuard::acquire(&home).unwrap();
    let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|_: &StateOwner| Ok(None));
    let store = open_runtime_principal_store(&home, quota).await.unwrap();
    store.publish_runtime_projection(&home).unwrap();
    let owner = store.handoff_for_retirement(&home).unwrap();
    let mut outcome = Ok(ShutdownOutcome::Retirement(owner));
    record_close_error(
        &mut outcome,
        StorageError::Internal("injected KV close error".into()),
    );
    record_close_error(
        &mut outcome,
        StorageError::Internal("injected audit close error".into()),
    );
    assert!(RuntimeLifecycleGuard::acquire(&home).is_err());
    let Ok(ShutdownOutcome::Retirement(owner)) = outcome else {
        panic!("close error discarded retirement custody");
    };
    std::fs::write(home.root().join("config.toml"), b"final write").unwrap();
    let error = guard.finish_with_owner(owner).unwrap_err();
    assert!(error.to_string().contains("injected KV close error"));
    assert!(!home.root().join("config.toml").exists());
}
