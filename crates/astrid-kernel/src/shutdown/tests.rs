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
    let owner = store.handoff_for_finalization(&home).unwrap();
    let mut outcome = Ok(ShutdownCustody::Immediate(owner));
    record_close_error(
        &mut outcome,
        StorageError::Internal("injected KV close error".into()),
    );
    record_close_error(
        &mut outcome,
        StorageError::Internal("injected audit close error".into()),
    );
    assert!(RuntimeLifecycleGuard::acquire(&home).is_err());
    let Ok(ShutdownCustody::Immediate(owner)) = outcome else {
        panic!("close error discarded retirement custody");
    };
    std::fs::write(home.root().join("config.toml"), b"final write").unwrap();
    let error = guard.finish_retained(owner).unwrap_err();
    assert!(error.to_string().contains("injected KV close error"));
    assert!(error.to_string().contains("injected audit close error"));
    assert!(!home.root().join("config.toml").exists());
}

#[test]
fn close_error_preserves_the_prior_finalization_failure() {
    let mut outcome = Err(StorageError::Internal("injected handoff failure".into()));
    record_close_error(
        &mut outcome,
        StorageError::Internal("injected later close failure".into()),
    );
    let Err(error) = outcome else {
        panic!("close error discarded the finalization failure");
    };
    let message = error.to_string();
    assert!(message.contains("injected handoff failure"));
    assert!(message.contains("injected later close failure"));
}

#[tokio::test]
async fn shutdown_watch_is_sticky_for_late_subscribers() {
    let (tx, mut early) = tokio::sync::watch::channel(false);
    tx.send_replace(true);
    assert!(*early.borrow());
    // A subscriber created after the replace must still observe shutdown.
    let mut late = tx.subscribe();
    assert!(*late.borrow());
    let mut late_wait = std::pin::pin!(late.wait_for(|requested| *requested));
    assert!(
        matches!(
            std::future::Future::poll(
                late_wait.as_mut(),
                &mut std::task::Context::from_waker(std::task::Waker::noop())
            ),
            std::task::Poll::Ready(_)
        ),
        "sticky watch must not lose a shutdown published before park"
    );
    let mut early_wait = std::pin::pin!(early.wait_for(|requested| *requested));
    assert!(matches!(
        std::future::Future::poll(
            early_wait.as_mut(),
            &mut std::task::Context::from_waker(std::task::Waker::noop())
        ),
        std::task::Poll::Ready(_)
    ));
}

#[tokio::test]
async fn retain_pending_keeps_engine_open_until_explicit_handoff() {
    use astrid_storage::principal_state::RuntimeLifecycleGuard;
    use astrid_storage::{KvQuotaResolver, StateOwner, open_runtime_principal_store};
    use std::sync::Arc;

    let parent = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(parent.path().join("runtime"));
    let lifecycle = RuntimeLifecycleGuard::acquire(&home).unwrap();
    let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|_: &StateOwner| Ok(None));
    let store = open_runtime_principal_store(&home, quota).await.unwrap();
    store
        .kv()
        .set("system:retirement", "pending", b"open".to_vec())
        .await
        .unwrap();
    store.publish_runtime_projection(&home).unwrap();

    let pending = store.retain_for_finalization(&home).unwrap();
    // Immediate path remains available and still revokes old handles.
    // Pending custody itself must not revoke before handoff.
    assert_eq!(
        store
            .kv()
            .get("system:retirement", "pending")
            .await
            .unwrap(),
        Some(b"open".to_vec())
    );
    let owner = pending.handoff_for_finalization().unwrap();
    assert!(
        store
            .kv()
            .get("system:retirement", "pending")
            .await
            .is_err()
    );
    lifecycle.finish_retained(owner).unwrap();
}

#[tokio::test]
async fn pending_close_helper_skips_kv_poll_records_audit_error_and_packs() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::Poll;

    use astrid_audit::AuditError;

    let parent = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(parent.path().join("runtime"));
    let lifecycle = RuntimeLifecycleGuard::acquire(&home).unwrap();
    let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|_: &StateOwner| Ok(None));
    let store = open_runtime_principal_store(&home, Arc::clone(&quota))
        .await
        .unwrap();
    store
        .kv()
        .set("system:retirement", "pending-audit", b"open".to_vec())
        .await
        .unwrap();
    store.publish_runtime_projection(&home).unwrap();
    std::fs::write(home.root().join("config.toml"), b"late host write").unwrap();

    let pending = store.retain_for_finalization(&home).unwrap();
    let mut custody = Ok(ShutdownCustody::Pending(pending));

    let kv_polled = AtomicBool::new(false);
    let kv_close = std::future::poll_fn(|_cx| {
        kv_polled.store(true, Ordering::SeqCst);
        Poll::Ready(Ok(()))
    });
    let audit_close = async {
        Err::<(), _>(AuditError::StorageError(
            "injected audit close failure".into(),
        ))
    };

    close_shutdown_projections(
        StoreShutdown::RetainPending,
        &mut custody,
        kv_close,
        audit_close,
    )
    .await;

    assert!(
        !kv_polled.load(Ordering::SeqCst),
        "RetainPending must not poll the KV close future"
    );

    let Ok(ShutdownCustody::Pending(pending)) = custody else {
        panic!("pending custody discarded by ancillary audit close error");
    };
    assert_eq!(
        store
            .kv()
            .get("system:retirement", "pending-audit")
            .await
            .unwrap(),
        Some(b"open".to_vec()),
        "pending mode must keep the authoritative engine open"
    );

    let owner = pending.handoff_for_finalization().unwrap();
    let error = lifecycle
        .finish_retained(owner)
        .expect_err("audit close failure must surface after pack");
    let message = error.to_string();
    assert!(
        message.contains("injected audit close failure"),
        "missing audit close failure: {message}"
    );
    assert!(
        message.contains("close audit log during shutdown"),
        "audit close must be recorded through the production wrapper: {message}"
    );
    assert!(
        message.contains("durable home packed and closed")
            || message.contains("earlier shutdown failed"),
        "pack must complete before reporting the ancillary error: {message}"
    );
    assert!(
        !home.root().join("config.toml").exists(),
        "late host write must be packed and retired"
    );
    let reopened = open_runtime_principal_store(&home, quota).await.unwrap();
    assert_eq!(
        std::fs::read(home.root().join("config.toml")).unwrap(),
        b"late host write"
    );
    assert_eq!(
        reopened
            .kv()
            .get("system:retirement", "pending-audit")
            .await
            .unwrap(),
        Some(b"open".to_vec())
    );
}
