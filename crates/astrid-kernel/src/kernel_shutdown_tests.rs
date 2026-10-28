//! Focused lifecycle tests for durable projection publication at shutdown.

use super::{Kernel, test_kernel_with_home};

#[tokio::test]
async fn graceful_shutdown_publishes_final_running_projection() {
    let root = tempfile::tempdir().unwrap();
    let home = astrid_core::dirs::AstridHome::from_path(root.path());
    let kernel: std::sync::Arc<Kernel> = test_kernel_with_home(home.clone()).await;

    let log_path = home.root().join("log/daemon.log");
    std::fs::create_dir_all(log_path.parent().unwrap()).unwrap();
    std::fs::write(&log_path, b"generation-1\ngeneration-2\n").unwrap();

    kernel.shutdown(Some("test".to_owned())).await;
    assert_eq!(
        std::fs::read(&log_path).unwrap(),
        b"generation-1\ngeneration-2\n"
    );
    drop(kernel);

    let reopened = astrid_storage::open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    assert_eq!(
        std::fs::read(&log_path).unwrap(),
        b"generation-1\ngeneration-2\n"
    );
    reopened.kv().close().await.unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn failed_shutdown_publication_retains_host_projection_for_recovery() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    let home = astrid_core::dirs::AstridHome::from_path(root.path());
    let kernel = test_kernel_with_home(home.clone()).await;

    let log_path = home.root().join("log/daemon.log");
    let config_path = home.root().join("etc/authz.conf");
    std::fs::create_dir_all(log_path.parent().unwrap()).unwrap();
    std::fs::write(&log_path, b"generation-1\ngeneration-2\n").unwrap();
    std::fs::write(&config_path, b"allow=generation-2\n").unwrap();
    let outside = tempfile::tempdir().unwrap();
    let redirect = home.root().join("redirect");
    symlink(outside.path(), &redirect).unwrap();

    // `Kernel::shutdown` is intentionally infallible; admission must fail
    // without retiring or claiming the still-hosted projection.
    kernel.shutdown(Some("test".to_owned())).await;
    assert!(redirect.symlink_metadata().is_ok());
    assert_eq!(
        std::fs::read(&log_path).unwrap(),
        b"generation-1\ngeneration-2\n"
    );
    assert_eq!(
        std::fs::read(&config_path).unwrap(),
        b"allow=generation-2\n"
    );
    drop(kernel);

    std::fs::remove_file(&redirect).unwrap();
    let recovered = astrid_storage::open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    assert_eq!(
        std::fs::read(&log_path).unwrap(),
        b"generation-1\ngeneration-2\n"
    );
    assert_eq!(
        std::fs::read(&config_path).unwrap(),
        b"allow=generation-2\n"
    );
    recovered.kv().close().await.unwrap();
}

fn unlimited_quota()
-> std::sync::Arc<dyn astrid_storage::KvQuotaResolver<astrid_storage::StateOwner>> {
    std::sync::Arc::new(|owner: &astrid_storage::StateOwner| {
        Ok(match owner {
            astrid_storage::StateOwner::System => None,
            astrid_storage::StateOwner::Principal(_) | astrid_storage::StateOwner::Fleet(_) => {
                Some(u64::MAX)
            },
        })
    })
}

#[tokio::test]
async fn shutdown_joins_admitted_writers_before_closing_storage() {
    let root = tempfile::tempdir().unwrap();
    let home = astrid_core::dirs::AstridHome::from_path(root.path());
    let kernel = test_kernel_with_home(home).await;
    let writer = kernel.runtime_work.admit().unwrap();
    let mut shutdown = Box::pin(kernel.shutdown(Some("writer barrier".into())));
    assert!(
        std::future::Future::poll(
            shutdown.as_mut(),
            &mut std::task::Context::from_waker(std::task::Waker::noop())
        )
        .is_pending()
    );
    assert!(kernel.runtime_work.admit().is_none());
    kernel
        .kv
        .set("shutdown-regression", "admitted", b"committed".to_vec())
        .await
        .unwrap();
    drop(writer);
    shutdown.await;
    // Retaining the closed kernel/store must not retain a strong hosted-volume
    // handle: explicit close releases file ownership immediately.
    assert!(
        astrid_storage::volume::HostedFileVolume::open(kernel.astrid_home.storage_volume_path())
            .is_ok()
    );
    assert!(
        kernel
            .kv
            .set("shutdown-regression", "late", b"rejected".to_vec())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn closed_lifecycle_rejects_health_restart_before_registry_or_storage_access() {
    let root = tempfile::tempdir().unwrap();
    let home = astrid_core::dirs::AstridHome::from_path(root.path());
    let kernel = test_kernel_with_home(home).await;
    kernel.runtime_work.close().await;
    let id = astrid_capsule_types::CapsuleId::new("not-loaded").unwrap();
    let error = kernel
        .restart_capsule(&id, &astrid_core::PrincipalId::default(), None)
        .await
        .unwrap_err();
    assert_eq!(error.to_string(), "runtime is shutting down");
    kernel.shutdown(Some("closed restart".into())).await;
}

mod idle_dispatcher;

#[tokio::test]
async fn retained_shutdown_joins_admitted_writers_and_closes_only_at_finalization() {
    let root = tempfile::tempdir().unwrap();
    let home = astrid_core::dirs::AstridHome::from_path(root.path());
    let lifecycle = astrid_storage::principal_state::RuntimeLifecycleGuard::acquire(&home).unwrap();
    let kernel = test_kernel_with_home(home.clone()).await;
    let writer = kernel.runtime_work.admit().unwrap();
    let mut shutdown = Box::pin(kernel.shutdown_for_finalization(Some("writer barrier".into())));
    assert!(
        std::future::Future::poll(
            shutdown.as_mut(),
            &mut std::task::Context::from_waker(std::task::Waker::noop())
        )
        .is_pending()
    );
    assert!(kernel.runtime_work.admit().is_none());
    kernel
        .kv
        .set("shutdown-regression", "admitted", b"committed".to_vec())
        .await
        .unwrap();
    drop(writer);
    let token = shutdown.await.unwrap();
    // All engine projections, including audit, must leave the authority open
    // for the host's final pack rather than trigger a second recovery.
    assert_eq!(
        kernel
            .kv
            .get("shutdown-regression", "admitted")
            .await
            .unwrap(),
        Some(b"committed".to_vec())
    );
    lifecycle.finish_retained(token).unwrap();
    assert!(
        kernel
            .kv
            .set("shutdown-regression", "late", b"rejected".to_vec())
            .await
            .is_err()
    );
    let reopened = astrid_storage::open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    assert_eq!(
        reopened
            .kv()
            .get("shutdown-regression", "admitted")
            .await
            .unwrap(),
        Some(b"committed".to_vec())
    );
    reopened.kv().close().await.unwrap();
}

#[test]
fn retained_shutdown_packs_host_write_joined_by_original_runtime_drop() {
    let root = tempfile::tempdir().unwrap();
    let home = astrid_core::dirs::AstridHome::from_path(root.path());
    let lifecycle = astrid_storage::principal_state::RuntimeLifecycleGuard::acquire(&home).unwrap();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let (kernel, token) = runtime.block_on(async {
        let kernel = test_kernel_with_home(home.clone()).await;
        let log = home.root().join("log/daemon.log");
        std::fs::create_dir_all(log.parent().unwrap()).unwrap();
        std::fs::write(&log, b"before shutdown").unwrap();
        let (release, pending) = std::sync::mpsc::channel();
        // Deliberately not awaited: the host runtime's destructor must join
        // this writer before finalization can retire its path.
        tokio::task::spawn_blocking(move || {
            pending.recv().unwrap();
            std::fs::write(log, b"joined during runtime drop").unwrap();
        });
        let token = kernel
            .shutdown_for_finalization(Some("runtime join".into()))
            .await
            .unwrap();
        release.send(()).unwrap();
        (kernel, token)
    });
    drop(runtime);
    lifecycle.finish_retained(token).unwrap();
    assert!(!home.root().join("log/daemon.log").exists());
    let recovery = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    recovery.block_on(async {
        assert!(kernel.kv.get("system:test", "late").await.is_err());
        let reopened = astrid_storage::open_runtime_principal_store(&home, unlimited_quota())
            .await
            .unwrap();
        assert_eq!(
            std::fs::read(home.root().join("log/daemon.log")).unwrap(),
            b"joined during runtime drop"
        );
        reopened.kv().close().await.unwrap();
    });
}
