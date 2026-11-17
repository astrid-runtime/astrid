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
async fn finalization_revokes_old_handles_before_host_pack() {
    let root = tempfile::tempdir().unwrap();
    let home = astrid_core::dirs::AstridHome::from_path(root.path());
    let lifecycle = astrid_storage::principal_state::RuntimeLifecycleGuard::acquire(&home).unwrap();
    let kernel = test_kernel_with_home(home.clone()).await;
    let content = kernel.principal_store.as_ref().unwrap().content();
    let name = astrid_storage::ContentName::new("capsules/handoff-test.wasm").unwrap();
    content
        .put(
            &astrid_storage::StateOwner::System,
            &name,
            b"durable capsule",
        )
        .unwrap();
    kernel
        .kv
        .set("shutdown-regression", "durable", b"committed".to_vec())
        .await
        .unwrap();
    let opened = content
        .open_read(&astrid_storage::StateOwner::System, &name)
        .unwrap()
        .unwrap();
    assert_eq!(opened.read().unwrap(), b"durable capsule");
    assert_eq!(
        kernel
            .kv
            .get("shutdown-regression", "durable")
            .await
            .unwrap(),
        Some(b"committed".to_vec())
    );
    let token = kernel.shutdown_for_finalization(None).await.unwrap();
    assert!(
        kernel
            .kv
            .get("shutdown-regression", "durable")
            .await
            .is_err(),
        "old KV reads must be revoked before the final pack"
    );
    assert!(
        kernel
            .kv
            .set("shutdown-regression", "late", b"forbidden".to_vec())
            .await
            .is_err()
    );
    assert!(
        content
            .read(&astrid_storage::StateOwner::System, &name)
            .is_err()
    );
    assert!(opened.read().is_err());
    assert!(
        content
            .put(&astrid_storage::StateOwner::System, &name, b"forbidden")
            .is_err()
    );
    // Closing a revoked projection must not release the new owner's volume.
    kernel.kv.close().await.unwrap();
    assert!(astrid_storage::volume::HostedFileVolume::open(home.storage_volume_path()).is_err());
    std::fs::write(home.root().join("config.toml"), b"final host state").unwrap();
    lifecycle.finish_retained(token).unwrap();
    let reopened = astrid_storage::open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    assert_eq!(
        reopened
            .kv()
            .get("shutdown-regression", "durable")
            .await
            .unwrap(),
        Some(b"committed".to_vec())
    );
    assert_eq!(
        reopened
            .kv()
            .get("shutdown-regression", "late")
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        reopened
            .content()
            .read(&astrid_storage::StateOwner::System, &name)
            .unwrap(),
        Some(b"durable capsule".to_vec())
    );
    assert_eq!(
        std::fs::read(home.root().join("config.toml")).unwrap(),
        b"final host state"
    );
    reopened.kv().close().await.unwrap();
}

#[tokio::test]
async fn retained_shutdown_joins_admitted_writers_and_revokes_former_handles() {
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
    // Admission is drained, and every old projection is now closed. Only
    // the distinct finalization owner retains the verified files and lock.
    assert!(
        kernel
            .kv
            .get("shutdown-regression", "admitted")
            .await
            .is_err()
    );
    kernel.kv.close().await.unwrap();
    assert!(astrid_storage::volume::HostedFileVolume::open(home.storage_volume_path()).is_err());
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

#[test]
fn retained_shutdown_defers_host_publication_until_runtime_writers_join() {
    let root = tempfile::tempdir().unwrap();
    let home = astrid_core::dirs::AstridHome::from_path(root.path());
    let lifecycle = astrid_storage::principal_state::RuntimeLifecycleGuard::acquire(&home).unwrap();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let (kernel, token) = runtime.block_on(async {
        let kernel = test_kernel_with_home(home.clone()).await;
        let path = home.root().join("etc/retained-final-publication.conf");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"before runtime teardown").unwrap();
        let name = astrid_storage::ContentName::new("etc/retained-final-publication.conf").unwrap();
        let store = kernel.principal_store.as_ref().unwrap();
        assert_eq!(
            store
                .content()
                .read(&astrid_storage::StateOwner::System, &name)
                .unwrap(),
            None
        );
        let (release, pending) = std::sync::mpsc::channel();
        tokio::task::spawn_blocking(move || {
            pending.recv().unwrap();
            std::fs::write(path, b"joined during runtime teardown").unwrap();
        });
        let token = kernel
            .shutdown_for_finalization(Some("single publication".into()))
            .await
            .unwrap();
        // Old projections are revoked immediately; they cannot inspect or
        // mutate the distinct finalizer's generation.
        let published = store
            .content()
            .read(&astrid_storage::StateOwner::System, &name);
        release.send(()).unwrap();
        assert!(published.is_err());
        (kernel, token)
    });
    drop(runtime);
    lifecycle.finish_retained(token).unwrap();
    assert!(
        !home
            .root()
            .join("etc/retained-final-publication.conf")
            .exists()
    );
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
            std::fs::read(home.root().join("etc/retained-final-publication.conf")).unwrap(),
            b"joined during runtime teardown"
        );
        reopened.kv().close().await.unwrap();
    });
}

#[tokio::test]
async fn abandoned_retained_shutdown_recovers_unpublished_host_writes() {
    let root = tempfile::tempdir().unwrap();
    let home = astrid_core::dirs::AstridHome::from_path(root.path());
    let lifecycle = astrid_storage::principal_state::RuntimeLifecycleGuard::acquire(&home).unwrap();
    let kernel = test_kernel_with_home(home.clone()).await;
    let path = home.root().join("etc/abandoned-finalization.conf");
    let name = astrid_storage::ContentName::new("etc/abandoned-finalization.conf").unwrap();
    std::fs::write(&path, b"recover without intermediate publication").unwrap();
    let token = kernel
        .shutdown_for_finalization(Some("abandoned finalizer".into()))
        .await
        .unwrap();
    assert!(
        kernel
            .principal_store
            .as_ref()
            .unwrap()
            .content()
            .read(&astrid_storage::StateOwner::System, &name)
            .is_err()
    );
    drop(token);
    assert!(kernel.kv.get("system:test", "late").await.is_err());
    assert_eq!(
        std::fs::read(&path).unwrap(),
        b"recover without intermediate publication"
    );
    drop(kernel);
    drop(lifecycle);
    let reopened = astrid_storage::open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    assert_eq!(
        reopened
            .content()
            .read(&astrid_storage::StateOwner::System, &name)
            .unwrap(),
        Some(b"recover without intermediate publication".to_vec())
    );
    assert_eq!(
        std::fs::read(&path).unwrap(),
        b"recover without intermediate publication"
    );
    reopened.kv().close().await.unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn retained_finalization_rejects_redirect_without_retiring_host_writes() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let home = astrid_core::dirs::AstridHome::from_path(root.path());
    let lifecycle = astrid_storage::principal_state::RuntimeLifecycleGuard::acquire(&home).unwrap();
    let kernel = test_kernel_with_home(home.clone()).await;
    let path = home.root().join("etc/unsafe-finalization.conf");
    std::fs::write(&path, b"preserve on failed finalization").unwrap();
    let redirect = home.root().join("redirect");
    std::os::unix::fs::symlink(outside.path(), &redirect).unwrap();
    let token = kernel
        .shutdown_for_finalization(Some("unsafe finalizer".into()))
        .await
        .unwrap();
    assert!(lifecycle.finish_retained(token).is_err());
    assert!(redirect.symlink_metadata().is_ok());
    assert_eq!(
        std::fs::read(&path).unwrap(),
        b"preserve on failed finalization"
    );
    assert!(kernel.kv.get("system:test", "late").await.is_err());
    drop(kernel);
    std::fs::remove_file(&redirect).unwrap();
    let reopened = astrid_storage::open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    assert_eq!(
        std::fs::read(&path).unwrap(),
        b"preserve on failed finalization"
    );
    reopened.kv().close().await.unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn shutdown_retires_only_boot_captured_runtime_files() {
    for retained in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let foreign = tempfile::tempdir().unwrap();
        let home = astrid_core::dirs::AstridHome::from_path(root.path());
        let lifecycle =
            astrid_storage::principal_state::RuntimeLifecycleGuard::acquire(&home).unwrap();
        let kernel = test_kernel_with_home(home).await;
        let socket = kernel.token_path.with_file_name("system.sock");
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        for name in ["system.token", "system.ready", "system.pid"] {
            std::fs::write(kernel.token_path.with_file_name(name), b"owned runtime").unwrap();
        }
        for name in ["system.sock", "system.token", "system.ready", "system.pid"] {
            std::fs::write(foreign.path().join(name), b"other runtime").unwrap();
        }

        if retained {
            let token = kernel.shutdown_for_finalization(None).await.unwrap();
            lifecycle.finish_retained(token).unwrap();
        } else {
            kernel.shutdown(None).await;
        }

        // The primary falsifier is removal of the captured files: ambient
        // ASTRID_HOME differs from this fixture. The independent root also
        // guards against collateral cleanup without mutating process-wide env.
        for name in ["system.sock", "system.token", "system.ready", "system.pid"] {
            assert!(
                !kernel.token_path.with_file_name(name).exists(),
                "shutdown must retire its captured {name}"
            );
            assert_eq!(
                std::fs::read(foreign.path().join(name)).unwrap(),
                b"other runtime",
                "shutdown must preserve another runtime's {name}"
            );
        }
        drop(listener);
    }
}
