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
