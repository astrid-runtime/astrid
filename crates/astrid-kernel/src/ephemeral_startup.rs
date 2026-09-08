//! The readiness-to-client handoff owns the existing startup grace even when
//! launchers briefly connect for metadata before attaching their lasting uplink.
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use super::Kernel;

pub(super) fn spawn_ephemeral_startup_fallback(
    kernel: Arc<Kernel>,
    grace: Duration,
) -> astrid_runtime::JoinHandle<()> {
    kernel
        .ephemeral_startup_pending
        .store(true, Ordering::Release);
    astrid_runtime::spawn(async move {
        astrid_runtime::time::sleep(grace).await;
        kernel
            .ephemeral_startup_pending
            .store(false, Ordering::Release);
        kernel.request_ephemeral_shutdown_if_idle();
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn preflight_disconnect_does_not_consume_startup_grace() {
        let root = tempfile::tempdir().unwrap();
        let home = astrid_core::dirs::AstridHome::from_path(root.path());
        let kernel = crate::test_kernel_with_home(home).await;
        let principal = astrid_core::PrincipalId::new("operator").unwrap();
        kernel.set_ephemeral(true);
        let shutdown = kernel.shutdown_tx.subscribe();
        let fallback =
            spawn_ephemeral_startup_fallback(Arc::clone(&kernel), Duration::from_millis(50));
        kernel.connection_opened(&principal);
        kernel.connection_closed(&principal);
        assert!(
            !*shutdown.borrow(),
            "preflight is not the lasting host connection"
        );
        fallback.await.unwrap();
        assert!(
            *shutdown.borrow(),
            "an unused startup still retires after grace"
        );
    }

    #[tokio::test]
    async fn connected_host_outlives_startup_grace() {
        let root = tempfile::tempdir().unwrap();
        let home = astrid_core::dirs::AstridHome::from_path(root.path());
        let kernel = crate::test_kernel_with_home(home).await;
        let principal = astrid_core::PrincipalId::new("codex-code").unwrap();
        kernel.set_ephemeral(true);
        let shutdown = kernel.shutdown_tx.subscribe();
        let fallback =
            spawn_ephemeral_startup_fallback(Arc::clone(&kernel), Duration::from_millis(1));
        kernel.connection_opened(&principal);
        fallback.await.unwrap();
        assert!(!*shutdown.borrow());
        kernel.connection_closed(&principal);
        assert!(*shutdown.borrow());
    }
}
