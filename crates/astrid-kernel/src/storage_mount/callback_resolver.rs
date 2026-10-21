//! Keep OS-mediated `FSKit` container access off the asynchronous scheduler.

use std::path::PathBuf;

use astrid_core::storage_provider::StorageMountId;

pub(super) async fn resolve(mount_id: StorageMountId) -> Result<PathBuf, String> {
    resolve_with(move || astrid_core::fskit_socket::callback_path(mount_id)).await
}

async fn resolve_with(
    resolver: impl FnOnce() -> Result<PathBuf, String> + Send + 'static,
) -> Result<PathBuf, String> {
    // Opening an extension's container can wait for macOS privacy approval.
    // Preserve all canonical-path, ownership, mode and ACL checks, but do not
    // pin an async worker (and its queued admin/socket tasks) during that wait.
    // There is deliberately no detached timeout: the worker is read-only and
    // must finish before issuing a lease; runtime shutdown still joins it.
    tokio::task::spawn_blocking(resolver)
        .await
        .map_err(|error| format!("resolve FSKit callback container worker: {error}"))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test(flavor = "current_thread")]
    async fn permission_wait_does_not_block_other_async_requests() {
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let resolution = tokio::spawn(resolve_with(move || {
            let _ = entered_tx.send(());
            // Bound a failing inline implementation so the regression cannot
            // hang the test runtime indefinitely.
            release_rx
                .recv_timeout(Duration::from_secs(2))
                .map_err(|error| format!("async request could not release resolver: {error}"))?;
            Ok(PathBuf::from("validated-callback"))
        }));
        entered_rx.await.unwrap();
        // This represents independent admin work scheduled while the OS call
        // waits. An inline resolver cannot reach it before its wait expires.
        tokio::task::yield_now().await;
        release_tx.send(()).unwrap();
        assert_eq!(
            resolution.await.unwrap().unwrap(),
            PathBuf::from("validated-callback")
        );
    }

    #[tokio::test]
    async fn validation_failure_is_not_replaced_with_a_fallback() {
        let error = resolve_with(|| Err("private container validation rejected".to_owned()))
            .await
            .unwrap_err();
        assert_eq!(error, "private container validation rejected");
    }
}
