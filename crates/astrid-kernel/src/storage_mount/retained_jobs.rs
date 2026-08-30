//! Bounded cancellation and retained completion for callback filesystem work.

use std::path::Path;

use super::StorageMountLeaseState;

#[cfg(windows)]
const ENDPOINT_ABSENCE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

pub(super) async fn drain_accepted_tasks(state: &StorageMountLeaseState) -> bool {
    let mut tasks = state.accepted_tasks.lock().await;
    tasks.abort_all();
    let drain = async {
        while let Some(result) = tasks.join_next().await {
            let _ = result;
        }
    };
    if tokio::time::timeout(state.drain_timeouts().accepted_task, drain)
        .await
        .is_err()
    {
        tracing::warn!("storage mount accepted connection cancellation exceeded its drain bound");
        return false;
    }
    true
}

pub(super) async fn drain_blocking_jobs(state: &StorageMountLeaseState) -> bool {
    let mut jobs = state.blocking_jobs.lock().await;
    let drain = async {
        while let Some(result) = jobs.join_next().await {
            let _ = result;
        }
    };
    tokio::time::timeout(state.drain_timeouts().accepted_task, drain)
        .await
        .is_ok()
}

/// A drain timeout is not completion. Keep the revoked lease's admitted jobs
/// alive until their filesystem work and mutation fence finish, then let the
/// exact retry clean up the still-mapped resources.
pub(super) async fn finish_retained_jobs(state: &StorageMountLeaseState) {
    let mut tasks = state.accepted_tasks.lock().await;
    while let Some(result) = tasks.join_next().await {
        let _ = result;
    }
    drop(tasks);

    let mut jobs = state.blocking_jobs.lock().await;
    while let Some(result) = jobs.join_next().await {
        let _ = result;
    }
    drop(jobs);

    if endpoint_became_absent(&state.callback_path).await {
        state.listener_closed_tx.send_replace(true);
    }
}

#[cfg_attr(unix, allow(clippy::unused_async))]
pub(super) async fn endpoint_became_absent(callback_path: &Path) -> bool {
    #[cfg(unix)]
    {
        let _ = callback_path;
        true
    }
    #[cfg(not(unix))]
    {
        let wait = async {
            while astrid_core::local_transport::endpoint_is_present(callback_path).unwrap_or(true) {
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
        };
        tokio::time::timeout(ENDPOINT_ABSENCE_TIMEOUT, wait)
            .await
            .is_ok()
    }
}
