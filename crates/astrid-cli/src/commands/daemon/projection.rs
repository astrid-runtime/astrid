//! Projection inspection and retirement under the shared lifecycle fences.

use anyhow::{Context, Result};
use astrid_core::dirs::AstridHome;

mod lifetime;
pub(crate) use lifetime::{DaemonLease, retain_ready_daemon};

/// Restore the projection and inspect it without allowing a CLI stop between
/// readiness and the read. Interactive approval must happen after this returns.
pub(crate) async fn with_persistent_daemon_projection<T>(
    label: &str,
    inspect: impl FnOnce() -> Result<T>,
) -> Result<(T, DaemonLease)> {
    let fence = super::acquire_daemon_start_fence().await?;
    // Retain an existing ephemeral daemon before ensure's probe disconnects.
    // A CLI start fence excludes stop, not autonomous last-client retirement.
    let probe =
        astrid_core::local_transport::connect_outcome(&crate::socket_client::proxy_socket_path())
            .await?;
    let lease = if matches!(
        probe,
        astrid_core::local_transport::ConnectOutcome::Connected(_)
    ) {
        Some(retain_ready_daemon().await?)
    } else {
        None
    };
    super::ensure_daemon_inner_locked(label, true, super::DaemonSpawnMode::Persistent, None)
        .await?;
    let lease = match lease {
        Some(lease) => lease,
        None => retain_ready_daemon().await?,
    };
    drop(probe);
    // Archive hashing is synchronous. Yield the runtime worker so the lease
    // continues draining broadcasts even on a single-worker CLI runtime.
    let result = tokio::task::block_in_place(|| inspect_while_fenced(fence, inspect));
    Ok((result?, lease))
}

fn inspect_while_fenced<T>(
    fence: std::sync::Arc<std::fs::File>,
    inspect: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let result = inspect();
    drop(fence);
    result
}

/// Refuse stale healing while a daemon is still retiring its host projection.
/// The caller holds the CLI start fence; the daemon owns the lifecycle fence
/// through runtime teardown, even after its socket/PID have disappeared.
pub(super) fn ensure_finalization_finished() -> Result<()> {
    let home = AstridHome::resolve()?;
    drop(
        astrid_storage::principal_state::RuntimeLifecycleGuard::acquire(&home)
            .context("daemon is still finalizing; retry start after it exits")?,
    );
    Ok(())
}

/// Finish natural MCP retirement without stopping an operator-owned daemon.
/// Recheck under the startup fence so a replacement cannot race the pack.
pub(crate) async fn retire_disconnected_projection(pid: Option<u32>) -> Result<()> {
    let Some(pid) = pid else {
        return Ok(());
    };
    if !crate::commands::daemon_control::wait_for_exit(pid, crate::commands::daemon_control::GRACE)
        .await
    {
        return Ok(());
    }
    let _fence = super::acquire_daemon_start_fence().await?;
    if super::recorded_daemon_pid_is_alive()
        || astrid_core::local_transport::endpoint_is_present(
            &crate::socket_client::proxy_socket_path(),
        )?
    {
        return Ok(());
    }
    pack_stopped_projection().await
}

/// Reopen the stopped volume, publish the final projection, and retire hosts.
pub(super) async fn pack_stopped_projection() -> Result<()> {
    let home =
        AstridHome::resolve().context("shutdown stage durable_projection_home_resolution")?;
    pack_stopped_projection_for_home(&home).await
}

/// Pack and retire one explicit isolated home during tests and stop handling.
pub(super) async fn pack_stopped_projection_for_home(home: &AstridHome) -> Result<()> {
    if !home
        .storage_volume_path()
        .try_exists()
        .context("shutdown stage durable_media_probe")?
    {
        return Ok(());
    }

    astrid_storage::principal_state::RuntimeLifecycleGuard::acquire(home)
        .context("shutdown stage durable_projection_fence")?
        .finish()
        .await
        .context("shutdown stage durable_projection_pack")
}

#[cfg(test)]
mod tests;
