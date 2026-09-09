//! Recovery retirement after an already-dead daemon, using the shared finalizer.

use anyhow::{Context, Result};
use astrid_core::dirs::AstridHome;

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
