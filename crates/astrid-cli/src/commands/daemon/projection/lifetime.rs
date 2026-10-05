//! A drained authenticated uplink pins an ephemeral daemon's lifetime.

use anyhow::Context as _;

pub(crate) struct DaemonLease {
    reader: tokio::task::JoinHandle<()>,
}

impl Drop for DaemonLease {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

/// Connect without ensuring readiness again: callers may hold the start fence.
pub(crate) async fn retain_ready_daemon() -> anyhow::Result<DaemonLease> {
    let mut client = crate::socket_client::connect_for_workspace(
        astrid_core::SessionId::from_uuid(uuid::Uuid::new_v4()),
        crate::principal::current(),
        None,
    )
    .await
    .context("could not retain the runtime connection")?;
    // Unread broadcasts fill the outbound queue and disconnect a passive lease.
    let reader =
        tokio::spawn(async move { while matches!(client.read_message().await, Ok(Some(_))) {} });
    Ok(DaemonLease { reader })
}
