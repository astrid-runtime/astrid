//! Keep provisioning and its caller's post-install operations in one lifetime.

use anyhow::Context as _;

pub(crate) struct ProvisioningLease {
    reader: tokio::task::JoinHandle<()>,
}

impl Drop for ProvisioningLease {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

pub(super) async fn retain_daemon() -> anyhow::Result<ProvisioningLease> {
    // The kernel must admit a fresh home and publish its migration ledger
    // before the CLI creates any v2 layout state. Init spans multiple admin
    // connections, so its daemon must remain alive between those requests.
    crate::commands::daemon::ensure_persistent_daemon("init")
        .await
        .context("init could not ensure the runtime daemon")?;
    // An existing daemon can be ephemeral. Return the connection to the caller
    // so even post-init self-grants finish before the final lease is dropped.
    let mut client = crate::socket_client::connect_for_workspace(
        astrid_core::SessionId::from_uuid(uuid::Uuid::new_v4()),
        crate::principal::current(),
        None,
    )
    .await
    .context("init could not retain its runtime connection")?;
    // The uplink receives broadcasts while capsules install. An unread socket
    // fills its outbound queue and is disconnected, defeating a passive lease.
    let reader =
        tokio::spawn(async move { while matches!(client.read_message().await, Ok(Some(_))) {} });
    Ok(ProvisioningLease { reader })
}
