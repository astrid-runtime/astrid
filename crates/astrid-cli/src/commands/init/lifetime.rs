//! Keep provisioning and its caller's post-install operations in one lifetime.

use anyhow::Context as _;

pub(crate) use crate::commands::daemon::projection::DaemonLease as ProvisioningLease;

pub(super) async fn retain_daemon() -> anyhow::Result<ProvisioningLease> {
    // The kernel must admit a fresh home and publish its migration ledger
    // before the CLI creates any v2 layout state. Init spans multiple admin
    // connections, so its daemon must remain alive between those requests.
    crate::commands::daemon::ensure_persistent_daemon("init")
        .await
        .context("init could not ensure the runtime daemon")?;
    // An existing daemon can be ephemeral. Return the connection to the caller
    // so even post-init self-grants finish before the final lease is dropped.
    crate::commands::daemon::projection::retain_ready_daemon()
        .await
        .context("init could not retain its runtime connection")
}
