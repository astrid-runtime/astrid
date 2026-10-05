//! Keep provisioning and its caller's post-install operations in one lifetime.

use anyhow::Context as _;

pub(crate) use crate::commands::daemon::projection::DaemonLease as ProvisioningLease;

pub(super) async fn retain_daemon() -> anyhow::Result<ProvisioningLease> {
    // The kernel must admit a fresh home and publish its migration ledger
    // before the CLI creates any v2 layout state. Init spans multiple admin
    // connections, so its daemon must remain alive between those requests.
    // Acquire an existing daemon's lease before readiness probes disconnect,
    // using the same fenced handoff as install-authority inspection. Return it
    // so even post-init self-grants finish before the final lease is dropped.
    let ((), lease) = crate::commands::daemon::with_persistent_daemon_projection("init", || Ok(()))
        .await
        .context("init could not retain its runtime connection")?;
    Ok(lease)
}
