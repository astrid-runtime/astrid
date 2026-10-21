//! Explicit native administration and direct socket responder composition.

use anyhow::{Context, Result};
#[cfg(unix)]
use astrid_core::{
    PrincipalId,
    kernel_api::hosted_owner::{HostedOwnerRequest, HostedOwnerResponse},
};
use astrid_core::{dirs::AstridHome, identity::hosted_owner::HostedOwnerConfiguration};
use std::io::Read;
#[cfg(unix)]
use std::sync::Arc;

/// Offline ownership administration never shares the ordinary daemon boot path.
#[derive(clap::Args)]
pub struct AdministrationArgs {
    /// Explicit default execution target for offline owner policy configuration.
    #[arg(long, requires = "configure_hosted_owner")]
    pub owner_target_default: bool,
    /// Explicit controlling-account fresh provisioning policy, read from stdin.
    #[arg(long)]
    pub configure_hosted_owner: bool,
}

pub(super) async fn configure(home: &AstridHome, target_default: bool) -> Result<()> {
    // Match native IPC's 1 MiB payload ceiling. This also bounds JSON parsing
    // before any field-specific validation; it is not an operator policy knob.
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() <= 1024 * 1024,
        "public policy exceeds native payload limit"
    );
    let policy: HostedOwnerConfiguration =
        serde_json::from_slice(&bytes).context("invalid hosted policy")?;
    let record =
        astrid_kernel::Kernel::configure_native_hosted_owner(home, policy, target_default).await?;
    println!("{}", serde_json::to_string(&record)?);
    Ok(())
}

#[cfg(unix)]
pub(super) struct NativeOwnerResponder(pub(super) Arc<astrid_kernel::Kernel>);

#[cfg(unix)]
#[async_trait::async_trait]
impl astrid_uplink::native::hosted_owner::HostedOwnerResponder for NativeOwnerResponder {
    async fn respond(
        &self,
        principal: &PrincipalId,
        device_key_id: &str,
        request: HostedOwnerRequest,
    ) -> Result<HostedOwnerResponse, &'static str> {
        self.0
            .native_hosted_owner_request(principal, device_key_id, request)
            .await
    }
}
