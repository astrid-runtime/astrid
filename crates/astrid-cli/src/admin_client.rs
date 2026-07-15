//! Workspace-checked CLI wrapper for the shared
//! [`astrid_uplink::AdminClient`](::astrid_uplink::admin_client::AdminClient).
//!
//! The CLI binds the admin client to the process-wide principal
//! (resolved once at startup from `--principal` / `ASTRID_PRINCIPAL` /
//! `default`) — a fresh client per call, all stamping one identity.

pub(crate) use astrid_uplink::admin_client::into_result;

use anyhow::Result;
use astrid_core::kernel_api::{AdminRequestKind, AdminResponseBody};
use astrid_uplink::admin_client::AdminClient as UplinkAdminClient;

/// Admin request surface available to CLI commands.
///
/// Construction stays private to this module so command code cannot bypass
/// the selected-workspace checks in [`connect_for_workspace_as`].
pub(crate) struct AdminClient(UplinkAdminClient);

impl AdminClient {
    pub(crate) async fn request(&mut self, kind: AdminRequestKind) -> Result<AdminResponseBody> {
        self.0.request(kind).await
    }
}

/// Connect to the daemon as the process principal.
///
/// Single seam used by every `astrid agent / caps / quota / group /
/// invite` verb to construct a request-bound admin client without each
/// verb resolving the principal itself. The bound principal is the
/// one resolved at startup (`crate::principal::current`), so every
/// admin request this process sends attributes to one identity — the
/// uplink proxy pins the first principal per connection and drops
/// mismatches.
///
/// # Errors
/// Returns an error if the socket file is missing (no daemon),
/// connection fails, or the handshake is rejected.
pub(crate) async fn connect_as_active_agent() -> Result<AdminClient> {
    connect_for_workspace_as(crate::principal::current()).await
}

/// Connect an admin client as an explicit caller after verifying the selected
/// workspace on both sides of the daemon handshake.
///
/// Invite redemption uses the default principal because the invite token is
/// the authentication credential; the workspace boundary still applies.
pub(crate) async fn connect_for_workspace_as(
    caller: astrid_core::PrincipalId,
) -> Result<AdminClient> {
    let client =
        crate::socket_client::connect_workspace_client(None, || UplinkAdminClient::connect(caller))
            .await?;
    Ok(AdminClient(client))
}
