//! CLI re-export shim for the shared
//! [`astrid_uplink::AdminClient`](::astrid_uplink::admin_client::AdminClient).
//!
//! The CLI binds the admin client to the operator's active-agent
//! context — a fresh client per call, identical to the pre-refactor
//! behaviour.

pub(crate) use astrid_uplink::admin_client::{AdminClient, into_result};

use anyhow::{Context, Result};

/// Connect to the daemon as the currently active operator principal.
///
/// Single seam used by every `astrid agent / caps / quota / group /
/// invite` verb to construct a request-bound admin client without
/// each verb having to resolve `context::active_agent` itself.
///
/// # Errors
/// Returns an error if the active agent cannot be resolved, the
/// socket file is missing (no daemon), connection fails, or the
/// handshake is rejected.
pub(crate) async fn connect_as_active_agent() -> Result<AdminClient> {
    let caller =
        crate::context::active_agent().context("Failed to resolve active agent context")?;
    AdminClient::connect(caller).await
}
