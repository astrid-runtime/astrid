//! CLI re-export shim for the shared
//! [`astrid_uplink::SocketClient`](::astrid_uplink::socket_client::SocketClient).
//!
//! Everything except the CLI-specific `send_input` resolution lives in
//! the shared crate now; this module keeps the historical import path
//! (`crate::socket_client::*`) working without churning every caller.

pub(crate) use astrid_uplink::socket_client::{SocketClient, proxy_socket_path, readiness_path};

use anyhow::{Context, Result};

/// Convenience wrapper around [`SocketClient::send_input`] that pulls
/// the operator's active agent from `~/.astrid/run/cli-context.toml`.
///
/// Solo self-hosters with no active-agent context file fall back to
/// `default`, matching the historical CLI behaviour.
///
/// # Errors
/// Returns an error if the active-agent context cannot be resolved or
/// the underlying send fails.
pub(crate) async fn send_input_as_active_agent(
    client: &mut SocketClient,
    text: String,
) -> Result<()> {
    let caller =
        crate::context::active_agent().context("Failed to resolve active agent context")?;
    client.send_input(text, &caller).await
}
