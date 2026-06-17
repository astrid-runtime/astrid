//! CLI re-export shim for the shared
//! [`astrid_uplink::SocketClient`](::astrid_uplink::socket_client::SocketClient).
//!
//! Everything except the CLI-specific `send_input` resolution lives in
//! the shared crate now; this module keeps the historical import path
//! (`crate::socket_client::*`) working without churning every caller.

pub(crate) use astrid_uplink::socket_client::{
    SocketClient, pid_path, proxy_socket_path, readiness_path,
};

use anyhow::Result;

/// Send a user prompt over an established uplink.
///
/// The connection is already bound to the process principal (resolved
/// once at startup from `--principal` / `ASTRID_PRINCIPAL` / `default`),
/// so [`SocketClient::send_input`] stamps that identity — no per-call
/// resolution. Kept as a thin named seam so callers read intent
/// (`send_input_as_active_agent`) without re-resolving.
///
/// # Errors
/// Returns an error if the underlying send fails.
pub(crate) async fn send_input_as_active_agent(
    client: &mut SocketClient,
    text: String,
) -> Result<()> {
    client.send_input(text).await
}
