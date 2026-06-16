//! CLI re-export shim for the shared
//! [`astrid_uplink::AdminClient`](::astrid_uplink::admin_client::AdminClient).
//!
//! The CLI binds the admin client to the process-wide principal
//! (resolved once at startup from `--principal` / `ASTRID_PRINCIPAL` /
//! `default`) — a fresh client per call, all stamping one identity.

pub(crate) use astrid_uplink::admin_client::{AdminClient, into_result};

use anyhow::Result;

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
    AdminClient::connect(crate::principal::current()).await
}
