//! HTTP gateway for the Astrid admin API (issue #756).
//!
//! Translates HTTP requests into kernel IPC messages over the same
//! Unix-domain socket the CLI uses. The gateway is an uplink — it
//! reads `~/.astrid/run/system.token`, handshakes with the daemon,
//! and stamps every outbound message with the principal it
//! cryptographically verified on the inbound bearer.
//!
//! ## Trust shape
//!
//! Two facts make the gateway safe:
//!
//! * **Socket access is OS-gated.** Only the user that owns the
//!   daemon (and therefore the 0600 `system.token`) can connect at
//!   all. The gateway process inherits that posture.
//! * **HTTP principal claims are never trusted directly.** The
//!   gateway verifies the inbound `Authorization: Bearer ...` token
//!   against its boot-time ed25519 signing key, extracts the
//!   already-bound principal, and only THEN stamps it on the outbound
//!   `IpcMessage.principal`. The request body cannot influence the
//!   stamped principal.
//!
//! The kernel's existing Layer 5/6 capability gate does the rest.
//!
//! ## What this crate ships
//!
//! v1 implements the smallest cohesive surface that demonstrates the
//! invite + admin loop end-to-end: distribution discovery, invite
//! redemption (unauthenticated), session inspection, principal
//! listing, and invite issuance / listing for operators. Richer
//! routes (per-principal env writes, audit SSE, capsule topic
//! publishes) are tracked as follow-ups in the same issue — the
//! middleware, state, and error layers are pre-built so adding a
//! handler is a one-file change.

// Handlers return `GatewayResult<T>` with a single documented error
// type (`GatewayError`); per-fn `# Errors` sections would duplicate
// the enum's variant docs without adding signal.
#![allow(clippy::missing_errors_doc)]
// `routes::*::Foo` repeats the route family name in struct names;
// matches the rest of the workspace's style (see astrid-kernel).
#![allow(clippy::module_name_repetitions)]

pub mod auth;
pub mod config;
pub mod error;
pub mod metrics;
pub mod routes;
pub mod state;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::net::TcpListener;
use tracing::info;

pub use config::GatewayConfig;
pub use state::GatewayState;

/// Run the gateway HTTP server until `shutdown` resolves.
///
/// Binds the configured listen address, attaches every defined route,
/// and serves over plain HTTP. TLS termination is expected upstream
/// (Caddy / nginx / Cloudflare) — the gateway never speaks TLS itself.
/// This keeps the crate dependency-light and lets operators choose
/// their own cert lifecycle.
///
/// # Errors
/// Returns an error if the listener cannot bind, the daemon socket
/// handshake fails, or the HTTP server crashes.
pub async fn run(
    state: Arc<GatewayState>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<()> {
    let addr: SocketAddr = state.config.listen.parse().with_context(|| {
        format!(
            "gateway.listen {:?} is not a socket address",
            state.config.listen
        )
    })?;
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind gateway listener on {addr}"))?;
    let bound = listener.local_addr().unwrap_or(addr);
    info!(addr = %bound, "astrid-gateway listening");

    let router = routes::build(state);
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown)
        .await
        .context("gateway HTTP server failed")
}

use std::future::Future;
