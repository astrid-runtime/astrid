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
pub mod bus_admin;
pub mod config;
pub mod error;
pub mod metrics;
pub mod openapi;
pub mod routes;
pub mod state;
pub mod tls;

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
/// and serves over plain HTTP — unless `state.config.tls` is `Some`,
/// in which case rustls termination is layered in front of the same
/// router (see [`tls::serve_https`]). The default posture remains
/// "TLS upstream"; native TLS is an opt-in feature for single-box
/// installs that don't want to run a reverse proxy.
///
/// # Errors
/// Returns an error if the listener cannot bind, the rustls config
/// can't be loaded (TLS path), the daemon socket handshake fails, or
/// the HTTP server crashes.
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

    if let Some(tls_cfg) = state.config.tls.clone() {
        // TLS path: bind via axum-server, layer rustls in front of
        // the same router. The plain-HTTP TcpListener::bind dance
        // doesn't apply here — axum-server opens its own listener.
        info!(addr = %addr, scheme = "https", "astrid-gateway listening (TLS)");
        let rustls = tls::load_rustls_config(&tls_cfg).await?;
        let router = tls::apply_hsts(routes::build(state));
        return tls::serve_https(addr, router, rustls, shutdown).await;
    }

    // Plain HTTP path — unchanged behaviour from v0.7.0. Warn loudly
    // when the operator binds beyond loopback without enabling TLS,
    // since that's almost always a misconfig: either the gateway is
    // about to serve unencrypted traffic on the LAN/public, or
    // there's a reverse proxy upstream that the operator should
    // confirm is actually fronting plain TCP correctly.
    if !addr.ip().is_loopback() {
        tracing::warn!(
            addr = %addr,
            "gateway is binding a non-loopback address without TLS; ensure a TLS-terminating reverse proxy fronts this listener, or enable [tls] in gateway-http.toml"
        );
    }

    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind gateway listener on {addr}"))?;
    let bound = listener.local_addr().unwrap_or(addr);
    info!(addr = %bound, scheme = "http", "astrid-gateway listening");

    let router = routes::build(state);
    // `into_make_service_with_connect_info::<SocketAddr>()` is what
    // populates the `ConnectInfo<SocketAddr>` request extension that
    // `routes::auth::post_redeem` extracts for per-IP rate limiting.
    // Without it, every redeem fails with a 500 "Missing request
    // extension". The plain `axum::serve(listener, router)` shape
    // works for every other route but quietly breaks the redeem
    // path — caught at runtime by exercising the live daemon.
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await
    .context("gateway HTTP server failed")
}

use std::future::Future;
