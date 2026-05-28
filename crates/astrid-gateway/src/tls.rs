//! Native TLS termination for the gateway.
//!
//! When [`crate::config::GatewayConfig::tls`] is `Some(...)`, the
//! daemon switches from `axum::serve` (plain HTTP) to
//! `axum_server::bind_rustls` (TLS via rustls). The plain-HTTP path
//! stays the default — operators who already terminate TLS in
//! nginx/Caddy/Cloudflare see no change.
//!
//! ## Why rustls?
//!
//! The entire workspace is openssl-free by policy. `reqwest`,
//! `teloxide`, and now the gateway all use rustls. Avoids the
//! cross-platform vendoring complications of openssl-sys at install
//! time.
//!
//! ## What's not here
//!
//! * **ACME / Let's Encrypt.** Operators bring their own cert
//!   lifecycle — `certbot --standalone` then SIGHUP reload is the
//!   suggested flow.
//! * **HTTP/2.** ALPN advertises HTTP/1.1 only. Browsers and curl
//!   negotiate fine.
//! * **mTLS / client-cert auth.** The cert+key surface is server-
//!   side only; client auth is deferred. Tracking issue: see #773
//!   follow-ups.

use std::net::SocketAddr;
use std::path::Path;

use anyhow::{Context, Result};
use axum::Router;
use axum_server::tls_rustls::RustlsConfig;

use crate::config::TlsConfig;

/// Build a `RustlsConfig` from the cert + key paths. Validation that
/// the files *exist* happens earlier in
/// [`crate::config::GatewayConfig::validate`]; here we surface the
/// parser-level errors (malformed PEM, key/cert mismatch) with a
/// clear path-prefixed message so a deploying operator can find the
/// bad file fast.
///
/// Also installs the process-wide rustls `CryptoProvider` (idempotent
/// — re-install is a no-op). rustls 0.23 requires this when the
/// crate is built with multiple provider features available; without
/// it, the first TLS handshake panics with "Could not automatically
/// determine the process-level `CryptoProvider`". We pick `aws-lc-rs`
/// because it's already pulled in transitively by every other rustls
/// consumer in the workspace (reqwest, etc.).
pub async fn load_rustls_config(tls: &TlsConfig) -> Result<RustlsConfig> {
    install_crypto_provider();
    let cert_path = tls.cert_path.as_path();
    let key_path = tls.key_path.as_path();
    let cfg = RustlsConfig::from_pem_file(cert_path, key_path)
        .await
        .with_context(|| {
            format!(
                "failed to load TLS material — cert: {}, key: {}",
                cert_path.display(),
                key_path.display()
            )
        })?;
    Ok(cfg)
}

/// Idempotent installer for the process-wide rustls `CryptoProvider`.
/// Calling more than once returns an error from rustls which we
/// silently discard — the first caller wins, every subsequent caller
/// is a no-op.
fn install_crypto_provider() {
    // Returns `Err(...)` if a provider is already installed; we
    // genuinely don't care about that case, only about the first
    // install succeeding.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// Serve the gateway router over HTTPS until `shutdown` resolves.
///
/// Mirrors [`crate::serve_plain`] (the plain-HTTP path) but layers
/// rustls in front of the same router. `into_make_service_with_connect_info::<SocketAddr>()`
/// is what populates the `ConnectInfo<SocketAddr>` request extension
/// the redeem rate-limiter extracts; without it `POST /api/auth/redeem`
/// returns 500 "Missing request extension". Same gotcha as the plain
/// path.
pub async fn serve_https(
    addr: SocketAddr,
    router: Router,
    rustls: RustlsConfig,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<()> {
    // `axum_server::bind_rustls` opens its own listener — pass the
    // SocketAddr, not a pre-bound TcpListener. The library installs
    // its own graceful shutdown handle.
    let handle = axum_server::Handle::new();
    let handle_for_shutdown = handle.clone();
    tokio::spawn(async move {
        shutdown.await;
        // Drain in-flight connections gracefully; force-close after
        // 30s so a stuck connection doesn't block the daemon
        // shutdown indefinitely.
        handle_for_shutdown.graceful_shutdown(Some(std::time::Duration::from_secs(30)));
    });

    axum_server::bind_rustls(addr, rustls)
        .handle(handle)
        .serve(router.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .context("gateway HTTPS server failed")
}

/// Layer `Strict-Transport-Security` onto a router. **Only call this
/// from the TLS dispatch path** — HSTS over plain HTTP is forbidden
/// by RFC 6797 (browsers ignore the header on http:// origins, but
/// shipping it would still be a footgun if someone reverse-proxies
/// this output back to plain HTTP).
///
/// Two-year max-age + `includeSubDomains` follows the HSTS preload
/// list's minimum requirements without committing to the preload
/// list (an operator can submit on their own). `if_not_present` so
/// a handler that intentionally sets a different policy wins.
pub fn apply_hsts<S: Clone + Send + Sync + 'static>(router: axum::Router<S>) -> axum::Router<S> {
    use axum::http::{HeaderName, HeaderValue};
    use tower_http::set_header::SetResponseHeaderLayer;
    router.layer(SetResponseHeaderLayer::if_not_present(
        HeaderName::from_static("strict-transport-security"),
        HeaderValue::from_static("max-age=63072000; includeSubDomains"),
    ))
}

/// Convenience: warn if the key file looks world-readable. Called
/// at `config.validate()` time so the warning surfaces at daemon
/// boot, not on the first request.
#[cfg(unix)]
pub fn warn_if_key_is_too_open(key_path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    if let Ok(meta) = std::fs::metadata(key_path) {
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            tracing::warn!(
                path = %key_path.display(),
                mode = format!("{mode:o}"),
                "TLS private key is group- or world-readable; chmod 0600 recommended"
            );
        }
    }
}

#[cfg(not(unix))]
pub fn warn_if_key_is_too_open(_key_path: &Path) {}

/// Re-export so the daemon doesn't have to depend on axum-server
/// directly. `RustlsConfig` is already cheaply cloneable (its
/// internal `rustls::ServerConfig` lives behind an `Arc`), so no
/// extra `Arc<RustlsConfig>` wrapping is needed — clone it directly
/// if you need shared ownership for a future cert-reload story.
pub use axum_server::tls_rustls::RustlsConfig as ReexportedRustlsConfig;
