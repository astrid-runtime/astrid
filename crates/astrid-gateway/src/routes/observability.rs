//! `GET /healthz` + `GET /metrics`.
//!
//! Both routes are intentionally unauthenticated:
//!
//! * `/healthz` is what load balancers and process supervisors call
//!   every few seconds. Requiring a bearer would force every
//!   monitoring tool to manage a service account.
//! * `/metrics` is the standard Prometheus scrape endpoint. Same
//!   posture as `/healthz` — operators restrict access via the
//!   network layer (reverse proxy, firewall), not by minting a
//!   bearer per Prometheus instance.
//!
//! Both expose only operational signals — no principal identifiers,
//! no token material, no audit content. The cost of leaking
//! "Astrid is running and served 1234 requests" is acceptable; the
//! cost of leaking actual data is the regular routes' problem.

use std::sync::Arc;

use astrid_core::dirs::AstridHome;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::Response;

use crate::state::GatewayState;

/// `GET /healthz` — 200 if the daemon endpoint is present, 503 otherwise.
///
/// This deliberately performs a backend presence check, not a connection:
/// health scrapes are unauthenticated and must not create daemon sessions or
/// consume work in the local accept loop.
#[utoipa::path(
    get,
    path = "/healthz",
    tag = "ops",
    security(()),
    responses(
        (status = 200, description = "Daemon endpoint present. Body is the literal text `ok\\n`.", content_type = "text/plain"),
        (status = 503, description = "Daemon endpoint unavailable.", content_type = "text/plain"),
    )
)]
pub async fn get_healthz(State(_state): State<Arc<GatewayState>>) -> Response {
    let healthy = match AstridHome::resolve() {
        Ok(home) => daemon_endpoint_present(&home.socket_path()),
        Err(_) => false,
    };
    let (status, body) = if healthy {
        (StatusCode::OK, "ok\n")
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "daemon socket unreachable\n",
        )
    };
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(body.into())
        .unwrap_or_else(|_| Response::new("ok\n".into()))
}

fn daemon_endpoint_present(path: &std::path::Path) -> bool {
    astrid_core::local_transport::endpoint_is_present(path).unwrap_or(false)
}

#[cfg(all(test, unix))]
mod tests {
    use std::time::Duration;

    use astrid_core::local_transport;

    use super::daemon_endpoint_present;

    #[tokio::test]
    async fn health_presence_probe_does_not_open_a_daemon_connection() {
        let directory = tempfile::tempdir().unwrap();
        let endpoint = directory.path().join("health.sock");
        let listener = local_transport::bind(&endpoint).unwrap();

        assert!(daemon_endpoint_present(&endpoint));
        assert!(
            tokio::time::timeout(
                Duration::from_millis(25),
                local_transport::accept(&listener)
            )
            .await
            .is_err(),
            "presence-only health probe must not enter the daemon accept queue"
        );

        drop(listener);
        local_transport::remove_endpoint(&endpoint).unwrap();
    }
}

/// `GET /metrics` — Prometheus text-exposition format.
#[utoipa::path(
    get,
    path = "/metrics",
    tag = "ops",
    security(()),
    responses(
        (status = 200, description = "Prometheus text-exposition format (version 0.0.4). Series: `astrid_gateway_requests_total{method,route,status}`, `astrid_gateway_request_duration_seconds{method,route,status}` (histogram), `astrid_gateway_auth_failures_total`, `astrid_gateway_redeem_attempts_total`, `astrid_gateway_redeem_rate_limited_total`, `astrid_build_info{version,git_sha,rustc}`, and the standard `process_*` family (`process_cpu_seconds_total`, `process_resident_memory_bytes`, `process_threads`, `process_open_fds`, `process_start_time_seconds`).", content_type = "text/plain"),
    )
)]
pub async fn get_metrics(State(state): State<Arc<GatewayState>>) -> Response {
    // Refresh the pull-based `process_*` gauges so the scrape reflects the
    // instant it was taken (the collector has no background thread).
    // `collect()` does synchronous `/proc` (Linux) / `libproc` (macOS)
    // reads, so run it on the blocking pool to keep the async workers
    // responsive under scrape spam against this unauthenticated endpoint.
    // Fail-soft: if the blocking task can't be joined, render with the
    // prior sample rather than panicking a public request.
    let _ = tokio::task::spawn_blocking(crate::metrics::collect_process_metrics).await;
    let body = state.metrics_handle.render();
    Response::builder()
        .status(StatusCode::OK)
        // Prometheus' content type — the version suffix is part of
        // the spec; some scrapers care about the version pin.
        .header(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )
        .body(body.into())
        .unwrap_or_else(|_| Response::new("# render failed\n".into()))
}
