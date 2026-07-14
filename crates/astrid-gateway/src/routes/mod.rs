//! HTTP route composition.
//!
//! Mirrors the layout sketched in issue #756. Each submodule owns
//! a family of related endpoints; this module wires them into a
//! single `axum::Router` with the auth middleware applied where
//! appropriate.

use std::sync::Arc;

use axum::routing::{delete, get, patch, post, put};
use axum::{Extension, Router};

use astrid_uplink::KernelClientError;

use crate::error::GatewayError;
use crate::state::GatewayState;

#[derive(Clone)]
pub(crate) struct WorkspaceContext {
    pub(crate) root: std::path::PathBuf,
    pub(crate) layout: astrid_core::dirs::WorkspaceLayout,
}

impl Default for WorkspaceContext {
    fn default() -> Self {
        Self {
            root: std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from(".")),
            layout: astrid_core::dirs::WorkspaceLayout::default(),
        }
    }
}

/// Map a bus-direct / socket kernel-request failure ([`KernelClientError`]) to a
/// [`GatewayError`]. Single-sourced so every `kernel_client_for(...).request()`
/// call site maps consistently.
///
/// A [`Timeout`](KernelClientError::Timeout) — the daemon was slow / wedged, not
/// a transport fault — maps to **504** so callers can distinguish "still
/// processing, retry" (e.g. a heavy `InstallCapsule` under load) from a genuine
/// 500. Connection loss, bus shutdown, build, and decode failures all map to
/// **500**. A kernel-side rejection is a `KernelResponse::Error` handled at the
/// call site (→ 403), never reaching this path.
#[allow(
    clippy::needless_pass_by_value,
    reason = "consumed by Display formatting"
)]
pub(crate) fn daemon_kernel_error(e: KernelClientError) -> GatewayError {
    if e.is_timeout() {
        return GatewayError::Timeout(format!("daemon kernel-request: {e}"));
    }
    GatewayError::Internal(anyhow::anyhow!("daemon kernel-request: {e}"))
}

pub mod agent;
pub mod audit;
pub mod auth;
pub mod caps;
mod capsule_sources;
pub mod capsules;
pub mod distribution;
pub mod env;
pub mod events;
pub mod groups;
pub mod invites;
pub mod models;
pub mod observability;
pub mod principals;
pub mod quotas;
pub mod sessions;
mod sessions_layout;
pub mod stream;
pub mod system;

/// Build the gateway's HTTP router with self-only audit visibility.
///
/// This builder installs a deny-all capability evaluator. Runtimes that need
/// live `audit:read_all` policy must use [`build_with_capability_probe`], which
/// also documents the required connect-info serving path for the unauthenticated
/// redeem routes' per-IP throttling.
// A flat list of route registrations: its length tracks the API surface,
// not branching complexity, and both the readiness and models surfaces add
// rows here. Splitting it into sub-routers would obscure the single
// public/authed grouping for no readability gain.
pub fn build(state: Arc<GatewayState>) -> Router {
    build_with_workspace_layout(state, astrid_core::dirs::WorkspaceLayout::default())
}

/// Build the gateway router with an explicit workspace layout and self-only
/// audit visibility.
///
/// This has the same real-socket connect-info requirement as [`build`].
pub fn build_with_workspace_layout(
    state: Arc<GatewayState>,
    workspace_layout: astrid_core::dirs::WorkspaceLayout,
) -> Router {
    let workspace_root = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    build_with_workspace(state, workspace_root, workspace_layout)
}

/// Build the gateway router with explicit workspace inputs and self-only
/// audit visibility.
///
/// This has the same real-socket connect-info requirement as [`build`].
pub fn build_with_workspace(
    state: Arc<GatewayState>,
    workspace_root: std::path::PathBuf,
    workspace_layout: astrid_core::dirs::WorkspaceLayout,
) -> Router {
    build_with_workspace_and_probe(
        state,
        workspace_root,
        workspace_layout,
        events::CapabilityProbe::deny_all(),
    )
}

/// Build the gateway's HTTP router with an in-process capability evaluator.
///
/// Co-located runtimes can use this to preserve live audit firehose policy
/// when they embed the router directly instead of calling
/// [`crate::run_with_capability_probe`].
///
/// When serving this router over a real socket, use
/// `router.into_make_service_with_connect_info::<std::net::SocketAddr>()`
/// rather than plain `axum::serve(listener, router)`. The unauthenticated
/// redeem routes require the peer address for per-IP throttling.
pub fn build_with_capability_probe<F>(state: Arc<GatewayState>, capability_probe: F) -> Router
where
    F: Fn(&astrid_core::PrincipalId, Option<&str>, &str) -> bool + Send + Sync + 'static,
{
    let workspace_root = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    build_with_workspace_and_probe(
        state,
        workspace_root,
        astrid_core::dirs::WorkspaceLayout::default(),
        events::CapabilityProbe::new(capability_probe),
    )
}

/// Build the gateway router with explicit workspace inputs and an in-process
/// capability evaluator.
///
/// This is the fully composed direct-embedding path. It has the same
/// real-socket connect-info requirement as [`build`].
pub fn build_with_workspace_and_capability_probe<F>(
    state: Arc<GatewayState>,
    workspace_root: std::path::PathBuf,
    workspace_layout: astrid_core::dirs::WorkspaceLayout,
    capability_probe: F,
) -> Router
where
    F: Fn(&astrid_core::PrincipalId, Option<&str>, &str) -> bool + Send + Sync + 'static,
{
    build_with_workspace_and_probe(
        state,
        workspace_root,
        workspace_layout,
        events::CapabilityProbe::new(capability_probe),
    )
}

#[allow(clippy::too_many_lines)]
pub(crate) fn build_with_workspace_and_probe(
    state: Arc<GatewayState>,
    workspace_root: std::path::PathBuf,
    workspace_layout: astrid_core::dirs::WorkspaceLayout,
    capability_probe: events::CapabilityProbe,
) -> Router {
    // Unauthenticated routes — discovery + redeem + ops probes.
    let public = Router::new()
        .route("/api/distribution", get(distribution::get_distribution))
        .route(
            "/api/distribution/onboarding",
            get(distribution::get_onboarding),
        )
        .route("/api/auth/redeem", post(auth::post_redeem))
        .route(
            "/api/auth/pair-device/redeem",
            post(auth::post_pair_device_redeem),
        )
        // Ops probes: intentionally unauthenticated so load
        // balancers and Prometheus scrapers don't need a bearer.
        // Restrict by network policy (reverse proxy / firewall).
        .route("/healthz", get(observability::get_healthz))
        .route("/metrics", get(observability::get_metrics))
        // OpenAPI: unauthenticated by design — the spec is the
        // contract the API publishes about itself, and clients
        // (dashboards, codegen tools) read it before they have
        // a bearer.
        .route("/api/openapi.json", get(crate::openapi::get_openapi));

    // Authenticated routes — bearer required, principal attached to
    // request extensions.
    let authed = build_authed_router(&state);

    let combined = public.merge(authed)
        .layer(Extension(capability_probe))
        // Count every request after it routes — axum's `MatchedPath`
        // extractor gives the registered template (e.g.
        // `/api/sys/principals/:id`) so the metric stays bounded
        // even under high-cardinality path params.
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&state),
            metrics_middleware,
        ));

    // Apply CORS only when the operator opted in via
    // `cors_allow_origins`. Empty allowlist = no CORS headers in any
    // response = browsers refuse cross-origin requests = same-origin
    // only. That's the secure default; adding the layer when nothing's
    // configured would mint unnecessary `Vary: Origin` and break
    // shared-cache assumptions further downstream.
    //
    // Origins were validated at config-load time (`GatewayConfig::
    // validate`) so the `parse::<HeaderValue>` here is infallible by
    // construction. We still `unwrap_or_else` defensively rather than
    // `expect` so a future grammar drift doesn't crash a live gateway.
    let with_cors = if state.config.cors_allow_origins.is_empty() {
        combined
    } else {
        let cors = build_cors_layer(&state.config.cors_allow_origins);
        combined.layer(cors)
    };

    // Security-headers stack applies to every response, including
    // CORS preflights and error paths. The gateway returns JSON,
    // SSE, plain text, and Prometheus — never HTML — so a strict
    // CSP and `X-Frame-Options: DENY` are safe blanket defaults.
    // A future misconfigured handler that accidentally renders HTML
    // would be neutered rather than ship a clickjacking / XSS
    // surface.
    apply_security_headers(with_cors)
        .with_state(state)
        .layer(Extension(WorkspaceContext {
            root: workspace_root,
            layout: workspace_layout,
        }))
}

/// Build the bearer-gated router half. Split out of [`build`] so each stays
/// under the per-function line cap; every route here inherits the
/// `require_session` middleware applied as the final `route_layer`.
fn build_authed_router(state: &Arc<GatewayState>) -> Router<Arc<GatewayState>> {
    Router::new()
        // ── Session ──
        .route("/api/auth/me", get(auth::get_me))
        .route("/api/auth/refresh", post(auth::post_refresh))
        .route(
            "/api/auth/pair-device",
            post(auth::post_pair_device_issue),
        )
        // ── Principals (agents) ──
        .route("/api/sys/principals", get(principals::list_principals))
        .route("/api/sys/principals", post(principals::create_principal))
        .route("/api/sys/principals/{id}", get(principals::get_principal))
        .route(
            "/api/sys/principals/{id}",
            patch(principals::modify_principal),
        )
        .route(
            "/api/sys/principals/{id}",
            delete(principals::delete_principal),
        )
        .route(
            "/api/sys/principals/{id}/enable",
            post(principals::enable_principal),
        )
        .route(
            "/api/sys/principals/{id}/disable",
            post(principals::disable_principal),
        )
        // ── Caps ──
        .route("/api/sys/principals/{id}/caps", post(caps::grant_caps))
        .route("/api/sys/principals/{id}/caps", delete(caps::revoke_caps))
        // ── Quotas ──
        .route("/api/sys/principals/{id}/quotas", get(quotas::get_quotas))
        .route("/api/sys/principals/{id}/quotas", put(quotas::set_quotas))
        .route("/api/sys/principals/{id}/usage", get(quotas::get_usage))
        // ── Devices (paired keys) ──
        .route(
            "/api/sys/principals/{id}/devices",
            get(principals::list_principal_devices),
        )
        .route(
            "/api/sys/principals/{id}/devices/{key_id}",
            delete(principals::delete_principal_device),
        )
        // ── Groups ──
        .route("/api/sys/groups", get(groups::list_groups))
        .route("/api/sys/groups", post(groups::create_group))
        .route("/api/sys/groups/{name}", patch(groups::modify_group))
        .route("/api/sys/groups/{name}", delete(groups::delete_group))
        // ── Invites ──
        .route("/api/sys/invites", post(invites::issue_invite))
        .route("/api/sys/invites", get(invites::list_invites))
        .route(
            "/api/sys/invites/{fingerprint}",
            delete(invites::revoke_invite),
        )
        // ── Capabilities catalog ──
        .route("/api/sys/capabilities", get(principals::list_capabilities))
        // ── Capsules ──
        .route("/api/capsules", get(capsules::list_capsules))
        .route("/api/capsules", post(capsules::install_capsule))
        .route("/api/capsules/{id}", get(capsules::get_capsule))
        .route(
            "/api/capsules/{id}/topics",
            get(capsules::list_capsule_topics),
        )
        .route("/api/capsules/{id}/env", get(env::get_env_schema))
        .route("/api/capsules/{id}/env/{field}", post(env::write_env))
        // ── Audit stream ──
        .route("/api/events", get(events::get_events))
        // ── Audit history (paginated) ──
        .route("/api/sys/audit", get(audit::get_audit))
        // ── Agent invocation (SSE) ──
        .route("/api/agent/prompt", post(agent::post_prompt))
        // ── Pending approval/elicit requests (SSE) ──
        .route("/api/agent/requests", get(agent::get_requests))
        // ── Per-principal live conversation feed (SSE, #973) ──
        .route("/api/agent/stream", get(stream::get_stream))
        // ── Conversation threads (proxied to capsule-session) ──
        .route(
            "/api/agent/sessions",
            get(sessions_layout::list_sessions_with_layout),
        )
        // `search` is a static segment and is registered before the `:id`
        // routes; axum prefers the static match, so `/sessions/search` never
        // collides with `/sessions/:id`.
        .route(
            "/api/agent/sessions/search",
            get(sessions_layout::search_sessions_with_layout),
        )
        .route(
            "/api/agent/sessions/{id}",
            get(sessions_layout::get_session_with_layout)
                .patch(sessions_layout::update_session_with_layout)
                .delete(sessions_layout::delete_session_with_layout),
        )
        .route(
            "/api/agent/sessions/{id}/messages",
            get(sessions_layout::get_session_messages_with_layout),
        )
        // ── Agent elicitation reply ──
        .route(
            "/api/agent/elicit-response",
            post(agent::post_elicit_response),
        )
        .route(
            "/api/agent/approval-response",
            post(agent::post_approval_response),
        )
        // ── Models (active-LLM selection) ──
        .route("/api/models", get(models::list_models_with_layout))
        .route(
            "/api/models/active",
            get(models::get_active_model_with_layout),
        )
        .route(
            "/api/models/active",
            put(models::set_active_model_with_layout),
        )
        // ── System ──
        .route("/api/sys/status", get(system::get_status))
        .route("/api/sys/readiness", get(system::get_readiness))
        .route(
            "/api/sys/capsules/reload",
            post(system::reload_capsules),
        )
        .route_layer(axum::middleware::from_fn_with_state(
            Arc::clone(state),
            crate::auth::require_session,
        ))
}

/// Apply the four static security headers every gateway response
/// carries. `if_not_present` means a handler that intentionally
/// sets one of these wins; this layer only fills in the defaults.
fn apply_security_headers<S: Clone + Send + Sync + 'static>(router: Router<S>) -> Router<S> {
    use axum::http::{HeaderName, HeaderValue};
    use tower_http::set_header::SetResponseHeaderLayer;
    router
        // X-Content-Type-Options: nosniff — stops browsers from
        // MIME-sniffing a JSON response into HTML when the
        // content-type is missing or wrong.
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        ))
        // X-Frame-Options: DENY — API responses must not be
        // embeddable. Clickjacking defence-in-depth for any HTML
        // that might accidentally land in the surface area later.
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("DENY"),
        ))
        // Referrer-Policy: no-referrer — URL paths can carry
        // principal ids (`/api/sys/principals/:id`); we don't want
        // those leaking to third-party origins via the `Referer`
        // header when an admin clicks an external link from a
        // dashboard view.
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("referrer-policy"),
            HeaderValue::from_static("no-referrer"),
        ))
        // Content-Security-Policy: gateway never returns HTML, so
        // deny every sub-resource by default. Kicks in as defence-
        // in-depth if a future bug accidentally surfaces HTML or an
        // error page from a misbehaving middleware.
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("content-security-policy"),
            HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
        ))
}

/// Build a `CorsLayer` from the operator-configured allowlist.
/// Allowlist entries are validated at config-load time, so any entry
/// that fails to parse as a header value here is treated as a config
/// drift and skipped with a warning — the layer still applies for
/// every entry that did parse.
#[allow(clippy::duration_suboptimal_units)] // 60 * 60 reads better than 3600
fn build_cors_layer(origins: &[String]) -> tower_http::cors::CorsLayer {
    use axum::http::{HeaderName, HeaderValue, Method};
    let parsed: Vec<HeaderValue> = origins
        .iter()
        .filter_map(|s| match s.parse::<HeaderValue>() {
            Ok(v) => Some(v),
            Err(e) => {
                tracing::warn!(origin = %s, error = %e, "skipping unparseable CORS origin");
                None
            },
        })
        .collect();
    tower_http::cors::CorsLayer::new()
        .allow_origin(tower_http::cors::AllowOrigin::list(parsed))
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            HeaderName::from_static("authorization"),
            HeaderName::from_static("content-type"),
            HeaderName::from_static("accept"),
        ])
        // `Vary: Origin` is what stops a shared cache (CDN, browser
        // disk cache) from serving an ACAO response keyed for one
        // origin to a request from another. tower-http defaults to
        // setting Vary on every CORS-eligible response, but we name
        // it here so the wiring is self-documenting.
        .vary([HeaderName::from_static("origin")])
        // Browsers may cache the preflight outcome for this long; one
        // hour is a sensible tradeoff between policy-rollout latency
        // and dashboard responsiveness.
        .max_age(std::time::Duration::from_secs(60 * 60))
}

/// Per-request observability — times the inner handler, records
/// into the latency histogram, bumps the counter, and emits one
/// structured `tracing::event!` per request. Uses axum's
/// `MatchedPath` so the metric cardinality stays bounded (one
/// bucket per route template, not one per concrete URL).
/// Failed-route requests (404 before match) fall under the
/// catch-all `<unmatched>` bucket.
async fn metrics_middleware(
    _state: axum::extract::State<Arc<GatewayState>>,
    matched: Option<axum::extract::MatchedPath>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let method = crate::metrics::http_method_static(request.method());
    let route = match matched.as_ref() {
        Some(m) => intern_route(m.as_str()),
        None => "<unmatched>",
    };

    let start = std::time::Instant::now();
    let response = next.run(request).await;
    let duration = start.elapsed();
    let status = response.status().as_u16();

    // Record into the process-wide `metrics::Recorder`. The labels
    // are `&'static str` (route templates interned once on first
    // sight; method + status mapped to static strs at the call
    // site) so the recorder doesn't allocate on the hot path.
    // Cardinality stays bounded by `routes × ~6 typical statuses`.
    crate::metrics::observe_request(method, route, status, duration);

    // Structured per-request log. /healthz and /metrics demote to
    // DEBUG so the high-frequency liveness probes don't drown the
    // INFO stream; every other route logs at INFO.
    #[allow(clippy::cast_precision_loss)]
    // duration_ms is a presentational field, precision loss is fine
    let duration_ms = duration.as_secs_f64() * 1000.0;
    let quiet = route == "/healthz" || route == "/metrics";
    if quiet {
        tracing::debug!(
            method = method,
            route = route,
            status = status,
            duration_ms = duration_ms,
            "request"
        );
    } else {
        tracing::info!(
            method = method,
            route = route,
            status = status,
            duration_ms = duration_ms,
            "request"
        );
    }

    response
}

/// Intern a route template `&str` into a `&'static str`. The set of
/// route templates is fixed at compile time by [`build`] above —
/// the matched-path extractor returns one of those literals on every
/// request — so leaking each unique template once is safe and the
/// total leak budget is the route count.
///
/// The mutex contention here is only paid the *first* time each
/// route is seen; subsequent requests skip the lock entirely because
/// `axum::extract::MatchedPath` returns a string borrowed from the
/// per-request router state that already has a stable representation
/// in axum's own intern table (the path strings are static-like once
/// the router is built). We intern again on our side to materialise
/// the `&'static str` lifetime the metric map's key requires.
fn intern_route(s: &str) -> &'static str {
    use std::sync::OnceLock;
    static INTERN: OnceLock<std::sync::Mutex<std::collections::HashSet<&'static str>>> =
        OnceLock::new();
    let table = INTERN.get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()));
    let mut guard = table.lock().expect("interner lock");
    if let Some(existing) = guard.get(s) {
        return existing;
    }
    let leaked: &'static str = Box::leak(s.to_string().into_boxed_str());
    guard.insert(leaked);
    leaked
}

#[cfg(test)]
mod tests {
    use astrid_uplink::{KernelClientError, TimeoutKind};

    use super::daemon_kernel_error;
    use crate::error::GatewayError;

    /// The shared kernel-request error mapper turns a typed `Timeout` into a 504
    /// `GatewayError::Timeout` (retryable — the daemon was slow/wedged, e.g. a
    /// heavy `InstallCapsule`), while every other typed failure maps to a 500
    /// `Internal`. Kernel-side rejections are `KernelResponse::Error` handled at
    /// the call site (→ 403) and never reach this path.
    #[test]
    fn daemon_kernel_error_maps_timeout_to_504_others_to_500() {
        let timed_out = KernelClientError::Timeout {
            topic: "astrid.v1.response.install_capsule.abc".to_string(),
            kind: TimeoutKind::Ceiling,
        };
        assert!(
            matches!(daemon_kernel_error(timed_out), GatewayError::Timeout(_)),
            "a typed Timeout must map to 504",
        );

        let bus_closed = KernelClientError::BusClosed {
            topic: "astrid.v1.response.status.abc".to_string(),
        };
        assert!(
            matches!(daemon_kernel_error(bus_closed), GatewayError::Internal(_)),
            "a non-timeout transport failure must stay 500",
        );

        let deserialize = KernelClientError::Deserialize {
            topic: "astrid.v1.response.status.abc".to_string(),
        };
        assert!(
            matches!(daemon_kernel_error(deserialize), GatewayError::Internal(_)),
            "a decode failure must stay 500",
        );
    }
}
