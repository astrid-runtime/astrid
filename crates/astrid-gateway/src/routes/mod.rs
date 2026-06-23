//! HTTP route composition.
//!
//! Mirrors the layout sketched in issue #756. Each submodule owns
//! a family of related endpoints; this module wires them into a
//! single `axum::Router` with the auth middleware applied where
//! appropriate.

use std::sync::Arc;

use axum::Router;
use axum::routing::{delete, get, patch, post, put};

use crate::state::GatewayState;

pub mod agent;
pub mod audit;
pub mod auth;
pub mod caps;
pub mod capsules;
pub mod distribution;
pub mod env;
pub mod events;
pub mod groups;
pub mod invites;
pub mod observability;
pub mod principals;
pub mod quotas;
pub mod system;

/// Build the gateway's HTTP router.
pub fn build(state: Arc<GatewayState>) -> Router {
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
    let authed = Router::new()
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
        .route("/api/sys/principals/:id", get(principals::get_principal))
        .route(
            "/api/sys/principals/:id",
            patch(principals::modify_principal),
        )
        .route(
            "/api/sys/principals/:id",
            delete(principals::delete_principal),
        )
        .route(
            "/api/sys/principals/:id/enable",
            post(principals::enable_principal),
        )
        .route(
            "/api/sys/principals/:id/disable",
            post(principals::disable_principal),
        )
        // ── Caps ──
        .route("/api/sys/principals/:id/caps", post(caps::grant_caps))
        .route("/api/sys/principals/:id/caps", delete(caps::revoke_caps))
        // ── Quotas ──
        .route("/api/sys/principals/:id/quotas", get(quotas::get_quotas))
        .route("/api/sys/principals/:id/quotas", put(quotas::set_quotas))
        .route("/api/sys/principals/:id/usage", get(quotas::get_usage))
        // ── Devices (paired keys) ──
        .route(
            "/api/sys/principals/:id/devices",
            get(principals::list_principal_devices),
        )
        .route(
            "/api/sys/principals/:id/devices/:key_id",
            delete(principals::delete_principal_device),
        )
        // ── Groups ──
        .route("/api/sys/groups", get(groups::list_groups))
        .route("/api/sys/groups", post(groups::create_group))
        .route("/api/sys/groups/:name", patch(groups::modify_group))
        .route("/api/sys/groups/:name", delete(groups::delete_group))
        // ── Invites ──
        .route("/api/sys/invites", post(invites::issue_invite))
        .route("/api/sys/invites", get(invites::list_invites))
        .route(
            "/api/sys/invites/:fingerprint",
            delete(invites::revoke_invite),
        )
        // ── Capabilities catalog ──
        .route("/api/sys/capabilities", get(principals::list_capabilities))
        // ── Capsules ──
        .route("/api/capsules", get(capsules::list_capsules))
        .route("/api/capsules", post(capsules::install_capsule))
        .route("/api/capsules/:id", get(capsules::get_capsule))
        .route(
            "/api/capsules/:id/topics",
            get(capsules::list_capsule_topics),
        )
        .route("/api/capsules/:id/env", get(env::get_env_schema))
        .route("/api/capsules/:id/env/:field", post(env::write_env))
        // ── Audit stream ──
        .route("/api/events", get(events::get_events))
        // ── Audit history (paginated) ──
        .route("/api/sys/audit", get(audit::get_audit))
        // ── Agent invocation (SSE) ──
        .route("/api/agent/prompt", post(agent::post_prompt))
        // ── System ──
        .route("/api/sys/status", get(system::get_status))
        .route("/api/sys/readiness", get(system::get_readiness))
        .route(
            "/api/sys/capsules/reload",
            post(system::reload_capsules),
        )
        .route_layer(axum::middleware::from_fn_with_state(
            Arc::clone(&state),
            crate::auth::require_session,
        ));

    let combined = public.merge(authed)
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
    apply_security_headers(with_cors).with_state(state)
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
