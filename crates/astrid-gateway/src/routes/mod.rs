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
        .route("/metrics", get(observability::get_metrics));

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
        // ── System ──
        .route("/api/sys/status", get(system::get_status))
        .route(
            "/api/sys/capsules/reload",
            post(system::reload_capsules),
        )
        .route_layer(axum::middleware::from_fn_with_state(
            Arc::clone(&state),
            crate::auth::require_session,
        ));

    public
        .merge(authed)
        // Count every request after it routes — axum's `MatchedPath`
        // extractor gives the registered template (e.g.
        // `/api/sys/principals/{id}`) so the metric stays bounded
        // even under high-cardinality path params.
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&state),
            metrics_middleware,
        ))
        .with_state(state)
}

/// Per-request counter bump. Uses axum's `MatchedPath` so the
/// cardinality stays bounded (one bucket per route template, not
/// one per concrete URL). Failed-route requests (404 before match)
/// fall under the catch-all `<unmatched>` bucket.
async fn metrics_middleware(
    axum::extract::State(state): axum::extract::State<Arc<GatewayState>>,
    matched: Option<axum::extract::MatchedPath>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use std::sync::OnceLock;
    // Static interner: every route template is a literal string,
    // but the matched-path extractor returns `&str` borrowed from
    // the per-request router state. We need `&'static str` for the
    // counter map. The set of templates is fixed at compile time
    // (we register them) so a one-time lazy interner is bounded.
    static INTERN: OnceLock<std::sync::Mutex<std::collections::HashSet<&'static str>>> =
        OnceLock::new();
    let templates = INTERN.get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()));

    let method = request.method().clone();
    let template: &'static str = matched.as_ref().map_or("<unmatched>", |m| {
        let s = m.as_str();
        let mut guard = templates.lock().expect("interner lock");
        if let Some(existing) = guard.get(s) {
            existing
        } else {
            let leaked: &'static str = Box::leak(s.to_string().into_boxed_str());
            guard.insert(leaked);
            leaked
        }
    });

    // Build the bucket key once and intern it too — same logic as
    // the template intern above.
    let key: &'static str = {
        let composed = format!("{method} {template}");
        let mut guard = templates.lock().expect("interner lock");
        if let Some(existing) = guard.get(composed.as_str()) {
            existing
        } else {
            let leaked: &'static str = Box::leak(composed.into_boxed_str());
            guard.insert(leaked);
            leaked
        }
    };

    state.metrics.observe_request(key).await;

    next.run(request).await
}
