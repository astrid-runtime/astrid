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
pub mod groups;
pub mod invites;
pub mod principals;
pub mod quotas;
pub mod system;

/// Build the gateway's HTTP router.
pub fn build(state: Arc<GatewayState>) -> Router {
    // Unauthenticated routes — discovery + redeem.
    let public = Router::new()
        .route("/api/distribution", get(distribution::get_distribution))
        .route(
            "/api/distribution/onboarding",
            get(distribution::get_onboarding),
        )
        .route("/api/auth/redeem", post(auth::post_redeem));

    // Authenticated routes — bearer required, principal attached to
    // request extensions.
    let authed = Router::new()
        // ── Session ──
        .route("/api/auth/me", get(auth::get_me))
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
        .route("/api/capsules/{id}", get(capsules::get_capsule))
        .route(
            "/api/capsules/{id}/topics",
            get(capsules::list_capsule_topics),
        )
        .route("/api/capsules/{id}/env", get(env::get_env_schema))
        .route("/api/capsules/{id}/env/{field}", post(env::write_env))
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

    public.merge(authed).with_state(state)
}
