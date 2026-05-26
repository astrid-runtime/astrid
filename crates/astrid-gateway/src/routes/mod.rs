//! HTTP route composition.
//!
//! Mirrors the layout sketched in issue #756. Each submodule owns a
//! family of related endpoints; this module wires them into a single
//! `axum::Router` with the auth middleware applied where appropriate.

use std::sync::Arc;

use axum::Router;
use axum::routing::{get, post};

use crate::state::GatewayState;

pub mod auth;
pub mod distribution;
pub mod invites;
pub mod principals;

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

    // Authenticated routes — bearer token required, principal
    // attached to extensions.
    let authed = Router::new()
        .route("/api/auth/me", get(auth::get_me))
        .route("/api/sys/principals", get(principals::list_principals))
        .route("/api/sys/invites", post(invites::issue_invite))
        .route("/api/sys/invites", get(invites::list_invites))
        .route(
            "/api/sys/invites/{fingerprint}",
            axum::routing::delete(invites::revoke_invite),
        )
        .route("/api/sys/capabilities", get(principals::list_capabilities))
        .route_layer(axum::middleware::from_fn_with_state(
            Arc::clone(&state),
            crate::auth::require_session,
        ));

    public.merge(authed).with_state(state)
}
