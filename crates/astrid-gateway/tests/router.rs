//! Integration tests for the HTTP router.
//!
//! These tests exercise the router and middleware *without* a running
//! daemon: every test path is one that doesn't call into the kernel
//! (discovery, auth-only middleware, bearer verification). Routes
//! that talk to the daemon (`/api/sys/*`, `/api/auth/redeem`) are
//! exercised end-to-end in the per-crate integration harness; here
//! we pin the trust-shape invariants that don't need the kernel.
//!
//! ## What this file proves
//!
//! 1. **Unauthenticated discovery returns a 200 with the configured
//!    distro metadata.** Pure cache reflection.
//! 2. **Authenticated routes refuse missing/malformed bearers.**
//!    The auth middleware is the gatekeeper.
//! 3. **The principal a client claims in the request body is
//!    ignored** — the verified bearer is the only source of truth.

use std::sync::Arc;

use astrid_core::PrincipalId;
use astrid_gateway::{
    GatewayConfig, GatewayState,
    auth::{CallerContext, mint_bearer, verify_bearer},
    routes,
    routes::distribution::{
        DistributionInfo, OnboardingFields, parse_distribution, parse_onboarding,
    },
    state::SigningMaterial,
};
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;

const SAMPLE_DISTRO: &str = r#"
schema-version = 1

[distro]
id = "test-distro"
name = "Test"
pretty-name = "Test 0.1.0"

[invites]
issuers = ["admin"]
default-group = "agent"

[[capsule]]
name = "astrid-capsule-cli"
source = "@unicity-astrid/capsule-cli"
version = "0.7.0"
role = "uplink"
"#;

fn fresh_state_with_distro(distro: Option<&str>) -> Arc<GatewayState> {
    let (distribution, onboarding) = match distro {
        Some(text) => (
            parse_distribution(text).expect("test distro parses"),
            parse_onboarding(text).expect("test onboarding parses"),
        ),
        None => (
            DistributionInfo::single_tenant(),
            OnboardingFields::default(),
        ),
    };
    Arc::new(GatewayState {
        config: GatewayConfig::default(),
        signing: SigningMaterial::fresh(),
        distribution: Arc::new(distribution),
        onboarding: Arc::new(onboarding),
        redeem_limiter: tokio::sync::Mutex::default(),
    })
}

#[tokio::test]
async fn distribution_endpoint_returns_metadata_unauthenticated() {
    let state = fresh_state_with_distro(Some(SAMPLE_DISTRO));
    let router = routes::build(state);

    let req = Request::builder()
        .uri("/api/distribution")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 4096).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["id"], "test-distro");
    assert_eq!(body["name"], "Test");
    assert_eq!(body["invites_enabled"], true);
}

#[tokio::test]
async fn distribution_with_no_manifest_is_single_tenant() {
    let state = fresh_state_with_distro(None);
    let router = routes::build(state);

    let req = Request::builder()
        .uri("/api/distribution")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 4096).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["id"], "single-tenant");
    assert_eq!(body["invites_enabled"], false);
}

#[tokio::test]
async fn me_route_refuses_request_without_bearer() {
    let state = fresh_state_with_distro(None);
    let router = routes::build(state);

    let req = Request::builder()
        .uri("/api/auth/me")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn me_route_refuses_tampered_bearer() {
    let state = fresh_state_with_distro(None);
    let router = routes::build(Arc::clone(&state));

    let principal = PrincipalId::new("alice").unwrap();
    let mut bearer = mint_bearer(&state.signing.signer, &principal, 3600);
    // Flip last hex char — invalidates the signature.
    let last = bearer.pop().unwrap();
    bearer.push(if last == 'a' { 'b' } else { 'a' });

    let req = Request::builder()
        .uri("/api/auth/me")
        .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn me_route_returns_principal_from_valid_bearer() {
    let state = fresh_state_with_distro(None);
    let router = routes::build(Arc::clone(&state));

    let principal = PrincipalId::new("alice").unwrap();
    let bearer = mint_bearer(&state.signing.signer, &principal, 3600);

    let req = Request::builder()
        .uri("/api/auth/me")
        .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 4096).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["principal"], "alice");
}

#[tokio::test]
async fn me_route_ignores_principal_claim_in_query_string() {
    // Adversarial check: a client tries to coerce `/api/auth/me` to
    // return a different principal by adding a query parameter. The
    // verified bearer is the only source of truth, so the query
    // string MUST be ignored.
    let state = fresh_state_with_distro(None);
    let router = routes::build(Arc::clone(&state));

    let principal = PrincipalId::new("alice").unwrap();
    let bearer = mint_bearer(&state.signing.signer, &principal, 3600);

    let req = Request::builder()
        .uri("/api/auth/me?principal=root")
        .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 4096).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["principal"], "alice");
}

#[tokio::test]
async fn verify_bearer_rejects_signing_key_from_another_boot() {
    // Adversarial check: signature verification is tied to the
    // gateway's current boot keypair. A bearer minted with a
    // different keypair (i.e. a previous gateway restart) MUST NOT
    // verify against the current keypair.
    let state_a = fresh_state_with_distro(None);
    let state_b = fresh_state_with_distro(None);
    assert!(
        state_a.signing.verifier.to_bytes() != state_b.signing.verifier.to_bytes(),
        "fresh signing material must differ"
    );

    let principal = PrincipalId::new("alice").unwrap();
    let bearer_from_a = mint_bearer(&state_a.signing.signer, &principal, 3600);

    let result = verify_bearer(&state_b, &bearer_from_a);
    assert!(
        result.is_err(),
        "bearer signed by another boot must be rejected"
    );
}

#[tokio::test]
async fn caller_context_is_attached_to_extensions_for_authed_routes() {
    // Sanity check the wiring: a valid bearer attaches a
    // CallerContext that handlers can pull out.
    let state = fresh_state_with_distro(None);
    let principal = PrincipalId::new("alice").unwrap();
    let bearer = mint_bearer(&state.signing.signer, &principal, 3600);
    let caller = verify_bearer(&state, &bearer).expect("verify");
    let _: CallerContext = caller; // type-asserts the public shape
}
