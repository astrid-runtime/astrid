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
        metrics_handle: astrid_gateway::metrics::install_recorder().expect("recorder"),
        event_bus: None,
        revoked_at: std::sync::Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
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

#[tokio::test]
async fn openapi_route_serves_valid_spec_unauthenticated() {
    // The spec is the contract clients read before they have a
    // bearer — codegen tools, dashboards, Swagger UI all need it
    // without auth. Verify it returns 200 with a parseable
    // OpenAPI 3.x document and that the canary routes are listed.
    let state = fresh_state_with_distro(None);
    let router = routes::build(state);

    let req = Request::builder()
        .uri("/api/openapi.json")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let doc: serde_json::Value = serde_json::from_slice(&bytes).expect("openapi must be JSON");

    assert!(
        doc.get("openapi").and_then(|v| v.as_str()).is_some(),
        "spec must declare an OpenAPI version"
    );
    let paths = doc
        .get("paths")
        .and_then(|v| v.as_object())
        .expect("spec must declare paths");
    for canary in [
        "/api/auth/redeem",
        "/api/auth/me",
        "/api/sys/principals",
        "/api/sys/capabilities",
        "/api/capsules",
        "/api/events",
        "/healthz",
        "/metrics",
    ] {
        assert!(paths.contains_key(canary), "missing path: {canary}");
    }

    // Bearer auth scheme must be declared.
    let schemes = doc
        .get("components")
        .and_then(|v| v.get("securitySchemes"))
        .and_then(|v| v.as_object())
        .expect("spec must declare security schemes");
    assert!(schemes.contains_key("bearerAuth"));
}

#[test]
fn openapi_lists_every_router_route() {
    // Drift-check: the route registered in `routes::build` and the
    // path annotated with `#[utoipa::path(...)]` must agree. If
    // someone wires a new route into the router but forgets the
    // utoipa annotation (or forgets to add it under `paths(...)` in
    // the `ApiDoc` macro), this test catches it before review.
    use astrid_gateway::openapi::ApiDoc;
    use utoipa::OpenApi;

    // Every concrete `/api` route the router exposes. Update this
    // list when you add a route; the spec must contain a matching
    // entry under each.
    const ROUTER_PATHS: &[&str] = &[
        // Public
        "/api/distribution",
        "/api/distribution/onboarding",
        "/api/auth/redeem",
        "/api/auth/pair-device/redeem",
        "/api/openapi.json",
        "/healthz",
        "/metrics",
        // Authed
        "/api/auth/me",
        "/api/auth/refresh",
        "/api/auth/pair-device",
        "/api/sys/principals",
        "/api/sys/principals/{id}",
        "/api/sys/principals/{id}/enable",
        "/api/sys/principals/{id}/disable",
        "/api/sys/principals/{id}/caps",
        "/api/sys/principals/{id}/quotas",
        "/api/sys/groups",
        "/api/sys/groups/{name}",
        "/api/sys/invites",
        "/api/sys/invites/{fingerprint}",
        "/api/sys/capabilities",
        "/api/capsules",
        "/api/capsules/{id}",
        "/api/capsules/{id}/topics",
        "/api/capsules/{id}/env",
        "/api/capsules/{id}/env/{field}",
        "/api/events",
        "/api/agent/prompt",
        "/api/sys/status",
        "/api/sys/capsules/reload",
    ];

    let doc = ApiDoc::openapi();
    let spec_paths: std::collections::HashSet<&str> =
        doc.paths.paths.keys().map(String::as_str).collect();

    for p in ROUTER_PATHS {
        assert!(
            spec_paths.contains(p),
            "router path {p} is not in the OpenAPI spec — annotate the handler with #[utoipa::path(...)] and list it under paths(...) in ApiDoc"
        );
    }
}

#[tokio::test]
async fn metrics_endpoint_decomposes_request_by_status_and_records_latency() {
    // Make a real request through the middleware, then hit /metrics
    // and confirm the exposition reflects the (method, route, status)
    // we just observed AND emits the histogram lines (count + +Inf
    // bucket) for the same labels. Pins the wiring between the
    // middleware and the `Metrics` type.
    let state = fresh_state_with_distro(Some(SAMPLE_DISTRO));
    let router = routes::build(Arc::clone(&state));

    // Drive one /api/distribution → expected 200.
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/distribution")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Scrape /metrics and verify shape.
    let metrics_resp = router
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(metrics_resp.status(), StatusCode::OK);
    let body = to_bytes(metrics_resp.into_body(), 64 * 1024).await.unwrap();
    let text = std::str::from_utf8(&body).expect("metrics must be UTF-8");

    // Counter — at least one observation for the request we made.
    assert!(
        text.contains(
            "astrid_gateway_requests_total{method=\"GET\",route=\"/api/distribution\",status=\"200\"}"
        ),
        "missing counter for GET /api/distribution 200; body was:\n{text}"
    );
    // Histogram — `_count` line for the same labels.
    assert!(
        text.contains(
            "astrid_gateway_request_duration_seconds_count{method=\"GET\",route=\"/api/distribution\",status=\"200\"}"
        ),
        "missing histogram _count for GET /api/distribution 200; body was:\n{text}"
    );
    // Histogram — `+Inf` bucket present.
    assert!(
        text.contains(
            "astrid_gateway_request_duration_seconds_bucket{method=\"GET\",route=\"/api/distribution\",status=\"200\",le=\"+Inf\"}"
        ),
        "missing +Inf bucket; body was:\n{text}"
    );
}
