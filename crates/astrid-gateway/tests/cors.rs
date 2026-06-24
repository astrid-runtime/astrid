//! End-to-end CORS verification.
//!
//! Background: `cors_allow_origins` shipped in v0.7.0 as a config
//! field that the router never actually consumed — operators could
//! set an allowlist and nothing happened. These tests pin both
//! halves of the fix: (a) origins in the allowlist do receive the
//! ACAO + Vary + preflight responses a browser needs; (b) empty
//! allowlist is no-CORS-headers, which under the same-origin rule is
//! the correct secure default; (c) origins outside the allowlist
//! don't get ACAO so a browser refuses the request.
//!
//! All tests use `tower::ServiceExt::oneshot` against the in-process
//! router — no real socket, no daemon. The `CorsLayer` ships with
//! tower-http; we're verifying the *wiring*, not tower-http itself.

use std::sync::Arc;

use astrid_gateway::{
    GatewayConfig, GatewayState, routes,
    routes::distribution::{DistributionInfo, OnboardingFields},
    state::SigningMaterial,
};
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use tower::ServiceExt;

fn state_with_origins(origins: Vec<&str>) -> Arc<GatewayState> {
    let cfg = GatewayConfig {
        cors_allow_origins: origins.into_iter().map(String::from).collect(),
        ..GatewayConfig::default()
    };
    // Validation mirrors what the daemon does on boot; bad origins
    // would crash the daemon, so a test that ships unparseable ones
    // should fail loudly here too.
    cfg.validate().expect("test config must validate");
    Arc::new(GatewayState {
        config: cfg,
        signing: SigningMaterial::fresh(),
        distribution: Arc::new(DistributionInfo::single_tenant()),
        onboarding: Arc::new(OnboardingFields::default()),
        redeem_limiter: tokio::sync::Mutex::default(),
        metrics_handle: astrid_gateway::metrics::install_recorder().expect("recorder"),
        event_bus: None,
        revoked_at: std::sync::Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
        revoked_key_ids: std::sync::Arc::new(std::sync::RwLock::new(
            std::collections::HashMap::new(),
        )),
        audit_log: None,
        session_id: None,
        gateway_route_uuid: uuid::Uuid::new_v4(),
        readiness_probe: None,
        topic_probe: None,
        registry_timeout: None,
    })
}

/// Build a CORS preflight request: OPTIONS with `Origin`,
/// `Access-Control-Request-Method`, and `Access-Control-Request-Headers`.
/// Browsers send this before any cross-origin request that isn't a
/// "simple" GET/HEAD/POST-with-form-encoded body.
fn preflight(path: &str, origin: &str, method: &str) -> Request<Body> {
    Request::builder()
        .method(Method::OPTIONS)
        .uri(path)
        .header(header::ORIGIN, origin)
        .header("access-control-request-method", method)
        .header(
            "access-control-request-headers",
            "authorization,content-type",
        )
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn preflight_from_allowlisted_origin_gets_full_cors_response() {
    let state = state_with_origins(vec!["https://app.example"]);
    let router = routes::build(state);

    let response = router
        .oneshot(preflight("/api/auth/redeem", "https://app.example", "POST"))
        .await
        .expect("router responds");

    // tower-http returns 200 (not 204) for accepted preflights by
    // default — the spec allows either; both are equally browser-safe.
    assert!(
        matches!(response.status(), StatusCode::OK | StatusCode::NO_CONTENT),
        "preflight status: {:?}",
        response.status()
    );
    let headers = response.headers();
    assert_eq!(
        headers
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .expect("ACAO present"),
        "https://app.example",
        "allowlisted origin must be echoed verbatim (browsers byte-match)"
    );
    let allow_methods = headers
        .get(header::ACCESS_CONTROL_ALLOW_METHODS)
        .expect("ACA-Methods present")
        .to_str()
        .unwrap();
    assert!(
        allow_methods.to_uppercase().contains("POST"),
        "preflight must list POST: {allow_methods:?}"
    );
    let allow_headers = headers
        .get(header::ACCESS_CONTROL_ALLOW_HEADERS)
        .expect("ACA-Headers present")
        .to_str()
        .unwrap()
        .to_lowercase();
    assert!(
        allow_headers.contains("authorization") && allow_headers.contains("content-type"),
        "preflight must list authorization+content-type: {allow_headers:?}"
    );
    assert!(
        headers.get(header::VARY).is_some_and(|v| v
            .to_str()
            .unwrap_or("")
            .to_lowercase()
            .contains("origin")),
        "Vary: Origin missing — shared caches will mis-serve cross-origin responses"
    );
}

#[tokio::test]
async fn preflight_from_unlisted_origin_drops_acao() {
    let state = state_with_origins(vec!["https://app.example"]);
    let router = routes::build(state);

    let response = router
        .oneshot(preflight(
            "/api/auth/redeem",
            "https://evil.invalid",
            "POST",
        ))
        .await
        .expect("router responds");

    let headers = response.headers();
    // tower-http's contract: an unlisted origin gets no
    // `Access-Control-Allow-Origin` header. Browsers see that and
    // abort the actual request. The HTTP status may still be 200 (or
    // a 4xx — tower-http versions differ); what matters is the
    // *absence* of ACAO, since that's the bit the browser checks.
    let acao = headers.get(header::ACCESS_CONTROL_ALLOW_ORIGIN);
    assert!(
        acao.is_none() || acao.unwrap().as_bytes() != b"https://evil.invalid",
        "unlisted origin must NOT be echoed in ACAO (got {acao:?})"
    );
}

#[tokio::test]
async fn actual_request_from_allowlisted_origin_carries_acao() {
    let state = state_with_origins(vec!["https://app.example"]);
    let router = routes::build(state);

    // `/api/distribution` is unauthenticated, so we can hit it with
    // a real GET and confirm the CORS response shape on a non-OPTIONS
    // request. (Preflights only cover OPTIONS; the actual request
    // needs ACAO too, separately.)
    let response = router
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/distribution")
                .header(header::ORIGIN, "https://app.example")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("router responds");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .expect("actual request must also carry ACAO")
            .to_str()
            .unwrap(),
        "https://app.example"
    );
}

#[tokio::test]
async fn empty_allowlist_means_no_cors_headers_anywhere() {
    // Default config = no allowlist. Browsers fall back to same-origin
    // only because no ACAO is ever set. This is the correct secure
    // default and we want to lock it in so a future "just add a CORS
    // layer always" refactor doesn't quietly mint `Vary: Origin` (or
    // worse, `*`) on every response.
    let state = state_with_origins(vec![]);
    let router = routes::build(state);

    let response = router
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/distribution")
                .header(header::ORIGIN, "https://app.example")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("router responds");

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none(),
        "default config must NOT carry ACAO on any response"
    );
}

#[tokio::test]
async fn security_headers_appear_on_every_response() {
    // The security-headers stack (nosniff, DENY, no-referrer, CSP)
    // is independent of CORS — it applies even when no allowlist
    // is configured. Pinning this so a future refactor of the
    // CORS conditional doesn't accidentally drop the header layer
    // off the "no CORS" branch.
    for origins in [vec![], vec!["https://app.example"]] {
        let state = state_with_origins(origins.clone());
        let router = routes::build(state);

        let response = router
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/distribution")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("router responds");

        let headers = response.headers();
        assert_eq!(
            headers
                .get("x-content-type-options")
                .map(axum::http::HeaderValue::as_bytes),
            Some(&b"nosniff"[..]),
            "X-Content-Type-Options missing (origins={origins:?})"
        );
        assert_eq!(
            headers
                .get("x-frame-options")
                .map(axum::http::HeaderValue::as_bytes),
            Some(&b"DENY"[..]),
            "X-Frame-Options missing (origins={origins:?})"
        );
        assert_eq!(
            headers
                .get("referrer-policy")
                .map(axum::http::HeaderValue::as_bytes),
            Some(&b"no-referrer"[..]),
            "Referrer-Policy missing (origins={origins:?})"
        );
        let csp = headers
            .get("content-security-policy")
            .expect("CSP must be set")
            .to_str()
            .unwrap();
        assert!(
            csp.contains("default-src 'none'") && csp.contains("frame-ancestors 'none'"),
            "CSP must deny default-src + frame-ancestors (origins={origins:?}): {csp}"
        );
    }
}

#[tokio::test]
async fn security_headers_apply_to_error_responses_too() {
    // Defence in depth: a 401 from missing-bearer still gets
    // the headers. A future XSS-via-error-page bug would still be
    // mitigated by the CSP.
    let state = state_with_origins(vec![]);
    let router = routes::build(state);

    let response = router
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/auth/me")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("router responds");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response
            .headers()
            .get("x-content-type-options")
            .map(axum::http::HeaderValue::as_bytes),
        Some(&b"nosniff"[..]),
        "401 must still carry nosniff"
    );
    assert_eq!(
        response
            .headers()
            .get("x-frame-options")
            .map(axum::http::HeaderValue::as_bytes),
        Some(&b"DENY"[..]),
        "401 must still carry X-Frame-Options"
    );
}

#[tokio::test]
async fn multiple_allowlisted_origins_each_get_their_own_acao() {
    // Allowlist with two entries: each origin must see itself echoed,
    // not the other. Pins that tower-http's `AllowOrigin::list`
    // matches per-request rather than concatenating.
    let state = state_with_origins(vec!["https://app.example", "https://staging.example"]);
    let router = routes::build(state);

    for origin in ["https://app.example", "https://staging.example"] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/distribution")
                    .header(header::ORIGIN, origin)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("router responds");

        assert_eq!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap_or_else(|| panic!("ACAO missing for {origin}"))
                .to_str()
                .unwrap(),
            origin,
            "ACAO must echo the requesting origin, not a sibling"
        );
    }
}
