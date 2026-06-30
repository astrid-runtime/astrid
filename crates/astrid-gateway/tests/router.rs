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
    auth::{CallerContext, mint_bearer, mint_bearer_scoped, verify_bearer},
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
        revoked_key_ids: std::sync::Arc::new(std::sync::RwLock::new(
            std::collections::HashMap::new(),
        )),
        audit_log: None,
        session_id: None,
        gateway_route_uuid: uuid::Uuid::new_v4(),
        readiness_probe: None,
        topic_probe: None,
        capsule_source_probe: None,
        registry_timeout: None,
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
async fn device_routes_require_a_bearer() {
    // The paired-device management routes (list + revoke) are
    // capability-gated admin operations and MUST sit behind the auth
    // middleware. A regression that moved them to the public router would
    // expose — and let anyone revoke — a principal's device fleet without a
    // bearer. Assert both reject an unauthenticated request at the middleware,
    // before any handler or kernel round-trip runs.
    let state = fresh_state_with_distro(None);
    let router = routes::build(state);

    let list = Request::builder()
        .uri("/api/sys/principals/alice/devices")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        router.clone().oneshot(list).await.unwrap().status(),
        StatusCode::UNAUTHORIZED,
        "GET /devices must require a bearer"
    );

    let revoke = Request::builder()
        .method("DELETE")
        .uri("/api/sys/principals/alice/devices/deadbeefdeadbeef")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        router.oneshot(revoke).await.unwrap().status(),
        StatusCode::UNAUTHORIZED,
        "DELETE /devices/{{key_id}} must require a bearer"
    );
}

#[tokio::test]
async fn readiness_route_requires_a_bearer() {
    // `GET /api/sys/readiness` is capsule-set introspection gated like the
    // capsule-list family — it must sit behind the auth middleware. A
    // regression that registered it on the public router would leak the
    // loaded-capsule set without a bearer. Assert it rejects an
    // unauthenticated request at the middleware, before any kernel round-trip.
    let state = fresh_state_with_distro(None);
    let router = routes::build(state);

    let req = Request::builder()
        .uri("/api/sys/readiness")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        router.oneshot(req).await.unwrap().status(),
        StatusCode::UNAUTHORIZED,
        "GET /api/sys/readiness must require a bearer"
    );
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
        "/api/auth/pair-device",
        "/api/sys/principals",
        "/api/sys/principals/{id}/devices",
        "/api/sys/principals/{id}/devices/{key_id}",
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
fn openapi_types_kernel_payloads_instead_of_opaque_json() {
    // Regression guard for #783: response payloads sourced from
    // `astrid-core` types must surface as typed schema mirrors, not
    // opaque `serde_json::Value` (which renders as `any`/`object`
    // and gives generated clients no field-level types). If someone
    // reverts a `value_type` back to `serde_json::Value`, the
    // mirror schema disappears from components and this fails.
    use astrid_gateway::openapi::ApiDoc;
    use utoipa::OpenApi;

    let doc: serde_json::Value = serde_json::to_value(ApiDoc::openapi()).expect("spec serializes");
    let schemas = doc
        .get("components")
        .and_then(|v| v.get("schemas"))
        .and_then(|v| v.as_object())
        .expect("spec must declare component schemas");

    for mirror in [
        "AgentSummaryView",
        "CapabilityInfoView",
        "QuotasView",
        "ResourceUsageView",
        "GroupSummaryView",
        "InviteIssuedView",
        "InviteSummaryView",
        "DeviceKeyInfoView",
    ] {
        assert!(
            schemas.contains_key(mirror),
            "typed schema mirror {mirror} is missing — a kernel payload regressed to opaque JSON"
        );
    }

    // `QuotasView` must mirror `Quotas` field-for-field, including the CPU
    // ceiling that previously drifted off the write-shape mirror.
    let quotas_props = schemas
        .get("QuotasView")
        .and_then(|v| v.get("properties"))
        .and_then(|v| v.as_object())
        .expect("QuotasView must have properties");
    assert!(
        quotas_props.contains_key("max_cpu_fuel_per_sec"),
        "QuotasView must mirror Quotas::max_cpu_fuel_per_sec"
    );

    // `ResourceUsageView` must mirror the live `ResourceUsage` payload —
    // the consumed total and the budget it's measured against.
    let usage_props = schemas
        .get("ResourceUsageView")
        .and_then(|v| v.get("properties"))
        .and_then(|v| v.as_object())
        .expect("ResourceUsageView must have properties");
    for field in [
        "principal",
        "cpu_fuel_consumed_total",
        "cpu_fuel_per_sec_limit",
        "exempt",
        "memory_bytes_limit_per_instance",
        "memory_bytes_current_total",
    ] {
        assert!(
            usage_props.contains_key(field),
            "ResourceUsageView must mirror ResourceUsage::{field}"
        );
    }

    // The list response must reference the mirror by `$ref`, proving
    // the `value_type` wiring took effect (not an inline `object`).
    let principals_items = schemas
        .get("PrincipalListResponse")
        .and_then(|v| v.get("properties"))
        .and_then(|v| v.get("principals"))
        .and_then(|v| v.get("items"))
        .and_then(|v| v.get("$ref"))
        .and_then(|v| v.as_str())
        .expect("PrincipalListResponse.principals must be a typed array");
    assert!(
        principals_items.ends_with("AgentSummaryView"),
        "principals array must $ref AgentSummaryView, got {principals_items}"
    );

    // `token_fingerprint` is the canonical field name (the old doc
    // comment drifted to `fingerprint`); pin it so it can't drift back.
    let invite_props = schemas
        .get("InviteSummaryView")
        .and_then(|v| v.get("properties"))
        .and_then(|v| v.as_object())
        .expect("InviteSummaryView must have properties");
    assert!(
        invite_props.contains_key("token_fingerprint")
            && invite_props.contains_key("issued_at_epoch"),
        "InviteSummaryView must mirror the real InviteSummary fields"
    );
}

// Every concrete method/path the router exposes. Keep this table next to the
// router drift test and update it with any route registration change; it is the
// only maintained inventory because axum does not expose one after build.
const ROUTER_METHODS: &[(&str, &str)] = &[
    // Public
    ("GET", "/api/distribution"),
    ("GET", "/api/distribution/onboarding"),
    ("POST", "/api/auth/redeem"),
    ("POST", "/api/auth/pair-device/redeem"),
    ("GET", "/api/openapi.json"),
    ("GET", "/healthz"),
    ("GET", "/metrics"),
    // Authed
    ("GET", "/api/auth/me"),
    ("POST", "/api/auth/refresh"),
    ("POST", "/api/auth/pair-device"),
    ("GET", "/api/sys/principals"),
    ("POST", "/api/sys/principals"),
    ("GET", "/api/sys/principals/{id}"),
    ("PATCH", "/api/sys/principals/{id}"),
    ("DELETE", "/api/sys/principals/{id}"),
    ("POST", "/api/sys/principals/{id}/enable"),
    ("POST", "/api/sys/principals/{id}/disable"),
    ("POST", "/api/sys/principals/{id}/caps"),
    ("DELETE", "/api/sys/principals/{id}/caps"),
    ("GET", "/api/sys/principals/{id}/quotas"),
    ("PUT", "/api/sys/principals/{id}/quotas"),
    ("GET", "/api/sys/principals/{id}/usage"),
    ("GET", "/api/sys/principals/{id}/devices"),
    ("DELETE", "/api/sys/principals/{id}/devices/{key_id}"),
    ("GET", "/api/sys/groups"),
    ("POST", "/api/sys/groups"),
    ("PATCH", "/api/sys/groups/{name}"),
    ("DELETE", "/api/sys/groups/{name}"),
    ("POST", "/api/sys/invites"),
    ("GET", "/api/sys/invites"),
    ("DELETE", "/api/sys/invites/{fingerprint}"),
    ("GET", "/api/sys/capabilities"),
    ("GET", "/api/capsules"),
    ("POST", "/api/capsules"),
    ("GET", "/api/capsules/{id}"),
    ("GET", "/api/capsules/{id}/topics"),
    ("GET", "/api/capsules/{id}/env"),
    ("POST", "/api/capsules/{id}/env/{field}"),
    ("GET", "/api/events"),
    ("GET", "/api/sys/audit"),
    ("POST", "/api/agent/prompt"),
    ("GET", "/api/agent/requests"),
    ("GET", "/api/agent/stream"),
    ("GET", "/api/agent/sessions"),
    ("GET", "/api/agent/sessions/search"),
    ("GET", "/api/agent/sessions/{id}"),
    ("PATCH", "/api/agent/sessions/{id}"),
    ("DELETE", "/api/agent/sessions/{id}"),
    ("GET", "/api/agent/sessions/{id}/messages"),
    ("POST", "/api/agent/elicit-response"),
    ("POST", "/api/agent/approval-response"),
    ("GET", "/api/models"),
    ("GET", "/api/models/active"),
    ("PUT", "/api/models/active"),
    ("GET", "/api/sys/status"),
    ("GET", "/api/sys/readiness"),
    ("POST", "/api/sys/capsules/reload"),
];

#[test]
fn openapi_lists_every_router_route() {
    // Drift-check: the route registered in `routes::build` and the
    // method/path annotated with `#[utoipa::path(...)]` must agree. If
    // someone wires a new route into the router but forgets the utoipa
    // annotation (or forgets to add it under `paths(...)` in the `ApiDoc`
    // macro), this test catches it before review. The same method/path must
    // also have a runtime scenario or explicit waiver in e2e/http-scenarios.toml.
    use astrid_gateway::openapi::ApiDoc;
    use std::collections::BTreeSet;
    use utoipa::OpenApi;

    let router: BTreeSet<String> = ROUTER_METHODS
        .iter()
        .map(|(method, path)| format!("{method} {path}"))
        .collect();
    let spec = openapi_methods(ApiDoc::openapi());
    let manifest = parse_http_manifest(
        include_str!("../../../e2e/http-scenarios.toml"),
        include_str!("../../../e2e/runtime-scenario-specs.toml"),
    );

    let missing_from_spec: Vec<&String> = router.difference(&spec).collect();
    assert!(
        missing_from_spec.is_empty(),
        "router method/path is not in OpenAPI: {}",
        missing_from_spec
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );

    let openapi_only: Vec<&String> = spec.difference(&router).collect();
    assert!(
        openapi_only.is_empty(),
        "OpenAPI documents method/path not registered in router: {}",
        openapi_only
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );

    let missing_scenarios: Vec<&String> = router.difference(&manifest).collect();
    assert!(
        missing_scenarios.is_empty(),
        "new HTTP route has no e2e scenario: {}",
        missing_scenarios
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );

    let stale_scenarios: Vec<&String> = manifest.difference(&router).collect();
    assert!(
        stale_scenarios.is_empty(),
        "HTTP e2e manifest references routes that are no longer registered: {}",
        stale_scenarios
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
}

fn openapi_methods(doc: utoipa::openapi::OpenApi) -> std::collections::BTreeSet<String> {
    doc.paths
        .paths
        .into_iter()
        .flat_map(|(path, item)| {
            [
                item.get.map(|_| format!("GET {path}")),
                item.post.map(|_| format!("POST {path}")),
                item.put.map(|_| format!("PUT {path}")),
                item.patch.map(|_| format!("PATCH {path}")),
                item.delete.map(|_| format!("DELETE {path}")),
            ]
            .into_iter()
            .flatten()
        })
        .collect()
}

fn parse_http_manifest(src: &str, specs_src: &str) -> std::collections::BTreeSet<String> {
    let parsed: toml::Value = toml::from_str(src).expect("http-scenarios.toml parses");
    let specs = parse_runtime_scenario_specs(specs_src);
    let routes = parsed
        .get("routes")
        .and_then(toml::Value::as_table)
        .expect("http-scenarios.toml must contain a [routes] table");

    routes
        .iter()
        .map(|(name, entry)| {
            let table = entry
                .as_table()
                .unwrap_or_else(|| panic!("manifest entry for {name:?} must be a table"));
            for field in ["scenario", "status", "auth"] {
                assert!(
                    table.contains_key(field),
                    "manifest entry for {name:?} is missing required field {field:?}"
                );
            }
            let status = table
                .get("status")
                .and_then(toml::Value::as_str)
                .unwrap_or_else(|| panic!("manifest entry for {name:?} has non-string status"));
            assert!(
                matches!(status, "mapped" | "covered" | "waived" | "future"),
                "manifest entry for {name:?} has invalid status {status:?}"
            );
            assert_status_reason(name, table, status);
            assert_scenario_contract(name, table, &specs, "http");
            name.clone()
        })
        .collect()
}

fn parse_runtime_scenario_specs(src: &str) -> toml::Value {
    let parsed: toml::Value = toml::from_str(src).expect("runtime-scenario-specs.toml parses");
    let scenarios = parsed
        .get("scenarios")
        .and_then(toml::Value::as_table)
        .expect("runtime-scenario-specs.toml must contain a [scenarios] table");

    for (name, entry) in scenarios {
        let table = entry
            .as_table()
            .unwrap_or_else(|| panic!("runtime scenario {name:?} must be a table"));
        for field in [
            "status", "surfaces", "auth", "success", "denial", "state", "evidence",
        ] {
            assert!(
                non_empty_field(table, field),
                "runtime scenario {name:?} is missing non-empty field {field:?}"
            );
        }
        let status = table
            .get("status")
            .and_then(toml::Value::as_str)
            .unwrap_or_else(|| panic!("runtime scenario {name:?} has non-string status"));
        assert!(
            matches!(status, "mapped" | "covered" | "waived" | "future"),
            "runtime scenario {name:?} has invalid status {status:?}"
        );
        if status == "waived" {
            assert!(
                non_empty_field(table, "waiver"),
                "waived runtime scenario {name:?} needs a waiver"
            );
        }
    }

    parsed
}

fn assert_status_reason(name: &str, table: &toml::value::Table, status: &str) {
    if matches!(status, "waived" | "future") {
        assert!(
            non_empty_field(table, "reason"),
            "manifest entry for {name:?} with status {status:?} needs a reason"
        );
    }
}

fn assert_scenario_contract(
    name: &str,
    table: &toml::value::Table,
    specs: &toml::Value,
    surface: &str,
) {
    let scenario = table
        .get("scenario")
        .and_then(toml::Value::as_str)
        .unwrap_or_else(|| panic!("manifest entry for {name:?} has non-string scenario"));
    let scenarios = specs
        .get("scenarios")
        .and_then(toml::Value::as_table)
        .expect("runtime specs already validated");
    let spec = scenarios
        .get(scenario)
        .and_then(toml::Value::as_table)
        .unwrap_or_else(|| {
            panic!("manifest entry for {name:?} references unknown scenario {scenario:?}")
        });
    let surfaces = spec
        .get("surfaces")
        .and_then(toml::Value::as_array)
        .expect("runtime specs already validated");
    assert!(
        surfaces.iter().any(|v| v.as_str() == Some(surface)),
        "manifest entry for {name:?} references scenario {scenario:?}, which does not declare surface {surface:?}"
    );
}

fn non_empty_field(table: &toml::value::Table, field: &str) -> bool {
    match table.get(field) {
        Some(toml::Value::String(s)) => !s.trim().is_empty(),
        Some(toml::Value::Array(items)) => !items.is_empty(),
        _ => false,
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

#[tokio::test]
async fn pair_device_redeem_is_rate_limited_per_ip() {
    // The unauthenticated `/api/auth/pair-device/redeem` route must
    // share the same per-IP redeem throttle as `/api/auth/redeem` —
    // otherwise pair-tokens are brute-forceable as fast as the network
    // allows. We pre-seed the shared limiter for one IP, then fire a
    // single pair-redeem from that IP: it must be rejected with 429
    // BEFORE the handler ever reaches the (absent) daemon.
    use std::net::{IpAddr, SocketAddr};

    let state = fresh_state_with_distro(None);
    let ip = IpAddr::from([203, 0, 113, 7]);

    // First probe is free and records the timestamp; the next attempt
    // from this IP within the interval must back off.
    {
        let mut limiter = state.redeem_limiter.lock().await;
        assert!(
            limiter
                .check(ip, state.config.redeem_rate_limit())
                .is_none(),
            "first probe for a fresh IP must be allowed"
        );
    }

    let router = routes::build(state);
    let mut req = Request::builder()
        .method("POST")
        .uri("/api/auth/pair-device/redeem")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            r#"{"token":"deadbeef","public_key":"ed25519:00"}"#,
        ))
        .unwrap();
    // `oneshot` doesn't run the connect-info layer, so inject the peer
    // the `ConnectInfo<SocketAddr>` extractor reads.
    req.extensions_mut()
        .insert(axum::extract::ConnectInfo(SocketAddr::new(ip, 40000)));

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "pair-device/redeem must enforce the shared per-IP redeem limiter"
    );
}

// ── Device-scoped bearer: key_id extraction + per-key revocation ──────

#[tokio::test]
async fn scoped_bearer_carries_device_key_id_to_caller_context() {
    // A 5-segment device-scoped bearer must verify and surface its `key_id`
    // on the CallerContext. The gateway stamps that key_id onto every admin
    // request (via `admin_client_for`), so the kernel cap-gate attenuates the
    // op to the device's scope — the HTTP half of the cross-transport
    // guarantee. (The kernel-side denial is proven in the kernel crate.)
    let state = fresh_state_with_distro(None);
    let principal = PrincipalId::new("alice").unwrap();
    let key_id = "abc123def4567890";
    let bearer = mint_bearer_scoped(&state.signing.signer, &principal, key_id, 3600);

    let caller = verify_bearer(&state, &bearer).expect("scoped bearer verifies");
    assert_eq!(caller.principal, principal);
    assert_eq!(
        caller.device_key_id.as_deref(),
        Some(key_id),
        "the scoped bearer's key_id must reach the CallerContext"
    );
}

#[tokio::test]
async fn revoked_device_key_id_rejects_bearer() {
    // Criterion 4 (HTTP half): a device-scoped bearer minted at-or-before its
    // key_id's revocation epoch (recorded from the PairDeviceRevoke audit
    // signal) is rejected by `verify_bearer` — the live HTTP session stops
    // immediately, independent of the bearer's remaining TTL.
    let state = fresh_state_with_distro(None);
    let principal = PrincipalId::new("alice").unwrap();
    let key_id = "deadbeefcafe0001";
    let bearer = mint_bearer_scoped(&state.signing.signer, &principal, key_id, 3600);

    // The bearer's iat anchors the at-or-before-revoke comparison.
    let iat = verify_bearer(&state, &bearer)
        .expect("scoped bearer verifies before revocation")
        .issued_at_epoch;

    // Revoke at-or-after the bearer's iat (what the audit watcher records on a
    // successful PairDeviceRevoke) → the bearer is a dead session.
    state
        .revoked_key_ids
        .write()
        .expect("revoked key map")
        .insert(key_id.to_string(), iat);
    assert!(
        verify_bearer(&state, &bearer).is_err(),
        "a bearer minted at-or-before the revoke epoch must be rejected"
    );

    // Re-pair: the same deterministic key_id, but recorded with an EARLIER
    // revoke epoch than this bearer was minted (iat > revoked_at — i.e. a bearer
    // minted after the device was re-paired). Keying on the epoch rather than a
    // bare membership set lets it authenticate instead of being dead forever.
    state
        .revoked_key_ids
        .write()
        .expect("revoked key map")
        .insert(key_id.to_string(), iat.saturating_sub(1));
    assert!(
        verify_bearer(&state, &bearer).is_ok(),
        "a bearer minted after the revoke epoch (re-pair) must authenticate"
    );

    // A bearer for a DIFFERENT key on the same principal is unaffected.
    let other = mint_bearer_scoped(&state.signing.signer, &principal, "0000111122223333", 3600);
    assert!(
        verify_bearer(&state, &other).is_ok(),
        "revoking one device must not stop another device's bearer"
    );
}
