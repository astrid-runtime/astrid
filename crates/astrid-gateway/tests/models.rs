//! Integration tests for `/api/models*` — list + bind the active LLM model.
//!
//! Split mirrors `router.rs`: routes that don't need a live registry are
//! pinned with `event_bus: None` (auth-only / pre-bus guards); the bus
//! round-trip routes use an in-process `EventBus` with a stub responder
//! that replies on the `registry.v1.response.*` topics stamped with the
//! requesting principal.
//!
//! The load-bearing test is `models_principal_isolation`: it proves that a
//! reply stamped for principal B is NOT observed by a handler invoked as
//! principal A, because the handler subscribes scoped to
//! `Some(Some(caller.principal))`. A regression to an unscoped subscription
//! would leak B's binding into A's response and fail this test.

use std::sync::Arc;
use std::time::Duration;

use astrid_core::PrincipalId;
use astrid_events::ipc::{IpcMessage, IpcPayload};
use astrid_events::{AstridEvent, EventBus, EventMetadata};
use astrid_gateway::{
    GatewayConfig, GatewayState,
    auth::mint_bearer,
    routes,
    routes::distribution::{DistributionInfo, OnboardingFields},
    state::SigningMaterial,
};
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;
use uuid::Uuid;

/// Build a gateway state, optionally wired to a live event bus.
fn state_with_bus(bus: Option<Arc<EventBus>>) -> Arc<GatewayState> {
    Arc::new(GatewayState {
        config: GatewayConfig::default(),
        signing: SigningMaterial::fresh(),
        distribution: Arc::new(DistributionInfo::single_tenant()),
        onboarding: Arc::new(OnboardingFields::default()),
        redeem_limiter: tokio::sync::Mutex::default(),
        metrics_handle: astrid_gateway::metrics::install_recorder().expect("recorder"),
        event_bus: bus,
        revoked_at: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
        revoked_key_ids: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
        audit_log: None,
        session_id: None,
        gateway_route_uuid: Uuid::new_v4(),
    })
}

/// Mint a valid bearer for `principal` against the state's signing key.
fn bearer_for(state: &GatewayState, principal: &str) -> String {
    let pid = PrincipalId::new(principal).expect("valid principal");
    mint_bearer(&state.signing.signer, &pid, 3600)
}

/// Spawn a stub registry responder: on the first request on `request_topic`,
/// publish `reply` on `response_topic` stamped with the SAME principal the
/// request carried (mirrors the host's caller-context → reply-principal
/// stamping). The subscribe happens **synchronously** before returning, so
/// the stub is guaranteed to be on the bus before the request is published —
/// no race with the handler's publish.
fn spawn_stub_responder(
    bus: &Arc<EventBus>,
    request_topic: &'static str,
    response_topic: &'static str,
    reply: serde_json::Value,
) {
    let mut rx = bus.subscribe_topic_routed(Uuid::new_v4(), request_topic, "test", "test::stub");
    let bus = Arc::clone(bus);
    tokio::spawn(async move {
        if let Some(event) = rx.recv(Some(Duration::from_secs(5))).await {
            let AstridEvent::Ipc { message, .. } = &*event else {
                return;
            };
            let principal = message.principal.clone();
            let mut resp = IpcMessage::new(response_topic, IpcPayload::RawJson(reply), Uuid::nil());
            // Reply stamped with the requester's principal, as the real
            // registry's own-principal `publish` does for a request whose
            // caller-context carries that principal.
            if let Some(p) = principal {
                resp = resp.with_principal(p);
            }
            bus.publish(AstridEvent::Ipc {
                metadata: EventMetadata::new("test::stub"),
                message: resp,
            });
        }
    });
}

#[tokio::test]
async fn models_routes_require_bearer() {
    // All three model routes sit behind the auth middleware; an
    // unauthenticated request must be rejected at the gate (401), never
    // 404 and never reaching a handler or the bus. `event_bus: None` is
    // irrelevant here — the middleware rejects before any handler runs.
    let state = state_with_bus(None);
    let router = routes::build(state);

    let get_list = Request::builder()
        .uri("/api/models")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        router.clone().oneshot(get_list).await.unwrap().status(),
        StatusCode::UNAUTHORIZED,
        "GET /api/models must require a bearer"
    );

    let get_active = Request::builder()
        .uri("/api/models/active")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        router.clone().oneshot(get_active).await.unwrap().status(),
        StatusCode::UNAUTHORIZED,
        "GET /api/models/active must require a bearer"
    );

    let put_active = Request::builder()
        .method("PUT")
        .uri("/api/models/active")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"id":"openai:gpt-4o"}"#))
        .unwrap();
    assert_eq!(
        router.oneshot(put_active).await.unwrap().status(),
        StatusCode::UNAUTHORIZED,
        "PUT /api/models/active must require a bearer"
    );
}

#[tokio::test]
async fn set_active_model_rejects_empty_id() {
    // An empty / whitespace `id` is rejected with 400 BEFORE the bus is
    // touched. Proven structurally: the state has NO event bus, so a
    // request that reached the round-trip would 500 ("not wired to a live
    // event bus"). A 400 therefore means the pre-bus guard fired first.
    let state = state_with_bus(None);
    let bearer = bearer_for(&state, "alice");
    let router = routes::build(state);

    for body in [r#"{"id":""}"#, r#"{"id":"   "}"#] {
        let req = Request::builder()
            .method("PUT")
            .uri("/api/models/active")
            .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .unwrap();
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "empty id must 400 before the bus round-trip (body: {body})"
        );
    }
}

#[tokio::test]
async fn list_models_returns_registry_providers() {
    let bus = Arc::new(EventBus::new());
    let state = state_with_bus(Some(Arc::clone(&bus)));
    let bearer = bearer_for(&state, "alice");

    let providers = serde_json::json!([
        { "id": "openai:gpt-4o", "provider": "openai", "model": "gpt-4o" },
        { "id": "anthropic:claude", "provider": "anthropic", "model": "claude" },
    ]);
    spawn_stub_responder(
        &bus,
        "registry.v1.get_providers",
        "registry.v1.response.get_providers",
        providers.clone(),
    );

    let router = routes::build(state);
    let req = Request::builder()
        .uri("/api/models")
        .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        body, providers,
        "the provider array must pass through unchanged"
    );
}

#[tokio::test]
async fn get_active_model_null_is_200() {
    // A `null` reply means "no model bound" — a valid 200 response, not an
    // error.
    let bus = Arc::new(EventBus::new());
    let state = state_with_bus(Some(Arc::clone(&bus)));
    let bearer = bearer_for(&state, "alice");

    spawn_stub_responder(
        &bus,
        "registry.v1.get_active_model",
        "registry.v1.response.get_active_model",
        serde_json::Value::Null,
    );

    let router = routes::build(state);
    let req = Request::builder()
        .uri("/api/models/active")
        .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(
        body.is_null(),
        "null binding must surface as JSON null at 200"
    );
}

#[tokio::test]
async fn set_active_model_surfaces_registry_error_verbatim() {
    // The registry owns id resolution; its error message is surfaced as a
    // 400 verbatim — the gateway does not reinterpret it.
    let bus = Arc::new(EventBus::new());
    let state = state_with_bus(Some(Arc::clone(&bus)));
    let bearer = bearer_for(&state, "alice");

    spawn_stub_responder(
        &bus,
        "registry.v1.set_active_model",
        "registry.v1.response.set_active_model",
        serde_json::json!({ "error": "unknown model: bogus" }),
    );

    let router = routes::build(state);
    let req = Request::builder()
        .method("PUT")
        .uri("/api/models/active")
        .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"id":"bogus"}"#))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        body["reason"], "unknown model: bogus",
        "the registry's error message must be surfaced verbatim"
    );
}

#[tokio::test]
async fn set_active_model_returns_persisted_entry() {
    // On success the registry replies `{ status: ok, active_model: <entry> }`;
    // the handler returns the persisted entry so the caller sees the
    // canonical id the registry bound.
    let bus = Arc::new(EventBus::new());
    let state = state_with_bus(Some(Arc::clone(&bus)));
    let bearer = bearer_for(&state, "alice");

    let entry =
        serde_json::json!({ "id": "openai:gpt-4o", "provider": "openai", "model": "gpt-4o" });
    spawn_stub_responder(
        &bus,
        "registry.v1.set_active_model",
        "registry.v1.response.set_active_model",
        serde_json::json!({ "status": "ok", "active_model": entry.clone() }),
    );

    let router = routes::build(state);
    let req = Request::builder()
        .method("PUT")
        .uri("/api/models/active")
        .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"id":"openai:gpt-4o"}"#))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body, entry, "the persisted active entry must be returned");
}

#[tokio::test]
async fn models_principal_isolation() {
    // Threat-model regression. With a single shared bus, a responder
    // publishes an active-model reply stamped for principal B. A handler
    // invoked as principal A (scoped subscription `Some(Some("A"))`) must
    // NOT observe B's reply — it times out instead. Then A's own reply is
    // published and A receives it. A regression to an unscoped subscription
    // would let A read B's binding and fail the first assertion.
    let bus = Arc::new(EventBus::new());
    let state = state_with_bus(Some(Arc::clone(&bus)));
    let bearer_a = bearer_for(&state, "alice");

    // A responder that replies to A's request stamped for B (the wrong
    // principal). Because the handler's subscription is scoped to A, this
    // reply is dropped at enqueue and never reaches the handler.
    {
        // Subscribe synchronously so the wrong-principal responder is
        // guaranteed on the bus before the request fires — its reply is
        // genuinely published (and then dropped at A's scoped enqueue),
        // not merely never sent.
        let mut rx = bus.subscribe_topic_routed(
            Uuid::new_v4(),
            "registry.v1.get_active_model",
            "test",
            "test::wrong-principal",
        );
        let bus = Arc::clone(&bus);
        tokio::spawn(async move {
            if rx.recv(Some(Duration::from_secs(5))).await.is_some() {
                let resp = IpcMessage::new(
                    "registry.v1.response.get_active_model",
                    IpcPayload::RawJson(serde_json::json!({ "id": "bob-only:secret" })),
                    Uuid::nil(),
                )
                .with_principal("bob".to_string());
                bus.publish(AstridEvent::Ipc {
                    metadata: EventMetadata::new("test::wrong-principal"),
                    message: resp,
                });
            }
        });
    }

    let router = routes::build(Arc::clone(&state));
    let req = Request::builder()
        .uri("/api/models/active")
        .header(header::AUTHORIZATION, format!("Bearer {bearer_a}"))
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    // The foreign-principal reply is dropped at enqueue, so the handler
    // never receives a reply and times out → 500. Critically, it must NOT
    // return B's secret binding.
    assert_eq!(
        resp.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "a reply stamped for B must not satisfy A's scoped subscription"
    );
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let text = String::from_utf8_lossy(&bytes);
    assert!(
        !text.contains("bob-only:secret"),
        "principal A must never observe principal B's binding; body was: {text}"
    );

    // Now prove the positive: A's OWN reply (stamped for A) IS received.
    spawn_stub_responder(
        &bus,
        "registry.v1.get_active_model",
        "registry.v1.response.get_active_model",
        serde_json::json!({ "id": "openai:gpt-4o", "provider": "openai", "model": "gpt-4o" }),
    );
    let router = routes::build(state);
    let req = Request::builder()
        .uri("/api/models/active")
        .header(header::AUTHORIZATION, format!("Bearer {bearer_a}"))
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "A's own reply (stamped for A) must be received"
    );
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["id"], "openai:gpt-4o");
}
