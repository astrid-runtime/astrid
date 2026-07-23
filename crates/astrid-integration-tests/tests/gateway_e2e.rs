//! Gateway × kernel end-to-end smoke test.
//!
//! Boots a real `Kernel` and a real `GatewayState` against a tempdir
//! `ASTRID_HOME`, then exercises the pieces of the loop that don't
//! require the `astrid-capsule-cli` proxy capsule. The proxy
//! capsule is what bridges the kernel's bound Unix socket to its
//! event bus; without it, `AdminClient::connect` times out on
//! handshake even though the socket file exists. Loading the proxy
//! would require a pre-built WASM artefact in this crate's test
//! fixtures, which is out of scope.
//!
//! ## What this proves
//!
//! 1. `Kernel::new` boots cleanly against an isolated tempdir
//!    `ASTRID_HOME`, opens the persistent KV store, audit log,
//!    capability store, and binds the Unix socket.
//! 2. The gateway's `SigningMaterial::load_or_generate` writes
//!    `gateway.ed25519` into the same home with 0600 perms.
//! 3. The unauthenticated discovery / ops routes return 200 against
//!    the live state — `GET /api/distribution`, `GET /api/openapi.json`,
//!    `GET /healthz`.
//! 4. Audit events the kernel publishes on
//!    `astrid.v1.audit.entry` reach both a direct bus subscriber and
//!    the gateway's live SSE response. Revoking the authenticating
//!    device immediately narrows that open response to the caller's
//!    own records through the kernel's live policy evaluator.
//! 5. Bearers minted by the gateway and verified by the gateway
//!    round-trip correctly — i.e. `signed → token → verified
//!    principal` matches against a real on-disk key.
//!
//! ## What this does NOT cover (and why)
//!
//! * **`/api/auth/redeem` over the real socket.** The redeem
//!   handler calls `AdminClient::connect` which times out without
//!   `astrid-capsule-cli` loaded. Covered manually with `astrid
//!   start && curl ...` against a built daemon, and by the
//!   in-process router tests in `astrid-gateway/tests/router.rs`
//!   that exercise the auth middleware with mocked state.
//! ## Sandbox note
//!
//! Unix-socket bind permissions are blocked in some sandboxed
//! environments (notably the developer-local cargo-sandbox used
//! here), and the kernel's `bind_listener` fails with `EPERM`.
//! Those failures are environmental — the test passes in
//! unconstrained CI. We detect the bind error and emit a `skipping`
//! notice rather than claim success or failure.

#![allow(clippy::unwrap_used, clippy::expect_used)]
// `std::env::set_var` is unsafe on edition 2024 — the global env
// table is not thread-safe and racing readers can observe a torn
// value. The test sets `ASTRID_HOME` once at the top of a fresh
// test binary before any other thread reads it, so the soundness
// hazard doesn't apply here.
#![allow(unsafe_code)]

use std::sync::Arc;
use std::time::Duration;

use astrid_audit::{AuditAction, AuditOutcome, AuthorizationProof};
use astrid_core::kernel_api::{AdminRequestKind, AdminResponseBody};
use astrid_core::{AuthMethod, DeviceKey, DeviceScope, PrincipalId, PrincipalProfile};
use astrid_events::AstridEvent;
use astrid_events::ipc::{IpcMessage, IpcPayload, Topic};
use astrid_gateway::{GatewayConfig, GatewayState, routes};
use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use tempfile::TempDir;
use tower::ServiceExt;

// `std::env::set_var` is disallowed by the workspace lint policy; permitted
// here because `set_astrid_home` is called once at the start of a single-test
// binary before any other thread reads the env, so there is no thread-safety
// hazard.
#[allow(clippy::disallowed_methods)]
fn set_astrid_home(dir: &TempDir) {
    // Safety: invoked once at the top of a single-test binary
    // before any thread reads $ASTRID_HOME.
    unsafe {
        std::env::set_var("ASTRID_HOME", dir.path());
    }
}

fn looks_like_sandbox_block(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::PermissionDenied || err.raw_os_error() == Some(1) // EPERM
}

fn publish_audit_marker(event_bus: &astrid_events::EventBus, principal: &str, marker: &str) {
    let payload = serde_json::json!({
        "principal": principal,
        "method": marker,
    });
    let message = IpcMessage::new(
        Topic::from_raw("astrid.v1.audit.entry"),
        IpcPayload::RawJson(payload),
        uuid::Uuid::nil(),
    )
    .with_principal(principal.to_owned());
    let _ = event_bus.publish(AstridEvent::Ipc {
        metadata: astrid_events::EventMetadata::new("gateway_sse_policy_test"),
        message,
    });
}

async fn append_audit_marker(
    kernel: &astrid_kernel::Kernel,
    principal: &PrincipalId,
    marker: &str,
) {
    kernel
        .audit_log
        .append_with_principal(
            kernel.session_id.clone(),
            principal.clone(),
            AuditAction::AdminRequest {
                method: marker.to_owned(),
                required_capability: "audit:read_all".to_owned(),
                target_principal: None,
                params: None,
                device_key_id: None,
            },
            AuthorizationProof::System {
                reason: "gateway audit attenuation regression".to_owned(),
            },
            AuditOutcome::Success { details: None },
        )
        .await
        .expect("append audit marker");
}

async fn wait_for_sse_marker(
    response: &mut reqwest::Response,
    observed: &mut String,
    marker: &str,
) {
    tokio::time::timeout(Duration::from_secs(3), async {
        while !observed.contains(marker) {
            let chunk = response
                .chunk()
                .await
                .expect("read SSE response")
                .expect("SSE response closed");
            observed.push_str(&String::from_utf8_lossy(&chunk));
        }
    })
    .await
    .unwrap_or_else(|_| panic!("SSE response did not contain {marker:?}: {observed}"));
}

async fn assert_sse_marker_absent(
    response: &mut reqwest::Response,
    observed: &mut String,
    marker: &str,
) {
    assert!(!observed.contains(marker));
    let result = tokio::time::timeout(Duration::from_millis(500), async {
        loop {
            let chunk = response
                .chunk()
                .await
                .expect("read SSE response")
                .expect("SSE response closed");
            observed.push_str(&String::from_utf8_lossy(&chunk));
            assert!(
                !observed.contains(marker),
                "SSE response leaked {marker:?}: {observed}"
            );
        }
    })
    .await;
    assert!(result.is_err());
    assert!(!observed.contains(marker));
}

async fn assert_scoped_admin_audit_history(
    client: &reqwest::Client,
    address: std::net::SocketAddr,
    kernel: &astrid_kernel::Kernel,
    principal: &PrincipalId,
    bob: &PrincipalId,
    bearer: &str,
) {
    append_audit_marker(kernel, bob, "BobHiddenFromScopedAdminHistory").await;
    append_audit_marker(kernel, principal, "CallerOwnScopedAdminHistory").await;
    let historical_url = format!("http://{address}/api/sys/audit?limit=1000");
    let historical = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            match client.get(&historical_url).bearer_auth(bearer).send().await {
                Ok(response) => return response,
                Err(_) => tokio::time::sleep(Duration::from_millis(25)).await,
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("gateway did not become ready at {historical_url}"));
    assert_eq!(historical.status(), reqwest::StatusCode::OK);
    let historical: serde_json::Value = historical
        .json()
        .await
        .expect("parse historical audit response");
    let historical_methods = historical["entries"]
        .as_array()
        .expect("historical entries")
        .iter()
        .filter_map(|entry| entry["method"].as_str())
        .collect::<Vec<_>>();
    assert!(historical_methods.contains(&"CallerOwnScopedAdminHistory"));
    assert!(!historical_methods.contains(&"BobHiddenFromScopedAdminHistory"));
}

async fn assert_scoped_admin_audit_stream(
    client: &reqwest::Client,
    address: std::net::SocketAddr,
    kernel: &astrid_kernel::Kernel,
    principal: &PrincipalId,
    bob: &PrincipalId,
    bearer: &str,
) {
    let url = format!("http://{address}/api/events");
    let mut scoped_response = client
        .get(&url)
        .bearer_auth(bearer)
        .send()
        .await
        .expect("open scoped-admin audit stream");
    assert_eq!(scoped_response.status(), reqwest::StatusCode::OK);
    let mut scoped_observed = String::new();
    wait_for_sse_marker(&mut scoped_response, &mut scoped_observed, "ready").await;
    assert!(
        scoped_observed.contains("\"firehose\":false"),
        "scoped admin ready frame must report firehose=false: {scoped_observed}"
    );
    publish_audit_marker(
        &kernel.event_bus,
        bob.as_str(),
        "BobHiddenFromScopedAdminStream",
    );
    assert_sse_marker_absent(
        &mut scoped_response,
        &mut scoped_observed,
        "BobHiddenFromScopedAdminStream",
    )
    .await;
    publish_audit_marker(
        &kernel.event_bus,
        principal.as_str(),
        "CallerOwnScopedAdminStream",
    );
    wait_for_sse_marker(
        &mut scoped_response,
        &mut scoped_observed,
        "CallerOwnScopedAdminStream",
    )
    .await;
    assert!(!scoped_observed.contains("BobHiddenFromScopedAdminStream"));
}

async fn assert_live_audit_revocation(
    client: &reqwest::Client,
    address: std::net::SocketAddr,
    kernel: &astrid_kernel::Kernel,
    state: &GatewayState,
    principal: &PrincipalId,
    device_key_id: String,
    bearer: &str,
) {
    let url = format!("http://{address}/api/events");
    let mut response = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            match client.get(&url).bearer_auth(bearer).send().await {
                Ok(response) => return response,
                Err(_) => tokio::time::sleep(Duration::from_millis(25)).await,
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("gateway did not become ready at {url}"));
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let mut observed = String::new();
    wait_for_sse_marker(&mut response, &mut observed, "ready").await;

    publish_audit_marker(&kernel.event_bus, "bob", "BobVisibleBeforeRevocation");
    wait_for_sse_marker(&mut response, &mut observed, "BobVisibleBeforeRevocation").await;

    let revoke = state
        .admin_client(PrincipalId::default())
        .expect("admin client")
        .request(AdminRequestKind::PairDeviceRevoke {
            principal: principal.clone(),
            key_id: device_key_id,
        })
        .await
        .expect("revoke device");
    assert!(matches!(
        revoke,
        AdminResponseBody::PairDeviceRevoked { .. }
    ));

    publish_audit_marker(&kernel.event_bus, "bob", "BobHiddenAfterRevocation");
    assert_sse_marker_absent(&mut response, &mut observed, "BobHiddenAfterRevocation").await;
    publish_audit_marker(
        &kernel.event_bus,
        principal.as_str(),
        "CallerOwnAfterRevocation",
    );
    wait_for_sse_marker(&mut response, &mut observed, "CallerOwnAfterRevocation").await;
    assert_sse_marker_absent(&mut response, &mut observed, "BobHiddenAfterRevocation").await;
}

fn seed_audit_test_identity() -> (PrincipalId, String, String) {
    let principal = PrincipalId::new("audit-e2e-principal").unwrap();
    let audit_device = DeviceKey::new(
        "a".repeat(64),
        DeviceScope::Scoped {
            allow: vec!["audit:read_all".into()],
            deny: vec![],
        },
        Some("gateway-e2e".into()),
        0,
    );
    let audit_device_key_id = audit_device.key_id.clone();
    let self_list_device = DeviceKey::new(
        "b".repeat(64),
        DeviceScope::Scoped {
            allow: vec!["self:agent:list".into()],
            deny: vec!["audit:read_all".into()],
        },
        Some("gateway-e2e-self-list".into()),
        0,
    );
    let self_list_device_key_id = self_list_device.key_id.clone();
    let profile = PrincipalProfile {
        groups: vec!["admin".into()],
        auth: astrid_core::AuthConfig {
            methods: vec![AuthMethod::Keypair],
            public_keys: vec![audit_device, self_list_device],
        },
        ..PrincipalProfile::default()
    };
    let home = astrid_core::dirs::AstridHome::resolve().expect("ASTRID_HOME");
    profile
        .save_to_path(&PrincipalProfile::path_for(&home, &principal))
        .expect("save SSE principal profile");
    (principal, audit_device_key_id, self_list_device_key_id)
}

async fn check_live_audit_device_attenuation(
    kernel: &Arc<astrid_kernel::Kernel>,
    state: &Arc<GatewayState>,
    listener: tokio::net::TcpListener,
) {
    let address = listener.local_addr().expect("gateway listener address");
    let (principal, audit_device_key_id, self_list_device_key_id) = seed_audit_test_identity();

    let audit_bearer = astrid_gateway::auth::mint_bearer_scoped(
        &state.signing.signer,
        &principal,
        &audit_device_key_id,
        300,
    );
    let self_list_bearer = astrid_gateway::auth::mint_bearer_scoped(
        &state.signing.signer,
        &principal,
        &self_list_device_key_id,
        300,
    );
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server_state = Arc::clone(state);
    let policy_kernel = Arc::clone(kernel);
    let mut server = tokio::spawn(async move {
        astrid_gateway::run_with_capability_probe_on_listener(
            server_state,
            listener,
            async move {
                let _ = shutdown_rx.await;
            },
            move |principal, device_key_id, capability| {
                policy_kernel.runtime_capability_allows(principal, device_key_id, capability)
            },
        )
        .await
    });

    let client = reqwest::Client::new();
    let bob = PrincipalId::new("audit-e2e-bob").unwrap();
    assert_scoped_admin_audit_history(
        &client,
        address,
        kernel,
        &principal,
        &bob,
        &self_list_bearer,
    )
    .await;
    assert_scoped_admin_audit_stream(
        &client,
        address,
        kernel,
        &principal,
        &bob,
        &self_list_bearer,
    )
    .await;
    assert_live_audit_revocation(
        &client,
        address,
        kernel,
        state,
        &principal,
        audit_device_key_id,
        &audit_bearer,
    )
    .await;

    let _ = shutdown_tx.send(());
    if let Ok(result) = tokio::time::timeout(Duration::from_secs(3), &mut server).await {
        result.expect("gateway task").expect("gateway shutdown");
    } else {
        server.abort();
        let _ = server.await;
        panic!("gateway shutdown timed out");
    }
}

async fn check_unauthenticated_routes(router: Router) {
    let req = Request::builder()
        .uri("/api/distribution")
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.expect("distribution");
    assert_eq!(resp.status(), StatusCode::OK);

    let req = Request::builder()
        .uri("/api/openapi.json")
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.expect("openapi");
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let doc: serde_json::Value = serde_json::from_slice(&bytes).expect("openapi parses");
    assert!(
        doc["paths"]["/api/auth/redeem"].is_object(),
        "openapi spec must list /api/auth/redeem"
    );

    let req = Request::builder()
        .uri("/healthz")
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.expect("healthz");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "healthz must report 200 when the daemon socket exists"
    );
}

async fn check_audit_bus_roundtrip(event_bus: &astrid_events::EventBus) {
    let mut bus_rx = event_bus.subscribe_topic("astrid.v1.audit.entry");
    let payload = serde_json::json!({
        "ts_epoch": 1_700_000_000_u64,
        "method": "TestRoundTrip",
        "required_capability": "none",
        "principal": PrincipalId::default().to_string(),
        "target_principal": serde_json::Value::Null,
        "params": serde_json::Value::Null,
        "outcome": "success",
    });
    let msg = IpcMessage::new(
        Topic::audit_entry(),
        IpcPayload::RawJson(payload.clone()),
        uuid::Uuid::nil(),
    );
    event_bus.publish(AstridEvent::Ipc {
        metadata: astrid_events::EventMetadata::new("gateway_e2e_test"),
        message: msg,
    });

    let recv = tokio::time::timeout(std::time::Duration::from_secs(2), bus_rx.recv()).await;
    let event = recv
        .expect("audit event timed out within 2s — bus wiring is broken")
        .expect("event sender dropped before publish");
    if let AstridEvent::Ipc { message, .. } = &*event {
        if let IpcPayload::RawJson(v) = &message.payload {
            assert_eq!(
                v["method"], "TestRoundTrip",
                "payload must round-trip intact"
            );
        } else {
            panic!("expected RawJson payload, got {:?}", message.payload);
        }
    } else {
        panic!("expected Ipc event variant");
    }
}

async fn check_bearer_roundtrip(router: Router, state: &GatewayState) {
    let pid = PrincipalId::new("e2e-test-principal").unwrap();
    let bearer = astrid_gateway::auth::mint_bearer(&state.signing.signer, &pid, 3600);
    let caller = astrid_gateway::auth::verify_bearer(state, &bearer)
        .expect("gateway must verify its own bearer");
    assert_eq!(caller.principal, pid);

    let req = Request::builder()
        .uri("/api/auth/me")
        .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.expect("me");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "valid bearer must reach /api/auth/me — middleware is broken otherwise"
    );
    let bytes = to_bytes(resp.into_body(), 4096).await.unwrap();
    let me: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(me["principal"], "e2e-test-principal");

    check_agent_fail_fast(router, &bearer).await;
}

async fn check_agent_fail_fast(router: Router, bearer: &str) {
    let req = Request::builder()
        .method("POST")
        .uri("/api/agent/prompt")
        .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"text":"hi"}"#))
        .unwrap();
    let resp = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        router.clone().oneshot(req),
    )
    .await
    .expect("fail-fast must close the stream, not hang")
    .expect("prompt");
    assert_eq!(resp.status(), StatusCode::OK, "SSE responses are 200");
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let body = std::str::from_utf8(&bytes).unwrap();
    assert!(
        body.contains("agent loop not ready"),
        "fail-fast must name the unconfigured loop; body: {body}"
    );
    assert!(
        !body.contains("event:ready") && !body.contains("event: ready"),
        "must NOT emit a ready event on the fail-fast path; body: {body}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kernel_and_gateway_boot_against_shared_home() {
    let home_dir = tempfile::tempdir().expect("tempdir");
    set_astrid_home(&home_dir);

    let workspace = home_dir.path().join("workspace");
    std::fs::create_dir_all(&workspace).expect("workspace dir");

    let session_id = astrid_core::SessionId::new();
    let kernel = match astrid_kernel::Kernel::new(
        session_id.clone(),
        workspace.clone(),
        astrid_capsule::CapsuleRuntimeLimits::default(),
        std::collections::HashMap::new(),
        astrid_capsule::HttpLimits::default(),
    )
    .await
    {
        Ok(k) => k,
        Err(e) if looks_like_sandbox_block(&e) => {
            eprintln!("skipping: sandbox blocks Unix socket bind: {e}");
            return;
        },
        Err(e) => panic!("kernel boot failed: {e}"),
    };

    // ── Kernel boot artefacts on disk ───────────────────────────
    let home = astrid_core::dirs::AstridHome::resolve().expect("ASTRID_HOME");
    assert!(
        astrid_core::local_transport::endpoint_is_present(&home.socket_path())
            .expect("inspect kernel endpoint"),
        "kernel must bind the Unix socket at $ASTRID_HOME/run/system.sock"
    );
    // KV store + audit DB live under the home; presence proves boot
    // ran the persistence init.
    assert!(
        home.state_db_path().parent().expect("kv parent").exists(),
        "kernel must create the persistent KV directory"
    );

    // ── Gateway state shares the same home ──────────────────────
    //
    // Building it loads / generates the signing key at
    // $ASTRID_HOME/keys/gateway.ed25519 — the first boot writes,
    // every subsequent boot loads. Both paths are covered by the
    // SigningMaterial unit tests; here we just confirm the on-disk
    // artefact lands.
    let gateway_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind gateway listener");
    let gateway_address = gateway_listener
        .local_addr()
        .expect("gateway listener address");
    let gateway_config = GatewayConfig {
        listen: gateway_address.to_string(),
        ..GatewayConfig::default()
    };
    let state = GatewayState::new(
        gateway_config,
        Some(Arc::clone(&kernel.event_bus)),
        Some(Arc::clone(&kernel.audit_log)),
        Some(kernel.session_id.clone()),
        Some(kernel.agent_readiness_probe()),
        Some(kernel.capsule_topic_probe()),
    )
    .expect("gateway state");
    let key_path = home.root().join("keys").join("gateway.ed25519");
    assert!(
        key_path.exists(),
        "gateway must persist its signing key at $ASTRID_HOME/keys/gateway.ed25519"
    );

    // ── Unauthenticated routes against the live state ────────────
    let router = routes::build(Arc::clone(&state));
    check_unauthenticated_routes(router.clone()).await;

    // ── Audit event bus round-trip ──────────────────────────────
    //
    // Subscribe to the same topic the SSE handler uses, then
    // publish a synthetic audit event via the kernel's bus and
    // confirm it reaches us. This proves the bus → SSE wiring
    // (everything below the HTTP layer) works against the live
    // kernel.
    check_audit_bus_roundtrip(&kernel.event_bus).await;

    // ── Bearer / verify round-trip + agent fail-fast ──
    //
    // Exercises the gateway's own signing key and confirms the
    // agent-loop fail-fast path closes immediately when no capsule
    // is loaded.
    check_bearer_roundtrip(router, &state).await;

    check_live_audit_device_attenuation(&kernel, &state, gateway_listener).await;

    // ── Cleanup ─────────────────────────────────────────────────
    kernel.shutdown(Some("e2e-test-complete".into())).await;
}
