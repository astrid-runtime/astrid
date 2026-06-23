//! Gateway HTTPS smoke test against a self-signed cert.
//!
//! Proves that the gateway's optional `[tls]` block actually
//! terminates TLS — boots the gateway with a self-signed
//! `rcgen`-generated cert+key, fires a real `reqwest` HTTPS request
//! at `/api/openapi.json`, and checks the response. Without this test, the
//! TLS wiring is one parse-failure away from silently regressing.
//!
//! Generating the cert at test time (rather than checking one into
//! `tests/fixtures/`) avoids the maintenance burden of rotating an
//! expired test cert and the security-scanner false positives a
//! checked-in cert tends to attract.
//!
//! The TLS test runs without the kernel — `GatewayState::new` just
//! reads the cert + key from disk and starts axum-server. The kernel
//! is exercised independently in `gateway_e2e.rs`; we don't need both
//! moving parts here.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use astrid_gateway::{
    GatewayConfig, GatewayState,
    config::TlsConfig,
    routes::distribution::{DistributionInfo, OnboardingFields},
    state::SigningMaterial,
};

/// Write a self-signed cert + private key into the tempdir and
/// return the paths. The cert covers `localhost` so a `reqwest`
/// client with rustls' usual hostname checks (disabled in our test
/// via `danger_accept_invalid_certs`) parses it cleanly either way.
fn mint_self_signed(dir: &std::path::Path) -> (PathBuf, PathBuf) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])
        .expect("rcgen self-signed cert");
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    std::fs::write(&cert_path, cert.cert.pem()).expect("write cert");
    std::fs::write(&key_path, cert.key_pair.serialize_pem()).expect("write key");
    (cert_path, key_path)
}

/// Build a `GatewayState` configured to terminate TLS on `bind_addr`.
fn tls_state(bind_addr: SocketAddr, cert_path: PathBuf, key_path: PathBuf) -> Arc<GatewayState> {
    let cfg = GatewayConfig {
        enabled: true,
        listen: bind_addr.to_string(),
        tls: Some(TlsConfig {
            cert_path,
            key_path,
        }),
        ..GatewayConfig::default()
    };
    cfg.validate().expect("TLS config validates");
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
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gateway_terminates_tls_for_openapi_endpoint() {
    // Bind to 127.0.0.1:0 so the kernel picks a free port — running
    // tests in parallel must not collide on a fixed port.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("ephemeral bind");
    let addr = listener.local_addr().expect("local addr");
    drop(listener); // free the port; axum-server opens its own listener

    let tempdir = tempfile::tempdir().expect("tempdir");
    let (cert_path, key_path) = mint_self_signed(tempdir.path());

    let state = tls_state(addr, cert_path, key_path);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let server = tokio::spawn(async move {
        astrid_gateway::run(state, async move {
            let _ = shutdown_rx.await;
        })
        .await
    });

    // Wait for the listener to come up. axum-server doesn't expose a
    // ready-signal, so poll a short loop. The TLS handshake itself is
    // what proves readiness — pre-TLS the TCP accept may succeed but
    // the rustls layer would reject.
    let client = reqwest::Client::builder()
        // Self-signed cert means we have to skip cert chain
        // verification *in the test* — this is the standard pattern
        // for in-process TLS smoke tests; production callers
        // present a real cert.
        .danger_accept_invalid_certs(true)
        .build()
        .expect("build reqwest");

    let url = format!("https://{addr}/api/openapi.json");
    let mut last_err: Option<reqwest::Error> = None;
    let mut response = None;
    for _ in 0..50 {
        match client.get(&url).send().await {
            Ok(r) => {
                response = Some(r);
                break;
            },
            Err(e) => last_err = Some(e),
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    // Drain the gateway *before* asserting so an assert-panic doesn't
    // leak the server task. `let _` on the send is fine — if shutdown
    // already happened (server exited early), the receiver is gone.
    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), server)
        .await
        .expect("server shut down within 5s");

    let response = response.unwrap_or_else(|| {
        panic!(
            "TLS gateway never responded at {url}; last error: {:?}",
            last_err
        )
    });
    assert!(
        response.status().is_success(),
        "openapi: {}",
        response.status()
    );
    // HSTS must be set on the TLS path (RFC 6797 only meaningful
    // over a real https:// origin, so we wire it conditionally).
    let hsts = response
        .headers()
        .get("strict-transport-security")
        .expect("HSTS must be set on TLS responses")
        .to_str()
        .unwrap();
    assert!(
        hsts.contains("max-age=") && hsts.contains("includeSubDomains"),
        "HSTS must carry max-age + includeSubDomains: {hsts}"
    );
}

#[tokio::test]
async fn missing_cert_path_refuses_boot() {
    // The validate() path is the one that catches this; double-check
    // the integration shape so a daemon-side regression (e.g. some
    // future refactor that drops the validate() call) is caught.
    let cfg = GatewayConfig {
        enabled: true,
        listen: "127.0.0.1:0".into(),
        tls: Some(TlsConfig {
            cert_path: PathBuf::from("/dev/null/does/not/exist.pem"),
            key_path: PathBuf::from("/dev/null/does/not/exist.key"),
        }),
        ..GatewayConfig::default()
    };
    let err = cfg.validate().expect_err("missing cert must refuse boot");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("cert-path"),
        "boot-refusal message must surface cert-path: {msg}"
    );
}

#[tokio::test]
async fn plain_http_path_still_works_when_no_tls_block() {
    // Regression: the TLS dispatch in `gateway::run` must not break
    // the existing plain-HTTP path. With `tls = None`, the gateway
    // boots over plain HTTP as before.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("ephemeral bind");
    let addr = listener.local_addr().expect("local addr");
    drop(listener);

    let cfg = GatewayConfig {
        enabled: true,
        listen: addr.to_string(),
        tls: None,
        ..GatewayConfig::default()
    };
    cfg.validate().expect("no-tls config validates");
    let state = Arc::new(GatewayState {
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
    });

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        astrid_gateway::run(state, async move {
            let _ = shutdown_rx.await;
        })
        .await
    });

    let client = reqwest::Client::builder().build().expect("build reqwest");
    let url = format!("http://{addr}/api/openapi.json");
    let mut response = None;
    for _ in 0..50 {
        if let Ok(r) = client.get(&url).send().await {
            response = Some(r);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), server)
        .await
        .expect("server shut down within 5s");

    let response =
        response.unwrap_or_else(|| panic!("plain-HTTP gateway never responded at {url}"));
    assert!(
        response.status().is_success(),
        "openapi: {}",
        response.status()
    );
    // HSTS over plain HTTP is forbidden by RFC 6797 — browsers
    // ignore it on http:// origins, but emitting it would still be
    // a footgun if someone reverse-proxies this output back to
    // plain HTTP downstream. Pin the absence.
    assert!(
        response
            .headers()
            .get("strict-transport-security")
            .is_none(),
        "HSTS must NOT be set on plain HTTP responses (RFC 6797)"
    );
}
