//! Unit tests for the `astrid:http` host implementation (SSRF airlock,
//! local-egress allowlist, redirect policy). Split out via `#[path]` to keep
//! the module files under the file-size cap.

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use super::ErrorCode;
use super::ssrf::{
    MAX_HTTP_REDIRECTS, RedirectAction, classify_redirect, egress_allowed, egress_decision,
    filter_safe_addrs, is_safe_ip, literal_ip,
};

fn ip(s: &str) -> IpAddr {
    IpAddr::from_str(s).unwrap()
}

#[test]
fn safe_public_ips() {
    assert!(is_safe_ip(IpAddr::from_str("8.8.8.8").unwrap()));
    assert!(is_safe_ip(IpAddr::from_str("1.1.1.1").unwrap()));
    assert!(is_safe_ip(IpAddr::from_str("198.51.100.1").unwrap()));
    assert!(is_safe_ip(
        IpAddr::from_str("2001:4860:4860::8888").unwrap()
    ));
}

#[test]
fn blocks_loopback_and_unspecified() {
    assert!(!is_safe_ip(IpAddr::from_str("127.0.0.1").unwrap()));
    assert!(!is_safe_ip(IpAddr::from_str("::1").unwrap()));
    assert!(!is_safe_ip(IpAddr::from_str("0.0.0.0").unwrap()));
    assert!(!is_safe_ip(IpAddr::from_str("::").unwrap()));
}

#[test]
fn blocks_zero_block() {
    assert!(!is_safe_ip(IpAddr::from_str("0.0.0.1").unwrap()));
    assert!(!is_safe_ip(IpAddr::from_str("0.255.255.255").unwrap()));
}

#[test]
fn blocks_rfc1918_private() {
    assert!(!is_safe_ip(IpAddr::from_str("10.0.0.1").unwrap()));
    assert!(!is_safe_ip(IpAddr::from_str("10.255.255.255").unwrap()));
    assert!(!is_safe_ip(IpAddr::from_str("172.16.0.1").unwrap()));
    assert!(!is_safe_ip(IpAddr::from_str("172.31.255.255").unwrap()));
    assert!(!is_safe_ip(IpAddr::from_str("192.168.0.1").unwrap()));
    assert!(!is_safe_ip(IpAddr::from_str("192.168.255.255").unwrap()));
}

#[test]
fn blocks_link_local_and_cgnat() {
    assert!(!is_safe_ip(IpAddr::from_str("169.254.169.254").unwrap()));
    assert!(!is_safe_ip(IpAddr::from_str("100.64.0.1").unwrap()));
    assert!(!is_safe_ip(IpAddr::from_str("100.127.255.255").unwrap()));
}

#[test]
fn blocks_private_ipv6() {
    assert!(!is_safe_ip(IpAddr::from_str("fc00::1").unwrap()));
    assert!(!is_safe_ip(IpAddr::from_str("fd00::1").unwrap()));
    assert!(!is_safe_ip(IpAddr::from_str("fe80::1").unwrap()));
}

#[test]
fn blocks_ipv4_mapped_ipv6_bypass() {
    assert!(!is_safe_ip(IpAddr::from_str("::ffff:127.0.0.1").unwrap()));
    assert!(!is_safe_ip(IpAddr::from_str("::ffff:10.0.0.1").unwrap()));
    assert!(!is_safe_ip(
        IpAddr::from_str("::ffff:169.254.169.254").unwrap()
    ));
}

#[test]
fn blocks_ipv4_compatible_ipv6_bypass() {
    assert!(!is_safe_ip(IpAddr::from_str("::127.0.0.1").unwrap()));
    assert!(!is_safe_ip(IpAddr::from_str("::10.0.0.1").unwrap()));
    assert!(!is_safe_ip(IpAddr::from_str("::169.254.169.254").unwrap()));
    assert!(!is_safe_ip(IpAddr::from_str("::0.0.0.1").unwrap()));
}

#[test]
fn blocks_nat64_embedded_private_ipv4() {
    // NAT64 well-known prefix 64:ff9b::/96 embedding private/metadata IPv4.
    assert!(!is_safe_ip(ip("64:ff9b::7f00:1"))); // -> 127.0.0.1
    assert!(!is_safe_ip(ip("64:ff9b::a00:1"))); // -> 10.0.0.1
    assert!(!is_safe_ip(ip("64:ff9b::c0a8:1"))); // -> 192.168.0.1
    assert!(!is_safe_ip(ip("64:ff9b::a9fe:a9fe"))); // -> 169.254.169.254 (cloud metadata)
}

#[test]
fn blocks_6to4_embedded_private_ipv4() {
    // 6to4 2002::/16 embedding private IPv4 in bits 16..48.
    assert!(!is_safe_ip(ip("2002:7f00:1::"))); // -> 127.0.0.1
    assert!(!is_safe_ip(ip("2002:c0a8:1::"))); // -> 192.168.0.1
    assert!(!is_safe_ip(ip("2002:a9fe:a9fe::"))); // -> 169.254.169.254
}

#[test]
fn blocks_teredo_embedded_private_ipv4() {
    // Teredo 2001:0::/32 server IPv4 (bits 32..64) is loopback.
    assert!(!is_safe_ip(ip("2001:0:7f00:1::"))); // server -> 127.0.0.1
    // Public server (8.8.8.8) but private client: the client IPv4 is
    // the bitwise-NOT of the last 32 bits — !f5ff:!fffe == 0a00:0001
    // == 10.0.0.1. Must still be blocked.
    assert!(!is_safe_ip(ip("2001:0:808:808:0:0:f5ff:fffe")));
}

#[test]
fn embedded_transition_with_public_ipv4_stays_safe() {
    // A transition address embedding a *public* IPv4 must not be
    // over-blocked: only embedded private/loopback ranges are rejected.
    assert!(is_safe_ip(ip("64:ff9b::808:808"))); // NAT64 -> 8.8.8.8
    assert!(is_safe_ip(ip("2002:808:808::"))); // 6to4 -> 8.8.8.8
}

#[test]
fn literal_ip_parses_literals_not_domains() {
    assert_eq!(literal_ip("127.0.0.1"), Some(ip("127.0.0.1")));
    assert_eq!(literal_ip("8.8.8.8"), Some(ip("8.8.8.8")));
    assert_eq!(literal_ip("[::1]"), Some(ip("::1")));
    assert_eq!(
        literal_ip("[2606:4700:4700::1111]"),
        Some(ip("2606:4700:4700::1111"))
    );
    assert_eq!(literal_ip("example.com"), None);
    assert_eq!(literal_ip("localhost"), None);
    // Non-canonical numeric forms are not IP literals here; they fall
    // through to the resolver, which airlocks the resolved address.
    assert_eq!(literal_ip("2130706433"), None);
}

#[test]
fn preflight_blocks_ip_literal_local_urls() {
    // The IP-literal SSRF bypass: these never reach SafeDnsResolver,
    // so the pre-flight is the only thing that blocks them. No allowlist.
    for url in [
        "http://127.0.0.1:1234/",
        "http://192.168.1.5:1234/v1/chat/completions",
        "http://[::1]:1234/",
        "http://169.254.169.254/latest/meta-data/",
    ] {
        assert!(
            matches!(egress_decision(&[], url), Err(ErrorCode::AirlockRejected)),
            "expected airlock rejection for {url}"
        );
    }
}

#[test]
fn preflight_allows_public_literals_and_hostnames() {
    // Public IP literals pass; hostnames pass pre-flight (the resolver
    // airlocks them later). Ok(None) == not exempt, proceed normally.
    assert!(matches!(egress_decision(&[], "https://8.8.8.8/"), Ok(None)));
    assert!(matches!(
        egress_decision(&[], "https://api.openai.com/v1/models"),
        Ok(None)
    ));
    assert!(matches!(
        egress_decision(&[], "http://localhost:1234/"),
        Ok(None)
    ));
}

#[test]
fn preflight_rejects_unparsable_url() {
    assert!(matches!(
        egress_decision(&[], "not a url"),
        Err(ErrorCode::InvalidRequest)
    ));
}

#[test]
fn egress_allowlist_exempts_matching_host_port() {
    let allow = vec!["127.0.0.1:1234".to_string(), "localhost:1234".to_string()];

    // Allowlisted private literal -> exempt (NOT airlock-rejected), and
    // the exempt host is the literal itself.
    assert!(matches!(
        egress_decision(&allow, "http://127.0.0.1:1234/v1/chat/completions"),
        Ok(Some(ref h)) if &**h == "127.0.0.1"
    ));
    // Allowlisted hostname -> exempt host propagated for the resolver.
    assert!(matches!(
        egress_decision(&allow, "http://localhost:1234/v1/models"),
        Ok(Some(ref h)) if &**h == "localhost"
    ));
}

#[test]
fn egress_allowlist_is_port_specific() {
    let allow = vec!["127.0.0.1:1234".to_string()];
    // Wrong port: not exempt, and (private literal) still airlock-rejected.
    assert!(matches!(
        egress_decision(&allow, "http://127.0.0.1:9999/"),
        Err(ErrorCode::AirlockRejected)
    ));
    // Wrong port on a hostname: not exempt -> Ok(None) (resolver airlocks).
    assert!(matches!(
        egress_decision(&allow, "http://localhost:9999/"),
        Ok(None)
    ));
    // Wildcard port matches any port.
    let any = vec!["127.0.0.1:*".to_string()];
    assert!(matches!(
        egress_decision(&any, "http://127.0.0.1:9999/"),
        Ok(Some(_))
    ));
}

#[test]
fn egress_allowlist_does_not_exempt_other_hosts() {
    let allow = vec!["127.0.0.1:1234".to_string()];
    // A different private literal is still rejected.
    assert!(matches!(
        egress_decision(&allow, "http://10.0.0.5:1234/"),
        Err(ErrorCode::AirlockRejected)
    ));
    // egress_allowed host:port matching.
    assert!(egress_allowed(&allow, "127.0.0.1", 1234));
    assert!(!egress_allowed(&allow, "127.0.0.1", 1235));
    assert!(!egress_allowed(&allow, "10.0.0.5", 1234));
}

#[test]
fn resolver_exempt_host_keeps_private_addrs() {
    let loopback = SocketAddr::from(([127, 0, 0, 1], 1234));
    // Exempt: keep the private address, no trip.
    let (safe, saw) = filter_safe_addrs([loopback].into_iter(), true);
    assert_eq!(safe, vec![loopback]);
    assert!(!saw);
    // Not exempt: dropped + trip.
    let (safe, saw) = filter_safe_addrs([loopback].into_iter(), false);
    assert!(safe.is_empty());
    assert!(saw);
}

#[test]
fn redirect_blocks_ip_literal_targets() {
    // Redirect SSRF: a 302 Location pointing at an IP literal never
    // reaches the resolver, so the policy must block it per hop.
    assert_eq!(
        classify_redirect(Some("127.0.0.1"), 0, MAX_HTTP_REDIRECTS),
        RedirectAction::Block
    );
    assert_eq!(
        classify_redirect(Some("[::1]"), 0, MAX_HTTP_REDIRECTS),
        RedirectAction::Block
    );
    assert_eq!(
        classify_redirect(Some("169.254.169.254"), 0, MAX_HTTP_REDIRECTS),
        RedirectAction::Block
    );
    assert_eq!(
        classify_redirect(Some("10.0.0.5"), 2, MAX_HTTP_REDIRECTS),
        RedirectAction::Block
    );
}

#[test]
fn redirect_follows_safe_targets_within_cap() {
    // Hostnames are airlocked by the resolver, public literals are
    // safe; both follow until the hop cap.
    assert_eq!(
        classify_redirect(Some("example.com"), 0, MAX_HTTP_REDIRECTS),
        RedirectAction::Follow
    );
    assert_eq!(
        classify_redirect(Some("8.8.8.8"), 0, MAX_HTTP_REDIRECTS),
        RedirectAction::Follow
    );
    assert_eq!(
        classify_redirect(None, 0, MAX_HTTP_REDIRECTS),
        RedirectAction::Follow
    );
    assert_eq!(
        classify_redirect(Some("example.com"), MAX_HTTP_REDIRECTS, MAX_HTTP_REDIRECTS),
        RedirectAction::Stop
    );
}

/// A configured redirect ceiling BELOW the default stops following at the lower
/// bound — proving `classify_redirect` honours the passed ceiling, not the const.
#[test]
fn redirect_honours_configured_ceiling() {
    // 3 prior hops with a ceiling of 3 must Stop; with the default ceiling of
    // 10 the same hop count still Follows.
    assert_eq!(
        classify_redirect(Some("example.com"), 3, 3),
        RedirectAction::Stop
    );
    assert_eq!(
        classify_redirect(Some("example.com"), 3, MAX_HTTP_REDIRECTS),
        RedirectAction::Follow
    );
}

#[test]
fn filter_safe_addrs_reports_airlock_trip() {
    let loopback = SocketAddr::from(([127, 0, 0, 1], 1234));
    let public = SocketAddr::from(([8, 8, 8, 8], 443));

    // All-unsafe -> empty safe set, saw_unsafe true (the airlock trip).
    let (safe, saw) = filter_safe_addrs([loopback].into_iter(), false);
    assert!(safe.is_empty());
    assert!(saw);

    // Mixed -> drop unsafe, keep public, no trip (request proceeds).
    let (safe, saw) = filter_safe_addrs([loopback, public].into_iter(), false);
    assert_eq!(safe, vec![public]);
    assert!(saw);

    // Empty input is a resolution miss, not an airlock trip.
    let (safe, saw) = filter_safe_addrs(std::iter::empty(), false);
    assert!(safe.is_empty());
    assert!(!saw);
}

/// A runtime consent grant must re-enter the EXEMPT path, returning the same
/// `Ok(Some(host))` an operator pre-bless yields — so the consent-granted
/// endpoint resolves its private literal AND refuses redirects identically
/// (spec 8). A `LocalSocket` caller with an already-cached per-principal grant
/// takes the existing-grant fast path (no elicitation), so this is hermetic.
/// The complementary System/RemoteGateway case stays `Err(AirlockRejected)`.
#[tokio::test(flavor = "multi_thread")]
async fn consent_grant_yields_exempt_host() {
    use std::sync::Arc;

    use astrid_approval::{Allowance, AllowanceId, AllowancePattern, AllowanceStore};
    use astrid_core::principal::PrincipalId;
    use astrid_core::types::Timestamp;
    use astrid_crypto::KeyPair;
    use astrid_events::ipc::{IpcMessage, IpcPayload, MessageOrigin, Topic};

    use crate::engine::wasm::test_fixtures::minimal_host_state;

    let rt = tokio::runtime::Handle::current();
    let mut state = minimal_host_state(rt);
    let store = Arc::new(AllowanceStore::new());
    let alice = PrincipalId::new("alice").unwrap();
    // Pre-cache the per-principal, per-capsule grant (same shape
    // `consent_local_egress` writes) so the consent call short-circuits on the
    // existing-grant fast path — no blocking elicitation needed for this
    // hermetic test. `capsule_id` must match the fixture's ("test"), since the
    // gate keys the lookup on the requesting capsule.
    let keypair = KeyPair::generate();
    store
        .add_allowance(Allowance {
            id: AllowanceId::new(),
            principal: alice.clone(),
            action_pattern: AllowancePattern::NetworkHost {
                capsule_id: "test".to_string(),
                host: "127.0.0.1".to_string(),
                ports: Some(vec![1234]),
            },
            created_at: Timestamp::now(),
            expires_at: None,
            max_uses: None,
            uses_remaining: None,
            session_only: true,
            workspace_root: None,
            signature: keypair.sign(b"test"),
        })
        .unwrap();
    state.allowance_store = Some(store);
    state.caller_context = Some(
        IpcMessage::new(Topic::from_raw("t"), IpcPayload::Connect, uuid::Uuid::nil())
            .with_principal("alice")
            .with_origin(MessageOrigin::LocalSocket),
    );

    // Granted local-operator endpoint → exempt host returned (re-enters exempt
    // path).
    let decision = state.egress_decision_with_consent("http://127.0.0.1:1234/v1/models");
    assert_eq!(
        decision.unwrap().as_deref(),
        Some("127.0.0.1"),
        "a consent-granted endpoint must return the exempt host"
    );

    // Same endpoint, but the request is NOT local (RemoteGateway): no grant
    // applies to the origin gate, so it stays airlock-rejected.
    state.caller_context = Some(
        IpcMessage::new(Topic::from_raw("t"), IpcPayload::Connect, uuid::Uuid::nil())
            .with_principal("alice")
            .with_origin(MessageOrigin::RemoteGateway),
    );
    let decision = state.egress_decision_with_consent("http://127.0.0.1:1234/v1/models");
    assert!(
        matches!(decision, Err(ErrorCode::AirlockRejected)),
        "a remote-origin request to the same endpoint must stay airlock-rejected"
    );
}

// ── End-to-end redirect / per-hop-gate tests (unified manual-follow) ───────
//
// These drive the real `http_request_backend` / `http_stream_backend` against
// a loopback test server, exercising the production manual-follow loop (no
// reqwest redirect policy). Binding a loopback listener is blocked in some
// sandboxes — skip gracefully there (mirrors the gateway e2e tests); CI binds.

mod e2e {
    use std::sync::Arc;

    use async_trait::async_trait;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use crate::engine::wasm::host::http::tests::ErrorCode;
    use crate::engine::wasm::test_fixtures::minimal_host_state;
    use crate::security::{AllowAllGate, CapsuleSecurityGate, IdentityOperation};

    use super::super::{HttpMethod, HttpRequestData, RedirectPolicy, RequestOptions};

    /// A gate that denies any HTTP request whose URL contains `needle`, and
    /// permits everything else. Used to prove the async `check_http_request`
    /// gate runs on a per-hop URL inside the follow loop.
    #[derive(Debug)]
    struct HostDenyGate {
        needle: String,
    }

    #[async_trait]
    impl CapsuleSecurityGate for HostDenyGate {
        async fn check_http_request(
            &self,
            capsule_id: &str,
            method: &str,
            url: &str,
        ) -> Result<(), String> {
            if url.contains(&self.needle) {
                Err(format!(
                    "capsule '{capsule_id}' denied: {method} {url} (HostDenyGate)"
                ))
            } else {
                Ok(())
            }
        }

        async fn check_file_read(
            &self,
            _capsule_id: &str,
            _path: &str,
            _principal_home: Option<&std::path::Path>,
        ) -> Result<(), String> {
            Ok(())
        }

        async fn check_file_write(
            &self,
            _capsule_id: &str,
            _path: &str,
            _principal_home: Option<&std::path::Path>,
        ) -> Result<(), String> {
            Ok(())
        }

        async fn check_host_process(
            &self,
            _capsule_id: &str,
            _command: &str,
        ) -> Result<(), String> {
            Ok(())
        }

        async fn check_identity(
            &self,
            _capsule_id: &str,
            _operation: IdentityOperation,
        ) -> Result<(), String> {
            Ok(())
        }
    }

    /// Spawn a one-shot loopback server returning `response` verbatim. Returns
    /// `None` (test should skip) if the sandbox blocks the loopback bind.
    async fn one_shot_server(
        response: &'static [u8],
    ) -> Option<(std::net::SocketAddr, tokio::task::JoinHandle<()>)> {
        let listener = match TcpListener::bind("127.0.0.1:0").await {
            Ok(l) => l,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("skipping: sandbox blocks loopback bind: {e}");
                return None;
            },
            Err(e) => panic!("loopback bind failed: {e}"),
        };
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let _ = sock.write_all(response).await;
                let _ = sock.flush().await;
            }
        });
        Some((addr, handle))
    }

    fn get_request(url: String) -> HttpRequestData {
        HttpRequestData {
            url,
            method: HttpMethod::Get,
            headers: Vec::new(),
            body: None,
        }
    }

    fn follow_opts() -> RequestOptions {
        RequestOptions {
            timeouts: None,
            redirect: Some(RedirectPolicy::Follow),
            max_redirects: None,
            max_response_bytes: None,
            max_decompressed_bytes: None,
            auto_decompress: None,
            https_only: None,
            integrity: None,
        }
    }

    /// EXEMPT-NO-FOLLOW on the unified BUFFERED path: an operator-allowlisted
    /// loopback endpoint that returns a 302 is NOT followed — the 302 is the
    /// terminal response. Following would let a `30x` escape the port-scoped
    /// allowlist onto another port/host. `redirect = Follow` is set explicitly
    /// to prove the exempt rule overrides the follow policy.
    #[tokio::test]
    async fn exempt_request_does_not_follow_redirects_buffered() {
        let Some((addr, server)) = one_shot_server(
            b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/\r\nContent-Length: 0\r\n\r\n",
        )
        .await
        else {
            return;
        };

        let rt = tokio::runtime::Handle::current();
        let mut state = minimal_host_state(rt);
        state.security = Some(Arc::new(AllowAllGate));
        state.local_egress = vec![format!("127.0.0.1:{}", addr.port())];

        let limits = state.http_limits;
        let resp = state
            .http_request_backend(
                get_request(format!("http://{addr}/")),
                super::super::options::ResolvedOptions::from_options(follow_opts(), &limits),
            )
            .await
            .expect("exempt 302 should be returned, not followed");

        assert_eq!(
            resp.status, 302,
            "exempt request must not follow redirects (would widen the port-scoped allowlist)"
        );
        let _ = server.await;
    }

    /// EXEMPT-NO-FOLLOW on the unified STREAMING path: same rule via
    /// `http_stream_backend` — the stream resource carries the 302 status, the
    /// redirect is not followed.
    #[tokio::test]
    async fn exempt_stream_does_not_follow_redirects() {
        let Some((addr, server)) = one_shot_server(
            b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/\r\nContent-Length: 0\r\n\r\n",
        )
        .await
        else {
            return;
        };

        let rt = tokio::runtime::Handle::current();
        let mut state = minimal_host_state(rt);
        state.security = Some(Arc::new(AllowAllGate));
        state.local_egress = vec![format!("127.0.0.1:{}", addr.port())];

        let limits = state.http_limits;
        let resource = state
            .http_stream_backend(
                get_request(format!("http://{addr}/")),
                super::super::options::ResolvedOptions::from_options(follow_opts(), &limits),
            )
            .await
            .expect("exempt streaming 302 should open a stream, not follow");

        assert_eq!(
            super::super::backend::stream_status(&mut state, resource.rep()),
            302,
            "exempt streaming request must not follow redirects"
        );
        let _ = server.await;
    }

    /// THE GAP CLOSED: the STREAMING follow path now re-runs the async
    /// `check_http_request` gate on every hop via the shared manual-follow
    /// loop (`follow_redirects` → `send_one_hop`). This test denies the
    /// request URL at the gate and confirms `http_stream_backend` rejects with
    /// `CapabilityDenied` — the gate runs in `send_one_hop`, the exact per-hop
    /// call the redirect loop makes for the redirect TARGET on every hop. No
    /// network is reached (the gate denies before connect), so it is hermetic.
    #[tokio::test]
    async fn streaming_request_runs_async_gate_per_hop() {
        let rt = tokio::runtime::Handle::current();
        let mut state = minimal_host_state(rt);
        state.security = Some(Arc::new(HostDenyGate {
            needle: "denied.example".to_string(),
        }));

        let limits = state.http_limits;
        let err = state
            .http_stream_backend(
                get_request("https://denied.example.invalid/v1/stream".to_string()),
                super::super::options::ResolvedOptions::from_options(follow_opts(), &limits),
            )
            .await
            .expect_err("the gate must deny this host on the streaming path");

        assert!(
            matches!(err, ErrorCode::CapabilityDenied),
            "streaming path must route through the async gate (got {err:?})"
        );
    }
}

// ── @1.1.0 request-options ─────────────────────────────────────────────

mod v11 {
    use std::time::Duration;

    use reqwest::header::{HeaderMap, HeaderValue};

    use super::super::options::{
        ResolvedOptions, check_scheme, same_origin, strip_credentials, verify_integrity,
    };
    use super::super::{ErrorCode, RedirectPolicy, RequestOptions, TimeoutConfig};
    use crate::engine::wasm::limits::HttpLimits;

    /// Default host limits (the historical constants) for option-resolution
    /// tests — the path that resolves against config-supplied limits.
    fn limits() -> HttpLimits {
        HttpLimits::default()
    }

    fn empty_options() -> RequestOptions {
        RequestOptions {
            timeouts: None,
            redirect: None,
            max_redirects: None,
            max_response_bytes: None,
            max_decompressed_bytes: None,
            auto_decompress: None,
            https_only: None,
            integrity: None,
        }
    }

    /// An empty `request-options` must resolve to exactly the @1.0.0 defaults:
    /// follow redirects ≤10, 30s total timeout, 10 MB body cap, decompress on,
    /// no https-only, no SRI. This is the contract guarantee that backs the
    /// @1.0.0 shim delegating to the @1.1.0 backend.
    #[test]
    fn empty_options_reproduce_v10_defaults() {
        let limits = limits();
        let resolved = ResolvedOptions::from_options(empty_options(), &limits);
        let defaults = ResolvedOptions::v10_defaults(&limits);

        assert_eq!(resolved.total_timeout, Some(limits.default_total_timeout));
        assert_eq!(resolved.connect_timeout, None);
        assert_eq!(resolved.between_bytes_timeout, None);
        assert!(matches!(resolved.redirect, RedirectPolicy::Follow));
        assert_eq!(resolved.max_redirects, defaults.max_redirects);
        assert_eq!(resolved.max_response_bytes, defaults.max_response_bytes);
        assert!(resolved.auto_decompress);
        assert!(!resolved.https_only);
        assert!(resolved.integrity.is_none());
        assert!(resolved.total_was_default());
    }

    /// Caller-set option fields override the host defaults; the buffered body
    /// cap is clamped to the hard `MAX_GUEST_PAYLOAD_LEN` ceiling and never
    /// raised above it.
    #[test]
    fn options_override_and_clamp() {
        let opts = RequestOptions {
            timeouts: Some(TimeoutConfig {
                connect_ms: Some(1_000),
                first_byte_ms: Some(2_000),
                between_bytes_ms: Some(3_000),
                total_ms: Some(60_000),
            }),
            redirect: Some(RedirectPolicy::Error),
            max_redirects: Some(2),
            // Above the 10 MB hard ceiling: must clamp down, not raise.
            max_response_bytes: Some(u64::MAX),
            max_decompressed_bytes: Some(4096),
            auto_decompress: Some(false),
            https_only: Some(true),
            integrity: Some("sha256-abc".to_string()),
        };
        let r = ResolvedOptions::from_options(opts, &limits());
        assert_eq!(r.connect_timeout, Some(Duration::from_millis(1_000)));
        assert_eq!(r.first_byte_timeout, Some(Duration::from_millis(2_000)));
        assert_eq!(r.between_bytes_timeout, Some(Duration::from_millis(3_000)));
        assert_eq!(r.total_timeout, Some(Duration::from_millis(60_000)));
        assert!(matches!(r.redirect, RedirectPolicy::Error));
        assert_eq!(r.max_redirects, 2);
        assert_eq!(
            r.max_response_bytes,
            crate::engine::wasm::host::util::MAX_GUEST_PAYLOAD_LEN,
            "caller cannot raise the buffered cap above the host ceiling"
        );
        assert_eq!(r.max_decompressed_bytes, Some(4096));
        assert!(!r.auto_decompress);
        assert!(r.https_only);
        assert_eq!(r.integrity.as_deref(), Some("sha256-abc"));
        assert!(!r.total_was_default());
    }

    /// `https-only` rejects an http URL with `SchemeDenied` before connecting;
    /// any non-http(s) scheme is denied unconditionally.
    #[test]
    fn scheme_enforcement() {
        // https always allowed.
        assert!(check_scheme("https://api.example.com/x", true).is_ok());
        assert!(check_scheme("https://api.example.com/x", false).is_ok());
        // http allowed only when https-only is off.
        assert!(check_scheme("http://api.example.com/x", false).is_ok());
        assert!(matches!(
            check_scheme("http://api.example.com/x", true),
            Err(ErrorCode::SchemeDenied)
        ));
        // Non-http(s) schemes are always denied.
        for url in ["ftp://h/x", "file:///etc/passwd", "ws://h/x", "data:,hi"] {
            assert!(
                matches!(check_scheme(url, false), Err(ErrorCode::SchemeDenied)),
                "scheme must be denied: {url}"
            );
        }
        // Unparseable URL → InvalidRequest, not SchemeDenied.
        assert!(matches!(
            check_scheme("not a url", false),
            Err(ErrorCode::InvalidRequest)
        ));
    }

    /// Subresource-integrity: a correct digest passes; a wrong one is detected;
    /// a malformed SRI string is an invalid request.
    #[test]
    fn integrity_verification() {
        use base64::Engine as _;
        use sha2::{Digest, Sha256};

        let body = b"hello world";
        let digest = Sha256::digest(body);
        let b64 = base64::engine::general_purpose::STANDARD.encode(digest);
        let sri = format!("sha256-{b64}");

        // Correct digest → Ok.
        assert!(verify_integrity(&sri, body).is_ok());
        // Wrong body → IntegrityMismatch.
        assert!(matches!(
            verify_integrity(&sri, b"tampered"),
            Err(ErrorCode::IntegrityMismatch)
        ));
        // Unknown algorithm → InvalidRequest.
        assert!(matches!(
            verify_integrity(&format!("md5-{b64}"), body),
            Err(ErrorCode::InvalidRequest)
        ));
        // No dash separator → InvalidRequest.
        assert!(matches!(
            verify_integrity("sha256deadbeef", body),
            Err(ErrorCode::InvalidRequest)
        ));
        // Non-base64 payload → InvalidRequest.
        assert!(matches!(
            verify_integrity("sha256-!!!notb64!!!", body),
            Err(ErrorCode::InvalidRequest)
        ));
    }

    /// Cross-origin detection drives credential stripping on a redirect hop.
    #[test]
    fn same_origin_and_credential_stripping() {
        let a = reqwest::Url::parse("https://api.example.com/v1").unwrap();
        let same = reqwest::Url::parse("https://api.example.com/v2").unwrap();
        let other_host = reqwest::Url::parse("https://evil.example.com/").unwrap();
        let other_port = reqwest::Url::parse("https://api.example.com:8443/").unwrap();
        let other_scheme = reqwest::Url::parse("http://api.example.com/").unwrap();

        assert!(same_origin(&a, &same));
        assert!(!same_origin(&a, &other_host));
        assert!(!same_origin(&a, &other_port));
        assert!(!same_origin(&a, &other_scheme));

        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer secret"),
        );
        headers.insert(
            reqwest::header::COOKIE,
            HeaderValue::from_static("session=abc"),
        );
        headers.insert("x-keep", HeaderValue::from_static("yes"));
        strip_credentials(&mut headers);
        assert!(!headers.contains_key(reqwest::header::AUTHORIZATION));
        assert!(!headers.contains_key(reqwest::header::COOKIE));
        assert!(
            headers.contains_key("x-keep"),
            "non-credential headers must survive a cross-origin hop"
        );
    }

    /// A NON-default operator `default_total_timeout` actually changes the
    /// resolved default total timeout (proves the config knob threads through
    /// `v10_defaults`, not the old hardcoded 30s constant).
    #[test]
    fn config_default_timeout_changes_resolved_total() {
        let mut limits = HttpLimits::default();
        limits.default_total_timeout = Duration::from_secs(5);

        let resolved = ResolvedOptions::from_options(empty_options(), &limits);
        assert_eq!(
            resolved.total_timeout,
            Some(Duration::from_secs(5)),
            "the configured default total timeout must drive the resolved default"
        );
        assert!(
            resolved.total_was_default(),
            "an unset caller total still counts as the host default"
        );
    }

    /// A NON-default (lower) operator `max_redirects` ceiling clamps a caller
    /// who requests MORE — proving the clamp uses the configured ceiling, not
    /// the const. With ceiling 3, a caller asking for 9 resolves to 3.
    #[test]
    fn config_max_redirects_ceiling_clamps_caller() {
        let mut limits = HttpLimits::default();
        limits.max_redirects = 3;

        let opts = RequestOptions {
            max_redirects: Some(9),
            ..empty_options()
        };
        let resolved = ResolvedOptions::from_options(opts, &limits);
        assert_eq!(
            resolved.max_redirects, 3,
            "a caller cannot exceed the configured (lower) redirect ceiling"
        );

        // The default (unset) also takes the configured ceiling, not the const.
        let d = ResolvedOptions::from_options(empty_options(), &limits);
        assert_eq!(d.max_redirects, 3);
    }
}

/// The @1.1.0 → @1.0.0 error map: every @1.0.0 arm round-trips and the
/// @1.1.0-only arms fold to the nearest @1.0.0 arm. A blocked redirect hop
/// becomes `AirlockRejected` (the @1.0.0 way a redirect SSRF surfaced); a
/// too-long chain becomes a protocol error (no @1.0.0 arm exists).
#[test]
fn v11_error_maps_to_v10_arm_set() {
    use crate::engine::wasm::bindings::astrid::http1_0_0::host::ErrorCode as V10;

    use super::v11_error_to_v10;

    assert!(matches!(
        v11_error_to_v10(ErrorCode::AirlockRejected),
        V10::AirlockRejected
    ));
    assert!(matches!(
        v11_error_to_v10(ErrorCode::RedirectBlocked),
        V10::AirlockRejected
    ));
    assert!(matches!(
        v11_error_to_v10(ErrorCode::TooManyRedirects),
        V10::Protocol(_)
    ));
    assert!(matches!(
        v11_error_to_v10(ErrorCode::BodyTooLarge),
        V10::BodyTooLarge
    ));
    assert!(matches!(
        v11_error_to_v10(ErrorCode::DecompressionBomb),
        V10::BodyTooLarge
    ));
    assert!(matches!(
        v11_error_to_v10(ErrorCode::SchemeDenied),
        V10::InvalidRequest
    ));
    assert!(matches!(
        v11_error_to_v10(ErrorCode::Unknown("x".into())),
        V10::Unknown(_)
    ));
}
