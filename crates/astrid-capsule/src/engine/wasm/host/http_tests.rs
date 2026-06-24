//! Unit tests for the `astrid:http` host implementation (SSRF airlock,
//! local-egress allowlist, redirect policy). Split out via `#[path]` to keep
//! `http.rs` under the file-size cap.

use super::*;

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
        classify_redirect(Some("127.0.0.1"), 0),
        RedirectAction::Block
    );
    assert_eq!(classify_redirect(Some("[::1]"), 0), RedirectAction::Block);
    assert_eq!(
        classify_redirect(Some("169.254.169.254"), 0),
        RedirectAction::Block
    );
    assert_eq!(
        classify_redirect(Some("10.0.0.5"), 2),
        RedirectAction::Block
    );
}

#[test]
fn redirect_follows_safe_targets_within_cap() {
    // Hostnames are airlocked by the resolver, public literals are
    // safe; both follow until the hop cap.
    assert_eq!(
        classify_redirect(Some("example.com"), 0),
        RedirectAction::Follow
    );
    assert_eq!(
        classify_redirect(Some("8.8.8.8"), 0),
        RedirectAction::Follow
    );
    assert_eq!(classify_redirect(None, 0), RedirectAction::Follow);
    assert_eq!(
        classify_redirect(Some("example.com"), MAX_HTTP_REDIRECTS),
        RedirectAction::Stop
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

/// An operator-allowlisted (exempt) request must NOT follow redirects:
/// `build_redirect_policy(true, …)` yields `Policy::none()`, so a `30x` from
/// an allowlisted endpoint can't escape the port-scoped exemption onto a
/// different port/host. `reqwest::redirect::Policy` is opaque, so this is a
/// behavioural test against a loopback server that returns a redirect.
///
/// Binding a loopback listener is blocked in some sandboxes — skip gracefully
/// there (mirrors the gateway e2e tests); it runs in CI where loopback binds.
#[tokio::test]
async fn exempt_request_does_not_follow_redirects() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping: sandbox blocks loopback bind: {e}");
            return;
        },
        Err(e) => panic!("loopback bind failed: {e}"),
    };
    let addr = listener.local_addr().unwrap();

    // One-shot server: reply 302 redirecting to a *different* port. A client
    // that follows would try 127.0.0.1:1 (nothing there); one that does not
    // returns this 302 verbatim.
    let server = tokio::spawn(async move {
        if let Ok((mut sock, _)) = listener.accept().await {
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await;
            let resp =
                b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/\r\nContent-Length: 0\r\n\r\n";
            let _ = sock.write_all(resp).await;
            let _ = sock.flush().await;
        }
    });

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .redirect(build_redirect_policy(
            true,
            Arc::new(AtomicBool::new(false)),
        ))
        .build()
        .unwrap();

    let resp = client
        .get(format!("http://{addr}/"))
        .send()
        .await
        .expect("exempt request should return the 302 itself, not follow it");

    assert_eq!(
        resp.status().as_u16(),
        302,
        "exempt request must not follow redirects (would widen the port-scoped allowlist)"
    );

    let _ = server.await;
}
