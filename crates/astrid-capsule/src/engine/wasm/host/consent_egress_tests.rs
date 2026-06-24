//! Tests for runtime local-egress operator-consent (issue #1028).
//!
//! Coverage:
//! - origin gate: only `LocalSocket` may consent; `RemoteGateway` / `System` /
//!   unbound fail closed and NEVER elicit;
//! - existing-grant fast path short-circuits the prompt;
//! - approve / approve_session / approve_always caching;
//! - per-principal grant isolation;
//! - the consent-granted endpoint refuses redirects (exempt path).

use std::sync::Arc;
use std::time::Duration;

use astrid_approval::AllowanceStore;
use astrid_core::principal::PrincipalId;
use astrid_events::AstridEvent;
use astrid_events::ipc::{IpcMessage, IpcPayload, MessageOrigin};

use super::*;
use crate::engine::wasm::test_fixtures::minimal_host_state;

/// Stamp `state.caller_context` with a message carrying `origin` and
/// `principal`, so `effective_origin()` / `effective_principal()` reflect it —
/// exactly what the dispatcher does per invocation.
fn set_caller(state: &mut HostState, origin: MessageOrigin, principal: &str) {
    let msg = IpcMessage::new("t", IpcPayload::Connect, uuid::Uuid::nil())
        .with_principal(principal)
        .with_origin(origin);
    state.caller_context = Some(msg);
}

/// Spawn a one-shot responder: subscribe to `astrid.v1.approval`, wait for the
/// `ApprovalRequired`, then publish the given `decision` on the per-request
/// response topic. Mirrors what an uplink/broker does for the operator.
fn spawn_responder(bus: astrid_events::EventBus, decision: &'static str) {
    let mut req_rx = bus.subscribe_topic("astrid.v1.approval");
    tokio::spawn(async move {
        while let Some(event) = req_rx.recv().await {
            let AstridEvent::Ipc { message, .. } = &*event else {
                continue;
            };
            let IpcPayload::ApprovalRequired { request_id, .. } = &message.payload else {
                continue;
            };
            let response_topic = format!("astrid.v1.approval.response.{request_id}");
            let payload = IpcPayload::ApprovalResponse {
                request_id: request_id.clone(),
                decision: decision.to_string(),
                reason: None,
            };
            bus.publish(AstridEvent::Ipc {
                message: IpcMessage::new(response_topic, payload, uuid::Uuid::nil()),
                metadata: astrid_events::EventMetadata::default(),
            });
            return;
        }
    });
}

// ── Pure helper tests ────────────────────────────────────────────────────

#[test]
fn classify_decision_maps_approve_variants() {
    assert!(matches!(classify_decision("approve"), Decision::Once));
    assert!(matches!(
        classify_decision("approve_session"),
        Decision::Session
    ));
    assert!(matches!(
        classify_decision("approve_always"),
        Decision::Always
    ));
    // Everything else is a deny (fail-closed).
    assert!(matches!(classify_decision("deny"), Decision::Deny));
    assert!(matches!(classify_decision("garbage"), Decision::Deny));
    assert!(matches!(classify_decision(""), Decision::Deny));
}

#[test]
fn runtime_grant_is_per_principal() {
    // Spec (7): principal A's grant never exempts principal B.
    let store = AllowanceStore::new();
    let alice = PrincipalId::new("alice").unwrap();
    let bob = PrincipalId::new("bob").unwrap();

    add_runtime_grant(&store, &alice, "127.0.0.1", 1234, true);

    assert!(
        has_runtime_grant(&store, &alice, "127.0.0.1", 1234),
        "alice holds her own grant"
    );
    assert!(
        !has_runtime_grant(&store, &bob, "127.0.0.1", 1234),
        "bob must NOT inherit alice's grant"
    );
}

#[test]
fn runtime_grant_is_port_specific() {
    let store = AllowanceStore::new();
    let p = PrincipalId::new("alice").unwrap();
    add_runtime_grant(&store, &p, "127.0.0.1", 1234, true);

    assert!(has_runtime_grant(&store, &p, "127.0.0.1", 1234));
    // A different port on the same host is a different grant — not covered.
    assert!(!has_runtime_grant(&store, &p, "127.0.0.1", 5678));
}

// Spec (8) — a consent-granted endpoint refuses redirects identically to a
// pre-blessed one — is guarded structurally: `egress_decision_with_consent`
// returns the SAME `Ok(Some(host))` exempt value for a consent grant as
// `egress_decision` does for a pre-bless, and that value drives
// `build_redirect_policy(exempt = true)`. The behavioural live-server test
// `http_tests.rs::exempt_request_does_not_follow_redirects` exercises that
// exempt policy directly (it refuses a `302` to a different port), so it covers
// the consent path too. `http_tests.rs::consent_grant_yields_exempt_host` pins
// that a granted endpoint makes `egress_decision_with_consent` return the
// exempt host (`Ok(Some(host))`), not `None` — i.e. it re-enters the exempt
// path rather than the normal/airlocked one.

// ── Origin-gate tests (fail-closed, no elicitation) ──────────────────────

/// Run `consent_local_egress` under a given origin with a responder STANDING BY
/// that would approve if asked — then assert the decision and whether the
/// prompt was ever published. For the non-local origins the responder must
/// never fire, proving consent short-circuits before eliciting.
async fn consent_with_origin(origin: MessageOrigin) -> (bool, bool) {
    let rt = tokio::runtime::Handle::current();
    let mut state = minimal_host_state(rt);
    state.allowance_store = Some(Arc::new(AllowanceStore::new()));
    set_caller(&mut state, origin, "alice");

    // Watch the approval topic so we can prove (non-)elicitation.
    let mut watch_rx = state.event_bus.subscribe_topic("astrid.v1.approval");
    // A responder that WOULD approve — present for every case so a non-local
    // origin's silence is meaningful (it isn't that nobody would answer).
    spawn_responder(state.event_bus.clone(), "approve_session");

    let permitted = tokio::task::block_in_place(|| state.consent_local_egress("127.0.0.1", 1234));

    // Did an ApprovalRequired actually get published?
    let elicited = tokio::time::timeout(Duration::from_millis(50), watch_rx.recv())
        .await
        .ok()
        .flatten()
        .is_some();

    (permitted, elicited)
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_gateway_origin_never_elicits_and_fails_closed() {
    // Spec (6): a RemoteGateway request must never elicit and must fail closed.
    let (permitted, elicited) = consent_with_origin(MessageOrigin::RemoteGateway).await;
    assert!(!permitted, "remote gateway origin must be denied");
    assert!(!elicited, "remote gateway origin must NOT publish a prompt");
}

#[tokio::test(flavor = "multi_thread")]
async fn system_origin_never_elicits_and_fails_closed() {
    // Spec (6): a System-origin request (also the unbound-socket / no-caller
    // floor) must never elicit and must fail closed.
    let (permitted, elicited) = consent_with_origin(MessageOrigin::System).await;
    assert!(!permitted, "system origin must be denied");
    assert!(!elicited, "system origin must NOT publish a prompt");
}

#[tokio::test(flavor = "multi_thread")]
async fn absent_caller_context_is_system_and_fails_closed() {
    // No caller context at all → effective_origin() == System → fail closed,
    // no prompt. (An unbound socket forward and a load-time call both land
    // here.)
    let rt = tokio::runtime::Handle::current();
    let mut state = minimal_host_state(rt);
    state.allowance_store = Some(Arc::new(AllowanceStore::new()));
    // caller_context stays None.
    let mut watch_rx = state.event_bus.subscribe_topic("astrid.v1.approval");
    spawn_responder(state.event_bus.clone(), "approve");

    let permitted = tokio::task::block_in_place(|| state.consent_local_egress("127.0.0.1", 1234));
    let elicited = tokio::time::timeout(Duration::from_millis(50), watch_rx.recv())
        .await
        .ok()
        .flatten()
        .is_some();

    assert!(!permitted, "absent caller (System) must be denied");
    assert!(!elicited, "absent caller must NOT publish a prompt");
}

// ── LocalSocket elicitation tests ────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn local_socket_approve_session_permits_and_caches_grant() {
    // Spec (5): LocalSocket + not-allowlisted → elicits; on approve the in-flight
    // request proceeds AND a per-principal session grant is cached.
    let rt = tokio::runtime::Handle::current();
    let mut state = minimal_host_state(rt);
    let store = Arc::new(AllowanceStore::new());
    state.allowance_store = Some(store.clone());
    set_caller(&mut state, MessageOrigin::LocalSocket, "alice");
    spawn_responder(state.event_bus.clone(), "approve_session");

    let permitted = tokio::task::block_in_place(|| state.consent_local_egress("127.0.0.1", 1234));
    assert!(
        permitted,
        "approve_session must permit the in-flight request"
    );

    let alice = PrincipalId::new("alice").unwrap();
    assert!(
        has_runtime_grant(&store, &alice, "127.0.0.1", 1234),
        "approve_session must cache a per-principal grant"
    );
    // And a SECOND request to the same endpoint is now silent — no responder
    // present this time, so if it tried to elicit it would time out (deny).
    let again = tokio::task::block_in_place(|| state.consent_local_egress("127.0.0.1", 1234));
    assert!(again, "a cached grant short-circuits the prompt on repeat");
}

#[tokio::test(flavor = "multi_thread")]
async fn local_socket_approve_once_permits_without_caching() {
    // approve (once) lets the request through but caches nothing.
    let rt = tokio::runtime::Handle::current();
    let mut state = minimal_host_state(rt);
    let store = Arc::new(AllowanceStore::new());
    state.allowance_store = Some(store.clone());
    set_caller(&mut state, MessageOrigin::LocalSocket, "alice");
    spawn_responder(state.event_bus.clone(), "approve");

    let permitted = tokio::task::block_in_place(|| state.consent_local_egress("127.0.0.1", 1234));
    assert!(
        permitted,
        "approve (once) must permit the in-flight request"
    );

    let alice = PrincipalId::new("alice").unwrap();
    assert!(
        !has_runtime_grant(&store, &alice, "127.0.0.1", 1234),
        "approve (once) must NOT cache a grant"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn local_socket_deny_fails_closed() {
    let rt = tokio::runtime::Handle::current();
    let mut state = minimal_host_state(rt);
    let store = Arc::new(AllowanceStore::new());
    state.allowance_store = Some(store.clone());
    set_caller(&mut state, MessageOrigin::LocalSocket, "alice");
    spawn_responder(state.event_bus.clone(), "deny");

    let permitted = tokio::task::block_in_place(|| state.consent_local_egress("127.0.0.1", 1234));
    assert!(!permitted, "an explicit deny must keep the request blocked");

    let alice = PrincipalId::new("alice").unwrap();
    assert!(
        !has_runtime_grant(&store, &alice, "127.0.0.1", 1234),
        "a deny must cache nothing"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn local_socket_approve_always_persists_to_profile_egress() {
    // Spec (5) tail: approve_always caches a (non-session) grant AND persists
    // the endpoint to the principal's `profile.network.egress` on disk.
    use astrid_core::dirs::AstridHome;
    use astrid_core::principal::PrincipalId;
    use astrid_core::profile::PrincipalProfile;

    use crate::profile_cache::PrincipalProfileCache;

    let dir = tempfile::tempdir().expect("tempdir");
    let home = AstridHome::from_path(dir.path());
    let cache = Arc::new(PrincipalProfileCache::with_home(home.clone()));

    let rt = tokio::runtime::Handle::current();
    let mut state = minimal_host_state(rt);
    state.allowance_store = Some(Arc::new(AllowanceStore::new()));
    state.profile_cache = Some(cache);
    set_caller(&mut state, MessageOrigin::LocalSocket, "alice");
    spawn_responder(state.event_bus.clone(), "approve_always");

    let permitted = tokio::task::block_in_place(|| state.consent_local_egress("127.0.0.1", 1234));
    assert!(
        permitted,
        "approve_always must permit the in-flight request"
    );

    // The endpoint is now on disk in alice's profile egress allowlist.
    let alice = PrincipalId::new("alice").unwrap();
    let profile = PrincipalProfile::load(&home, &alice).expect("load profile");
    assert!(
        profile.network.egress.iter().any(|e| e == "127.0.0.1:1234"),
        "approve_always must persist the endpoint to profile.network.egress, got {:?}",
        profile.network.egress
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn local_socket_existing_grant_short_circuits_without_eliciting() {
    // A pre-existing grant means consent returns true with NO prompt published
    // — even with no responder present.
    let rt = tokio::runtime::Handle::current();
    let mut state = minimal_host_state(rt);
    let store = Arc::new(AllowanceStore::new());
    let alice = PrincipalId::new("alice").unwrap();
    add_runtime_grant(&store, &alice, "127.0.0.1", 1234, true);
    state.allowance_store = Some(store.clone());
    set_caller(&mut state, MessageOrigin::LocalSocket, "alice");

    let mut watch_rx = state.event_bus.subscribe_topic("astrid.v1.approval");
    let permitted = tokio::task::block_in_place(|| state.consent_local_egress("127.0.0.1", 1234));
    assert!(permitted, "an existing grant permits immediately");

    let elicited = tokio::time::timeout(Duration::from_millis(50), watch_rx.recv())
        .await
        .ok()
        .flatten()
        .is_some();
    assert!(!elicited, "an existing grant must NOT publish a prompt");
}
