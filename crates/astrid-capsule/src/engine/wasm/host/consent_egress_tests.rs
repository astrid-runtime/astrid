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

    add_runtime_grant(&store, &alice, "react", "127.0.0.1", 1234, true);

    assert!(
        has_runtime_grant(&store, &alice, "react", "127.0.0.1", 1234),
        "alice holds her own grant"
    );
    assert!(
        !has_runtime_grant(&store, &bob, "react", "127.0.0.1", 1234),
        "bob must NOT inherit alice's grant"
    );
}

#[test]
fn runtime_grant_is_per_capsule() {
    // Spec (FIX 1a): a grant for capsule "react" must NOT exempt capsule
    // "openai-compat" reaching the same host:port for the same principal.
    let store = AllowanceStore::new();
    let alice = PrincipalId::new("alice").unwrap();

    add_runtime_grant(&store, &alice, "react", "127.0.0.1", 1234, true);

    assert!(
        has_runtime_grant(&store, &alice, "react", "127.0.0.1", 1234),
        "react holds its own grant"
    );
    assert!(
        !has_runtime_grant(&store, &alice, "openai-compat", "127.0.0.1", 1234),
        "openai-compat must NOT inherit react's grant for the same endpoint"
    );
}

#[test]
fn runtime_grant_is_port_specific() {
    let store = AllowanceStore::new();
    let p = PrincipalId::new("alice").unwrap();
    add_runtime_grant(&store, &p, "react", "127.0.0.1", 1234, true);

    assert!(has_runtime_grant(&store, &p, "react", "127.0.0.1", 1234));
    // A different port on the same host is a different grant — not covered.
    assert!(!has_runtime_grant(&store, &p, "react", "127.0.0.1", 5678));
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
        has_runtime_grant(&store, &alice, "test", "127.0.0.1", 1234),
        "approve_session must cache a per-principal, per-capsule grant"
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
        !has_runtime_grant(&store, &alice, "test", "127.0.0.1", 1234),
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
        !has_runtime_grant(&store, &alice, "test", "127.0.0.1", 1234),
        "a deny must cache nothing"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn local_socket_approve_always_persists_under_capsule_key() {
    // Spec (5) tail + FIX 1b: approve_always caches a (non-session) grant AND
    // persists the endpoint to the principal's profile on disk, keyed by the
    // requesting capsule id (`network.capsule_egress[<capsule>]`), NOT the flat
    // general `egress` allowlist — so the persisted grant cannot widen across
    // capsules.
    use astrid_core::dirs::AstridHome;
    use astrid_core::principal::PrincipalId;
    use astrid_core::profile::PrincipalProfile;

    use crate::profile_cache::PrincipalProfileCache;

    let dir = tempfile::tempdir().expect("tempdir");
    let home = AstridHome::from_path(dir.path());
    let cache = Arc::new(PrincipalProfileCache::with_home(home.clone()));

    let rt = tokio::runtime::Handle::current();
    let mut state = minimal_host_state(rt);
    // The fixture's capsule id is "test"; the persisted grant lands under it.
    state.allowance_store = Some(Arc::new(AllowanceStore::new()));
    state.profile_cache = Some(cache);
    set_caller(&mut state, MessageOrigin::LocalSocket, "alice");
    spawn_responder(state.event_bus.clone(), "approve_always");

    let permitted = tokio::task::block_in_place(|| state.consent_local_egress("127.0.0.1", 1234));
    assert!(
        permitted,
        "approve_always must permit the in-flight request"
    );

    // The endpoint is now on disk under the "test" capsule key — and NOT in the
    // flat general egress allowlist.
    let alice = PrincipalId::new("alice").unwrap();
    let profile = PrincipalProfile::load(&home, &alice).expect("load profile");
    assert_eq!(
        profile.network.capsule_egress.get("test"),
        Some(&vec!["127.0.0.1:1234".to_string()]),
        "approve_always must persist under network.capsule_egress[<capsule>], got {:?}",
        profile.network.capsule_egress
    );
    assert!(
        profile.network.egress.is_empty(),
        "approve_always must NOT touch the flat general egress allowlist, got {:?}",
        profile.network.egress
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn approve_always_for_one_capsule_does_not_exempt_another_capsule() {
    // Spec (FIX 1b end-to-end): a session AND persisted approve_always grant
    // for capsule "react" reaching 127.0.0.1:1234 must NOT permit capsule
    // "openai-compat" reaching the same endpoint for the same principal — it
    // still elicits (and here, with no responder, fails closed).
    use astrid_core::dirs::AstridHome;
    use astrid_core::principal::PrincipalId;
    use astrid_core::profile::PrincipalProfile;

    use crate::capsule::CapsuleId;
    use crate::profile_cache::PrincipalProfileCache;

    let dir = tempfile::tempdir().expect("tempdir");
    let home = AstridHome::from_path(dir.path());
    let cache = Arc::new(PrincipalProfileCache::with_home(home.clone()));
    let store = Arc::new(AllowanceStore::new());

    let rt = tokio::runtime::Handle::current();
    let mut state = minimal_host_state(rt);
    state.allowance_store = Some(store.clone());
    state.profile_cache = Some(cache);
    set_caller(&mut state, MessageOrigin::LocalSocket, "alice");

    // 1. Capsule "react" gets approve_always for 127.0.0.1:1234 (session grant
    //    cached + persisted to disk under "react").
    state.capsule_id = CapsuleId::from_static("react");
    spawn_responder(state.event_bus.clone(), "approve_always");
    let react_permitted =
        tokio::task::block_in_place(|| state.consent_local_egress("127.0.0.1", 1234));
    assert!(react_permitted, "react's approve_always must permit");

    let alice = PrincipalId::new("alice").unwrap();
    // The session grant is cached for react and NOT for openai-compat.
    assert!(
        has_runtime_grant(&store, &alice, "react", "127.0.0.1", 1234),
        "react holds the session grant"
    );
    assert!(
        !has_runtime_grant(&store, &alice, "openai-compat", "127.0.0.1", 1234),
        "openai-compat must NOT inherit react's session grant"
    );
    // The persisted grant landed under "react" only.
    let profile = PrincipalProfile::load(&home, &alice).expect("load profile");
    assert_eq!(
        profile.network.capsule_egress.get("react"),
        Some(&vec!["127.0.0.1:1234".to_string()])
    );
    assert!(
        profile
            .network
            .capsule_egress
            .get("openai-compat")
            .is_none(),
        "openai-compat must NOT inherit react's persisted grant"
    );

    // 2. Now capsule "openai-compat" tries the SAME endpoint. It must NOT
    //    short-circuit on react's grant — it must elicit its OWN consent. We
    //    stand up a responder that DENIES, so a correct gate elicits and is
    //    denied (returns false); a buggy gate that reused react's grant would
    //    return true WITHOUT eliciting. (Using a deny responder rather than
    //    relying on the 60s timeout keeps the test fast.)
    state.capsule_id = CapsuleId::from_static("openai-compat");
    let mut watch_rx = state.event_bus.subscribe_topic("astrid.v1.approval");
    spawn_responder(state.event_bus.clone(), "deny");
    let openai_permitted =
        tokio::task::block_in_place(|| state.consent_local_egress("127.0.0.1", 1234));
    assert!(
        !openai_permitted,
        "openai-compat must NOT be exempted by react's grant; it elicits and is denied"
    );
    // It DID elicit (proving it did not silently short-circuit on react's grant).
    let elicited = tokio::time::timeout(Duration::from_millis(50), watch_rx.recv())
        .await
        .ok()
        .flatten()
        .is_some();
    assert!(
        elicited,
        "openai-compat must elicit its own consent rather than reuse react's grant"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn persisted_approve_always_grant_survives_empty_store_and_is_isolated() {
    // GAP FIX (PR #1029): an `approve_always` grant persists to
    // `profile.network.capsule_egress[<capsule>]`, but the in-memory
    // AllowanceStore starts EMPTY after a daemon restart. The egress gate must
    // therefore ALSO consult the persisted profile, or the "remember across
    // restarts" contract is silently broken and the operator is re-prompted.
    //
    // Simulate a fresh daemon: EMPTY AllowanceStore, but a profile on disk that
    // already remembers react -> 127.0.0.1:1234 for principal "alice". The gate
    // must PERMIT (alice, react, 127.0.0.1:1234) WITHOUT eliciting, while
    // isolation holds across the persisted path too:
    //   - (alice, openai-compat, 127.0.0.1:1234) still elicits (wrong capsule);
    //   - (bob,   react,         127.0.0.1:1234) still elicits (wrong principal).
    use astrid_core::dirs::AstridHome;
    use astrid_core::principal::PrincipalId;
    use astrid_core::profile::PrincipalProfile;

    use crate::capsule::CapsuleId;
    use crate::profile_cache::PrincipalProfileCache;

    let dir = tempfile::tempdir().expect("tempdir");
    let home = AstridHome::from_path(dir.path());

    // Seed alice's profile on disk with a remembered react grant — exactly the
    // shape `persist_egress` writes — WITHOUT ever touching the in-memory store.
    let alice = PrincipalId::new("alice").unwrap();
    let mut alice_profile = PrincipalProfile::default();
    alice_profile
        .network
        .capsule_egress
        .insert("react".to_string(), vec!["127.0.0.1:1234".to_string()]);
    alice_profile
        .save_to_path(&home.profile_path(&alice))
        .expect("seed alice profile");

    let cache = Arc::new(PrincipalProfileCache::with_home(home.clone()));

    // 1. (alice, react, 127.0.0.1:1234) — EMPTY store, but persisted grant
    //    present. Must PERMIT with NO prompt. A responder that WOULD deny is
    //    standing by; if the gate wrongly elicited, it would be denied (false).
    let rt = tokio::runtime::Handle::current();
    let mut state = minimal_host_state(rt.clone());
    state.allowance_store = Some(Arc::new(AllowanceStore::new())); // fresh, EMPTY
    state.profile_cache = Some(cache.clone());
    state.capsule_id = CapsuleId::from_static("react");
    set_caller(&mut state, MessageOrigin::LocalSocket, "alice");

    let mut watch_rx = state.event_bus.subscribe_topic("astrid.v1.approval");
    spawn_responder(state.event_bus.clone(), "deny");
    let permitted = tokio::task::block_in_place(|| state.consent_local_egress("127.0.0.1", 1234));
    assert!(
        permitted,
        "a persisted approve_always grant must permit on a fresh (empty) store"
    );
    let elicited = tokio::time::timeout(Duration::from_millis(50), watch_rx.recv())
        .await
        .ok()
        .flatten()
        .is_some();
    assert!(
        !elicited,
        "a persisted grant must short-circuit WITHOUT eliciting a prompt"
    );

    // 2. ISOLATION — wrong capsule. (alice, openai-compat, 127.0.0.1:1234) must
    //    NOT match react's persisted bucket; it must elicit its OWN consent
    //    (and, with a deny responder, be denied).
    state.capsule_id = CapsuleId::from_static("openai-compat");
    let mut watch_rx = state.event_bus.subscribe_topic("astrid.v1.approval");
    spawn_responder(state.event_bus.clone(), "deny");
    let openai_permitted =
        tokio::task::block_in_place(|| state.consent_local_egress("127.0.0.1", 1234));
    assert!(
        !openai_permitted,
        "openai-compat must NOT inherit react's persisted grant; it elicits and is denied"
    );
    let openai_elicited = tokio::time::timeout(Duration::from_millis(50), watch_rx.recv())
        .await
        .ok()
        .flatten()
        .is_some();
    assert!(
        openai_elicited,
        "wrong-capsule request must elicit its own consent, not reuse react's persisted grant"
    );

    // 3. ISOLATION — wrong principal. (bob, react, 127.0.0.1:1234) must NOT
    //    match alice's persisted profile; it must elicit (and be denied).
    state.capsule_id = CapsuleId::from_static("react");
    set_caller(&mut state, MessageOrigin::LocalSocket, "bob");
    let mut watch_rx = state.event_bus.subscribe_topic("astrid.v1.approval");
    spawn_responder(state.event_bus.clone(), "deny");
    let bob_permitted =
        tokio::task::block_in_place(|| state.consent_local_egress("127.0.0.1", 1234));
    assert!(
        !bob_permitted,
        "bob must NOT inherit alice's persisted grant; it elicits and is denied"
    );
    let bob_elicited = tokio::time::timeout(Duration::from_millis(50), watch_rx.recv())
        .await
        .ok()
        .flatten()
        .is_some();
    assert!(
        bob_elicited,
        "wrong-principal request must elicit its own consent, not reuse alice's persisted grant"
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
    add_runtime_grant(&store, &alice, "test", "127.0.0.1", 1234, true);
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
