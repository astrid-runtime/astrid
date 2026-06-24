//! Tests for the `astrid:ipc` host implementation: audit-scope self-scoping,
//! `publish-as` host-derived principal enforcement (issue #45/#852), and
//! per-device `device_key_id` stamping for cap-gate scope attenuation.
//!
//! Split out of `ipc.rs` to stay under the 1000-line CI cap; included via
//! `#[path]` so `super::*` resolves to the parent `ipc` module and reaches its
//! private items (`AUDIT_TOPIC`, `pattern_covers_audit`, `publish_inner`).

use super::*;
use crate::engine::wasm::bindings::astrid::ipc::host::Host as IpcHost;
use crate::engine::wasm::test_fixtures::minimal_host_state;

#[test]
fn audit_topic_literal_pinned() {
    // The capsule-local `AUDIT_TOPIC` must stay byte-equal to the
    // kernel's sole publisher (`astrid_kernel::kernel_router::AUDIT_TOPIC`)
    // and the gateway SSE consumer (`astrid-gateway`'s
    // `events::AUDIT_TOPIC`). The capsule cannot import the kernel
    // constant without a dependency cycle, so this pins the literal the
    // capsule routes against. If the kernel ever renames the topic,
    // `pattern_covers_audit` would otherwise silently stop recognising
    // audit subscriptions and leave them on the unscoped firehose default
    // for the renamed topic — exactly the drift the doc comment promises
    // is guarded. Mirrors `tests::audit_firehose_cap_literal_pinned`.
    assert_eq!(AUDIT_TOPIC, "astrid.v1.audit.entry");
}

// ── pattern_covers_audit (route-layer matcher, NOT topic_matches) ──

#[test]
fn pattern_covers_audit_via_route_matcher() {
    // Exact + audit-subtree wildcard + broad superset all COVER the
    // audit topic via the route matcher's trailing-suffix branch.
    assert!(pattern_covers_audit("astrid.v1.audit.entry"));
    assert!(pattern_covers_audit("astrid.v1.audit.*"));
    // The wildcard-superset bypass the route matcher closes: the
    // capsule's own topic_matches CANNOT see this coverage, but the
    // route matcher (what the bus routes with) DOES.
    assert!(pattern_covers_audit("astrid.v1.*"));
    assert!(pattern_covers_audit("astrid.*"));

    // Non-audit patterns are NOT covered → never scoped.
    assert!(!pattern_covers_audit("astrid.v1.request.*"));
    assert!(!pattern_covers_audit("astrid.v1.session.*"));
    assert!(!pattern_covers_audit("astrid.v1.audit"));
    assert!(!pattern_covers_audit("user.prompt"));
}

/// Build a routed publish on `bus` for an audit entry attributed to
/// `principal` (mirrors the kernel's `record_admin_audit` shape: topic
/// `astrid.v1.audit.entry`, `with_principal`).
fn publish_audit(bus: &astrid_events::EventBus, principal: &str) {
    let msg = InternalIpcMessage::new(
        AUDIT_TOPIC,
        IpcPayload::RawJson(serde_json::json!({ "principal": principal })),
        uuid::Uuid::nil(),
    )
    .with_principal(principal.to_string());
    bus.publish(AstridEvent::Ipc {
        metadata: EventMetadata::new("test_kernel"),
        message: msg,
    });
}

/// Drain the subscription's delivered messages and collect the
/// `Verified` principal strings.
fn drained_principals(state: &mut HostState, sub: &Resource<Subscription>) -> Vec<String> {
    let envelope = HostSubscription::poll(state, Resource::new_borrow(sub.rep()))
        .expect("poll should succeed");
    envelope
        .messages
        .iter()
        .map(|m| match &m.principal {
            PrincipalAttribution::Verified(p) | PrincipalAttribution::Claimed(p) => p.clone(),
            PrincipalAttribution::System => "<system>".to_string(),
        })
        .collect()
}

fn host_state_for(
    rt: tokio::runtime::Handle,
    owner: &str,
    firehose: bool,
    subscribe_acl: &[&str],
) -> HostState {
    let mut state = minimal_host_state(rt);
    state.principal = astrid_core::PrincipalId::new(owner).expect("valid principal");
    state.audit_firehose = firehose;
    state.ipc_subscribe_patterns = subscribe_acl.iter().map(|s| (*s).to_string()).collect();
    state
}

#[tokio::test]
async fn subscribe_audit_default_is_scoped_regression() {
    // THE bug regression. A capsule with audit_firehose=false and the
    // audit topic in its ACL, owner=alice, must receive ONLY alice's
    // entries — bob's leak on today's unconditional firehose default.
    let rt = tokio::runtime::Handle::current();
    let mut state = host_state_for(rt, "alice", false, &["astrid.v1.audit.entry"]);
    let bus = state.event_bus.clone();

    let sub = IpcHost::subscribe(&mut state, AUDIT_TOPIC.to_string())
        .expect("subscribe should be allowed by the ACL");

    for _ in 0..5 {
        publish_audit(&bus, "alice");
    }
    for _ in 0..5 {
        publish_audit(&bus, "bob");
    }

    let got = drained_principals(&mut state, &sub);
    assert_eq!(got.len(), 5, "only alice's five entries are delivered");
    assert!(
        got.iter().all(|p| p == "alice"),
        "no foreign-principal audit entry may leak, got: {got:?}"
    );
}

#[tokio::test]
async fn subscribe_wildcard_superset_is_scoped() {
    // A broad `astrid.v1.*` subscription (covers audit) by a
    // non-firehose capsule is still scoped — closes the wildcard bypass.
    let rt = tokio::runtime::Handle::current();
    let mut state = host_state_for(rt, "alice", false, &["astrid.v1.*"]);
    let bus = state.event_bus.clone();

    let sub = IpcHost::subscribe(&mut state, "astrid.v1.*".to_string())
        .expect("subscribe should be allowed by the ACL");

    publish_audit(&bus, "alice");
    publish_audit(&bus, "bob");

    let got = drained_principals(&mut state, &sub);
    assert!(
        got.iter().all(|p| p == "alice"),
        "wildcard superset must not leak bob's audit entry, got: {got:?}"
    );
    assert_eq!(got.len(), 1);
}

#[tokio::test]
async fn subscribe_firehose_holder_unscoped() {
    // audit_firehose=true ⇒ unscoped: both alice and bob delivered.
    let rt = tokio::runtime::Handle::current();
    let mut state = host_state_for(rt, "alice", true, &["astrid.v1.audit.entry"]);
    let bus = state.event_bus.clone();

    let sub = IpcHost::subscribe(&mut state, AUDIT_TOPIC.to_string())
        .expect("subscribe should be allowed by the ACL");

    publish_audit(&bus, "alice");
    publish_audit(&bus, "bob");

    let got = drained_principals(&mut state, &sub);
    assert_eq!(got.len(), 2, "firehose holder receives both principals");
    assert!(got.iter().any(|p| p == "alice"));
    assert!(got.iter().any(|p| p == "bob"));
}

#[tokio::test]
async fn subscribe_non_audit_topic_unaffected() {
    // A non-audit subscription (pattern_covers_audit=false) stays
    // unscoped even for a non-firehose capsule: cross-principal fan-in
    // is untouched by the audit flip.
    let rt = tokio::runtime::Handle::current();
    let mut state = host_state_for(rt, "alice", false, &["astrid.v1.session.*"]);
    let bus = state.event_bus.clone();

    let sub = IpcHost::subscribe(&mut state, "astrid.v1.session.*".to_string())
        .expect("subscribe should be allowed by the ACL");

    // Publish session events from two principals.
    for who in ["alice", "bob"] {
        let msg = InternalIpcMessage::new(
            "astrid.v1.session.update",
            IpcPayload::RawJson(serde_json::json!({})),
            uuid::Uuid::nil(),
        )
        .with_principal(who.to_string());
        bus.publish(AstridEvent::Ipc {
            metadata: EventMetadata::new("test"),
            message: msg,
        });
    }

    let got = drained_principals(&mut state, &sub);
    assert_eq!(got.len(), 2, "non-audit fan-in delivers all principals");
    assert!(got.iter().any(|p| p == "alice"));
    assert!(got.iter().any(|p| p == "bob"));
}

#[tokio::test]
async fn subscribe_rejects_non_terminal_wildcard() {
    // Regression guard for the daemon-down crash (capsule-cli #25). The cli
    // run loop tried to runtime-subscribe to a multi-wildcard pattern; the
    // syntactic gate returned InvalidInput, run() returned Err before
    // signal_ready, and the whole daemon went unreachable (the cli owns the
    // socket). The patterns are even DECLARED in the subscribe ACL here — the
    // gate rejects them regardless, so a manifest can declare a [subscribe]
    // pattern a runtime subscribe can never use. Pin it: a `*` that is not the
    // final segment is rejected; the single trailing `*` the fix kept works.
    let rt = tokio::runtime::Handle::current();
    let acl = &[
        "astrid.v1.admin.response.*",
        "astrid.v1.admin.response.*.*",
        "astrid.v1.admin.response.*.*.*",
    ];
    let mut state = host_state_for(rt, "default", false, acl);

    assert!(
        matches!(
            IpcHost::subscribe(&mut state, "astrid.v1.admin.response.*.*".to_string()),
            Err(ErrorCode::InvalidInput)
        ),
        "a non-terminal wildcard must be rejected even when declared in the ACL",
    );
    assert!(
        matches!(
            IpcHost::subscribe(&mut state, "astrid.v1.admin.response.*.*.*".to_string()),
            Err(ErrorCode::InvalidInput)
        ),
        "a deeper multi-wildcard must be rejected too",
    );
    assert!(
        IpcHost::subscribe(&mut state, "astrid.v1.admin.response.*".to_string()).is_ok(),
        "the single trailing wildcard the fix kept must be subscribable",
    );
}

// ── publish-as principal enforcement (issue #45/#852) ──

/// The self-stamp fix: when the source connection carries a kernel-verified
/// principal (recorded by the framed read that pulled the frame), `publish-as`
/// stamps THAT principal and ignores the capsule-supplied name. A socket
/// client that authenticated as `claude` but names `default` (admin) on the
/// wire cannot escalate — the kernel-bound identity wins.
#[tokio::test]
async fn publish_as_verified_principal_overrides_claimed_name() {
    let rt = tokio::runtime::Handle::current();
    let mut state = minimal_host_state(rt);
    state.has_uplink_capability = true;
    state.ipc_publish_patterns = vec!["client.v1.*".to_string()];
    state.ipc_subscribe_patterns = vec!["client.v1.*".to_string()];
    // The framed read recorded the connection's verified principal.
    state.ingress_principal = Some(astrid_core::PrincipalId::new("claude").unwrap());

    let sub = IpcHost::subscribe(&mut state, "client.v1.connect".to_string())
        .expect("subscribe allowed by ACL");

    // The client lies on the wire: it names `default`.
    IpcHost::publish_as(
        &mut state,
        "client.v1.connect".to_string(),
        "{}".to_string(),
        "default".to_string(),
    )
    .expect("publish_as should succeed");

    assert_eq!(
        drained_principals(&mut state, &sub),
        vec!["claude".to_string()],
        "the verified principal must override the claimed name (no escalation)"
    );
}

/// An UNAUTHENTICATED (unbound) connection is stamped with the reserved
/// no-capability `anonymous` identity, NOT the principal it claimed — an
/// unproven claim earns no privilege (issue #45/#852). This is the residual
/// self-stamp #932 left for unbound connections, now closed: a client that
/// did not authenticate cannot act as `default` (or any named principal).
#[tokio::test]
async fn publish_as_unbound_connection_is_stamped_anonymous() {
    let rt = tokio::runtime::Handle::current();
    let mut state = minimal_host_state(rt);
    state.has_uplink_capability = true;
    state.ipc_publish_patterns = vec!["client.v1.*".to_string()];
    state.ipc_subscribe_patterns = vec!["client.v1.*".to_string()];
    // No in-flight verified principal (an unbound connection).
    assert_eq!(state.ingress_principal, None);

    let sub = IpcHost::subscribe(&mut state, "client.v1.connect".to_string())
        .expect("subscribe allowed by ACL");

    // The client claims `default` (admin) without having authenticated.
    IpcHost::publish_as(
        &mut state,
        "client.v1.connect".to_string(),
        "{}".to_string(),
        "default".to_string(),
    )
    .expect("publish_as should succeed");

    assert_eq!(
        drained_principals(&mut state, &sub),
        vec![astrid_core::principal::PrincipalId::anonymous().to_string()],
        "an unauthenticated connection's claim earns no privilege — stamped anonymous"
    );
}

// ── publish-as device-scope stamping (per-device cap attenuation) ──

/// Drain ONE internal message off a raw bus subscription and return its
/// host-derived `device_key_id`. The guest WIT translation (`to_wit_message`)
/// drops `device_key_id`, so the stamping must be observed on the internal
/// `IpcMessage` the kernel cap-gate actually reads — subscribe straight on
/// the bus, not through `IpcHost::subscribe`.
fn first_device_key_id(
    receiver: &mut astrid_events::EventReceiver,
) -> (Option<String>, Option<String>) {
    let event = receiver.try_recv().expect("one published message");
    match &*event {
        AstridEvent::Ipc { message, .. } => {
            (message.principal.clone(), message.device_key_id.clone())
        },
        _ => panic!("expected an Ipc event"),
    }
}

/// `publish_as` stamps the host-derived `ingress_device_key_id` onto the
/// outbound message alongside the verified principal, so the kernel cap-gate
/// can resolve the device's scope. The key_id is host-derived (from the
/// in-flight connection), never the capsule-supplied name.
#[tokio::test]
async fn publish_as_stamps_host_derived_device_key_id() {
    let rt = tokio::runtime::Handle::current();
    let mut state = minimal_host_state(rt);
    state.has_uplink_capability = true;
    state.ipc_publish_patterns = vec!["client.v1.*".to_string()];
    // The framed read recorded the connection's verified principal AND the
    // device key_id that authenticated it.
    state.ingress_principal = Some(astrid_core::PrincipalId::new("claude").unwrap());
    state.ingress_device_key_id = Some("dev-abc123".to_string());

    let mut receiver = state.event_bus.subscribe_topic("client.v1.connect");

    IpcHost::publish_as(
        &mut state,
        "client.v1.connect".to_string(),
        "{}".to_string(),
        "default".to_string(),
    )
    .expect("publish_as should succeed");

    let (principal, device_key_id) = first_device_key_id(&mut receiver);
    assert_eq!(principal.as_deref(), Some("claude"));
    assert_eq!(
        device_key_id.as_deref(),
        Some("dev-abc123"),
        "publish_as must stamp the host-derived device key_id for cap-gate scoping"
    );
}

/// An unbound (unauthenticated) connection carries no device key_id, so
/// `publish_as` stamps `None` — the anonymous principal already fails closed
/// on every capability check, and a missing device id is the unattenuated
/// (full-principal) default the kernel reads as "no device floor".
#[tokio::test]
async fn publish_as_unbound_stamps_no_device_key_id() {
    let rt = tokio::runtime::Handle::current();
    let mut state = minimal_host_state(rt);
    state.has_uplink_capability = true;
    state.ipc_publish_patterns = vec!["client.v1.*".to_string()];
    assert_eq!(state.ingress_device_key_id, None);

    let mut receiver = state.event_bus.subscribe_topic("client.v1.connect");

    IpcHost::publish_as(
        &mut state,
        "client.v1.connect".to_string(),
        "{}".to_string(),
        "default".to_string(),
    )
    .expect("publish_as should succeed");

    let (_principal, device_key_id) = first_device_key_id(&mut receiver);
    assert_eq!(
        device_key_id, None,
        "an unbound connection must not stamp a device key_id"
    );
}

/// A capsule's OWN `publish` is never device-scoped: the owner acts at full
/// principal authority, so no device_key_id is stamped even if an unrelated
/// `ingress_device_key_id` happens to be set on the host state.
#[tokio::test]
async fn publish_never_stamps_device_key_id() {
    let rt = tokio::runtime::Handle::current();
    let mut state = minimal_host_state(rt);
    state.ipc_publish_patterns = vec!["capsule.v1.*".to_string()];
    // Even with an ingress device id present, the own-principal publish path
    // must not stamp it — only the publish_as forward path carries one.
    state.ingress_device_key_id = Some("dev-abc123".to_string());

    let mut receiver = state.event_bus.subscribe_topic("capsule.v1.ping");

    IpcHost::publish(&mut state, "capsule.v1.ping".to_string(), "{}".to_string())
        .expect("publish should succeed");

    let (_principal, device_key_id) = first_device_key_id(&mut receiver);
    assert_eq!(
        device_key_id, None,
        "a capsule's own publish must never carry a device key_id"
    );
}

/// Pull the `origin` off the first published message.
fn first_origin(receiver: &mut astrid_events::EventReceiver) -> astrid_events::ipc::MessageOrigin {
    let event = receiver.try_recv().expect("one published message");
    match &*event {
        AstridEvent::Ipc { message, .. } => message.origin,
        _ => panic!("expected an Ipc event"),
    }
}

/// Build a caller-context message carrying a given transport `origin`, as the
/// dispatcher installs per invocation.
fn caller_with_origin(origin: astrid_events::ipc::MessageOrigin) -> astrid_events::ipc::IpcMessage {
    astrid_events::ipc::IpcMessage::new(
        "in.flight",
        astrid_events::ipc::IpcPayload::Connect,
        uuid::Uuid::nil(),
    )
    .with_principal("default")
    .with_origin(origin)
}

/// THE no-elevation invariant: a fan-out capsule re-publishing on behalf of a
/// `RemoteGateway`-originated request must PRESERVE that origin — it can never
/// be silently elevated to `LocalSocket` by the fresh `InternalIpcMessage` the
/// fan-out builds. This is what stops a remote API caller's request, flowing
/// through react → openai-compat, from earning local-operator privilege at the
/// egress site.
#[tokio::test]
async fn publish_preserves_remote_gateway_origin_through_fanout() {
    let rt = tokio::runtime::Handle::current();
    let mut state = minimal_host_state(rt);
    state.ipc_publish_patterns = vec!["capsule.v1.*".to_string()];
    // The in-flight request arrived over the gateway HTTP listener.
    state.caller_context = Some(caller_with_origin(
        astrid_events::ipc::MessageOrigin::RemoteGateway,
    ));

    let mut receiver = state.event_bus.subscribe_topic("capsule.v1.ping");
    IpcHost::publish(&mut state, "capsule.v1.ping".to_string(), "{}".to_string())
        .expect("publish should succeed");

    assert_eq!(
        first_origin(&mut receiver),
        astrid_events::ipc::MessageOrigin::RemoteGateway,
        "a RemoteGateway request re-published by a fan-out capsule must stay \
         RemoteGateway — never elevated to LocalSocket"
    );
}

/// END-TO-END anti-forge invariant lock: a `RemoteGateway`-stamped request that
/// flows through the REAL fan-out hop chain (gateway stamp → fan-out capsule's
/// `publish` inherits caller_context.origin → `publish_inner` carries it onto
/// the republished bus message → the downstream capsule's dispatcher installs
/// that message as its `caller_context`) must be observed AS `RemoteGateway` at
/// the egress consent site — so `consent_local_egress` DECLINES (fail-closed)
/// and a remote API caller can never reach a loopback/private endpoint.
///
/// This closes the loop the bus-level propagation tests leave open: they prove
/// the origin survives ONE publish; this proves the surviving origin, fed back
/// into a downstream `HostState` exactly as the dispatcher does, makes the
/// consent gate refuse. It pins the whole `dispatcher → caller_context.origin →
/// publish_inner → downstream caller_context → consent_local_egress` chain
/// against any future republish that resets origin to `System`/`LocalSocket`.
#[tokio::test(flavor = "multi_thread")]
async fn remote_gateway_origin_survives_fanout_and_consent_declines() {
    use std::sync::Arc;

    use astrid_approval::AllowanceStore;

    let rt = tokio::runtime::Handle::current();

    // ── Hop 1: the gateway-originated request enters fan-out capsule A
    // (react stand-in). The dispatcher installed a RemoteGateway caller_context.
    let mut react = minimal_host_state(rt.clone());
    react.ipc_publish_patterns = vec!["capsule.v1.*".to_string()];
    react.caller_context = Some(caller_with_origin(
        astrid_events::ipc::MessageOrigin::RemoteGateway,
    ));

    // Capsule A re-publishes downstream (react → openai-compat) over the REAL
    // publish path. Subscribe first to capture the republished message verbatim.
    let mut downstream = react.event_bus.subscribe_topic("capsule.v1.infer");
    IpcHost::publish(&mut react, "capsule.v1.infer".to_string(), "{}".to_string())
        .expect("fan-out publish should succeed");

    // The republished bus message — exactly what the kernel routes to capsule B.
    let republished = match &*downstream.try_recv().expect("one republished message") {
        AstridEvent::Ipc { message, .. } => message.clone(),
        other => panic!("expected an Ipc event, got {other:?}"),
    };
    assert_eq!(
        republished.origin,
        astrid_events::ipc::MessageOrigin::RemoteGateway,
        "publish_inner must carry the RemoteGateway origin onto the republished \
         message — never reset it to the System default"
    );

    // ── Hop 2: the dispatcher installs the republished message as capsule B's
    // (openai-compat stand-in) caller_context, exactly as it does per invocation.
    let mut openai_compat = minimal_host_state(rt);
    openai_compat.allowance_store = Some(Arc::new(AllowanceStore::new()));
    openai_compat.caller_context = Some(republished);

    // The egress site reads the inherited origin and refuses consent: a remote
    // caller can neither see nor grant a local-egress prompt. fail-closed.
    assert_eq!(
        openai_compat.effective_origin(),
        astrid_events::ipc::MessageOrigin::RemoteGateway,
        "the downstream egress site must observe RemoteGateway after the hop"
    );
    let permitted =
        tokio::task::block_in_place(|| openai_compat.consent_local_egress("127.0.0.1", 1234));
    assert!(
        !permitted,
        "a RemoteGateway request that fanned out through a republish must be \
         DECLINED at the egress consent gate — it must never be silently \
         elevated to a local-operator grant across the hop"
    );
}

/// A guest `publish` with no in-flight caller context (a run-loop's
/// self-triggered / load-time publish) is `System` — the fail-closed,
/// non-local floor. A guest can never name an origin.
#[tokio::test]
async fn publish_without_caller_context_is_system_origin() {
    let rt = tokio::runtime::Handle::current();
    let mut state = minimal_host_state(rt);
    state.ipc_publish_patterns = vec!["capsule.v1.*".to_string()];
    assert!(state.caller_context.is_none());

    let mut receiver = state.event_bus.subscribe_topic("capsule.v1.ping");
    IpcHost::publish(&mut state, "capsule.v1.ping".to_string(), "{}".to_string())
        .expect("publish should succeed");

    assert_eq!(
        first_origin(&mut receiver),
        astrid_events::ipc::MessageOrigin::System,
        "a no-caller publish must default to System, not inherit a stale origin"
    );
}

/// A `publish_as` forward off a BOUND local-socket connection stamps
/// `LocalSocket` — the positive operator signal the egress gate keys on.
#[tokio::test]
async fn publish_as_bound_connection_stamps_local_socket_origin() {
    let rt = tokio::runtime::Handle::current();
    let mut state = minimal_host_state(rt);
    state.has_uplink_capability = true;
    state.ipc_publish_patterns = vec!["client.v1.*".to_string()];
    // The framed read off a bound connection recorded LocalSocket.
    state.ingress_principal = Some(astrid_core::PrincipalId::new("claude").unwrap());
    state.ingress_origin = Some(astrid_events::ipc::MessageOrigin::LocalSocket);

    let mut receiver = state.event_bus.subscribe_topic("client.v1.connect");
    IpcHost::publish_as(
        &mut state,
        "client.v1.connect".to_string(),
        "{}".to_string(),
        "default".to_string(),
    )
    .expect("publish_as should succeed");

    assert_eq!(
        first_origin(&mut receiver),
        astrid_events::ipc::MessageOrigin::LocalSocket,
        "a publish_as forward off a bound connection must stamp LocalSocket"
    );
}

/// A `publish_as` forward off an UNBOUND connection has `ingress_origin = None`,
/// so it stamps `System` (fail-closed, non-local) — an unauthenticated local
/// forward earns no local-operator privilege.
#[tokio::test]
async fn publish_as_unbound_connection_stamps_system_origin() {
    let rt = tokio::runtime::Handle::current();
    let mut state = minimal_host_state(rt);
    state.has_uplink_capability = true;
    state.ipc_publish_patterns = vec!["client.v1.*".to_string()];
    assert_eq!(state.ingress_origin, None);

    let mut receiver = state.event_bus.subscribe_topic("client.v1.connect");
    IpcHost::publish_as(
        &mut state,
        "client.v1.connect".to_string(),
        "{}".to_string(),
        "default".to_string(),
    )
    .expect("publish_as should succeed");

    assert_eq!(
        first_origin(&mut receiver),
        astrid_events::ipc::MessageOrigin::System,
        "an unbound publish_as forward must stamp System (non-local), not LocalSocket"
    );
}
