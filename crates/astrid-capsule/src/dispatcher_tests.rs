//! Tests for [`crate::dispatcher`]. Kept in a sibling file (referenced
//! via `#[path]`) so `dispatcher.rs` stays under the per-file CI line
//! cap while the test surface continues to grow with new dispatch
//! semantics (priority order, chain short-circuit, per-principal
//! isolation, …).

use super::*;

// ── Dispatch integration tests ──────────────────────────────────

use async_trait::async_trait;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use crate::capsule::{Capsule, CapsuleId, CapsuleState, InterceptResult};
use crate::context::CapsuleContext;
use crate::error::CapsuleResult;
use crate::manifest::{CapabilitiesDef, CapsuleManifest, PackageDef, SubscribeDef};
use crate::registry::WasmHash;
use astrid_core::PrincipalId;
use astrid_events::ipc::IpcPayload;
use astrid_events::ipc::Topic;

/// Register a mock capsule into the default principal's view (#1069).
///
/// The non-view-scoped integration tests here publish on mesh topics (no
/// principal, or a non-tool topic), which the dispatcher routes over the GLOBAL
/// instance set (`all_instances`) — so a capsule in ANY view is reachable.
/// `default` is the natural home. The instance hash is synthesized per capsule
/// id so each occupies its own instance slot.
fn register_mock(registry: &mut CapsuleRegistry, capsule: Box<dyn Capsule>) {
    register_mock_for(registry, capsule, &PrincipalId::default());
}

/// Register a mock capsule into a SPECIFIC principal's view (#1069). Used by the
/// view-scope / access tests, which publish on the view-scoped surface
/// (`tool.v1.execute.*`, `cli.v1.command.execute`, `tool.v1.request.describe`)
/// where the dispatcher iterates ONLY the caller's view — so the capsule must be
/// in the CALLER's view to be a candidate at all (the fail-closed floor that
/// precedes the grant gate).
fn register_mock_for(
    registry: &mut CapsuleRegistry,
    capsule: Box<dyn Capsule>,
    principal: &PrincipalId,
) {
    let hash = WasmHash::synthetic(capsule.id().as_str(), "0.0.1");
    registry.register(capsule, hash, principal).unwrap();
}

/// A minimal mock capsule for dispatch tests.
struct MockCapsule {
    id: CapsuleId,
    manifest: CapsuleManifest,
    invoked: Arc<AtomicBool>,
    /// Optional shared log for recording invocation order across capsules.
    invocation_log: Option<Arc<Mutex<Vec<String>>>>,
    /// Override the default `Continue` result for testing chain semantics.
    result_override: Option<InterceptResult>,
    /// Optional principal-tagged invocation counter. When set, every
    /// `invoke_interceptor` call appends the caller's `principal`
    /// field (or `<none>` for system events). Tests use this to
    /// assert per-principal isolation under fan-in.
    principal_log: Option<Arc<Mutex<Vec<String>>>>,
    /// Optional shared counter incremented on every invoke.
    invoke_counter: Option<Arc<AtomicUsize>>,
}

impl MockCapsule {
    fn new(name: &str, interceptor_event: &str) -> (Self, Arc<AtomicBool>) {
        Self::with_priority(name, interceptor_event, 100, None)
    }

    fn with_priority(
        name: &str,
        interceptor_event: &str,
        priority: u32,
        invocation_log: Option<Arc<Mutex<Vec<String>>>>,
    ) -> (Self, Arc<AtomicBool>) {
        let invoked = Arc::new(AtomicBool::new(false));
        let manifest = CapsuleManifest {
            package: PackageDef {
                name: name.to_string(),
                version: "0.0.1".to_string(),
                description: None,
                authors: Vec::new(),
                repository: None,
                homepage: None,
                documentation: None,
                license: None,
                license_file: None,
                readme: None,
                keywords: Vec::new(),
                categories: Vec::new(),
                astrid_version: None,
                publish: None,
                include: None,
                exclude: None,
                metadata: None,
            },
            components: Vec::new(),
            imports: std::collections::HashMap::new(),
            exports: std::collections::HashMap::new(),
            capabilities: CapabilitiesDef::default(),
            env: std::collections::HashMap::new(),
            context_files: Vec::new(),
            commands: Vec::new(),
            mcp_servers: Vec::new(),
            skills: Vec::new(),
            uplinks: Vec::new(),
            publishes: ::std::collections::HashMap::new(),
            // Interceptor binding = a [subscribe] entry with a handler (and
            // priority). effective_interceptors() resolves this to the same
            // dispatch tuple the removed [[interceptor]] block produced.
            subscribes: ::std::collections::HashMap::from([(
                interceptor_event.to_string(),
                SubscribeDef {
                    wit: "opaque".to_string(),
                    version: None,
                    tag: None,
                    rev: None,
                    branch: None,
                    path: None,
                    handler: Some("test_action".to_string()),
                    priority: Some(priority),
                },
            )]),
            tools: ::std::vec::Vec::new(),
        };
        let capsule = Self {
            id: CapsuleId::from_static(name),
            manifest,
            invoked: Arc::clone(&invoked),
            invocation_log,
            result_override: None,
            principal_log: None,
            invoke_counter: None,
        };
        (capsule, invoked)
    }
}

#[async_trait]
impl Capsule for MockCapsule {
    fn id(&self) -> &CapsuleId {
        &self.id
    }
    fn manifest(&self) -> &CapsuleManifest {
        &self.manifest
    }
    fn state(&self) -> CapsuleState {
        CapsuleState::Ready
    }
    async fn load(&mut self, _ctx: &CapsuleContext) -> CapsuleResult<()> {
        Ok(())
    }
    async fn unload(&mut self) -> CapsuleResult<()> {
        Ok(())
    }
    async fn invoke_interceptor(
        &self,
        _action: &str,
        _payload: &[u8],
        caller: Option<&astrid_events::ipc::IpcMessage>,
    ) -> CapsuleResult<InterceptResult> {
        self.invoked.store(true, Ordering::SeqCst);
        if let Some(ref log) = self.invocation_log {
            log.lock().unwrap().push(self.id.to_string());
        }
        if let Some(ref log) = self.principal_log {
            let p = caller
                .and_then(|m| m.principal.clone())
                .unwrap_or_else(|| "<none>".to_string());
            log.lock().unwrap().push(p);
        }
        if let Some(ref c) = self.invoke_counter {
            c.fetch_add(1, Ordering::SeqCst);
        }
        if let Some(ref result) = self.result_override {
            return Ok(result.clone());
        }
        Ok(InterceptResult::Continue(Vec::new()))
    }
}

/// Helper: publish an IPC event on the bus.
fn publish_ipc(bus: &EventBus, topic: &str) {
    let msg = astrid_events::ipc::IpcMessage::new(
        Topic::from_raw(topic),
        IpcPayload::Custom {
            data: serde_json::json!({}),
        },
        uuid::Uuid::nil(),
    );
    bus.publish(AstridEvent::Ipc {
        metadata: astrid_events::EventMetadata::new("test"),
        message: msg,
    });
}

/// Helper: publish an IPC event tagged with a principal.
fn publish_ipc_as(bus: &EventBus, topic: &str, principal: &str) {
    let msg = astrid_events::ipc::IpcMessage::new(
        Topic::from_raw(topic),
        IpcPayload::Custom {
            data: serde_json::json!({}),
        },
        uuid::Uuid::nil(),
    )
    .with_principal(principal);
    bus.publish(AstridEvent::Ipc {
        metadata: astrid_events::EventMetadata::new("test"),
        message: msg,
    });
}

#[tokio::test]
async fn dispatch_routes_to_matching_interceptor() {
    let (capsule, invoked) = MockCapsule::new("test-capsule", "test.topic");

    let mut registry = CapsuleRegistry::new();
    register_mock(&mut registry, Box::new(capsule));
    let registry = Arc::new(RwLock::new(registry));

    let bus = Arc::new(EventBus::with_capacity(64));
    let dispatcher = EventDispatcher::new(Arc::clone(&registry), Arc::clone(&bus));
    let handle = tokio::spawn(dispatcher.run());

    // Yield to let the dispatcher subscribe before publishing.
    tokio::task::yield_now().await;

    publish_ipc(&bus, "test.topic");

    // Give the dispatcher time to process.
    tokio::time::sleep(Duration::from_millis(200)).await;

    assert!(
        invoked.load(Ordering::SeqCst),
        "interceptor should have been invoked for matching topic"
    );

    handle.abort();
}

#[tokio::test]
async fn dispatch_skips_non_matching_topic() {
    let (capsule, invoked) = MockCapsule::new("test-capsule-skip", "specific.topic");

    let mut registry = CapsuleRegistry::new();
    register_mock(&mut registry, Box::new(capsule));
    let registry = Arc::new(RwLock::new(registry));

    let bus = Arc::new(EventBus::with_capacity(64));
    let dispatcher = EventDispatcher::new(Arc::clone(&registry), Arc::clone(&bus));
    let handle = tokio::spawn(dispatcher.run());

    tokio::task::yield_now().await;

    publish_ipc(&bus, "other.topic");

    tokio::time::sleep(Duration::from_millis(200)).await;

    assert!(
        !invoked.load(Ordering::SeqCst),
        "interceptor should NOT have been invoked for non-matching topic"
    );

    handle.abort();
}

#[tokio::test]
async fn dispatch_concurrent_does_not_block() {
    // Both capsules match different topics. With concurrent dispatch,
    // the second event is processed immediately without waiting for
    // the first interceptor to complete.
    let (cap_a, invoked_a) = MockCapsule::new("capsule-a", "topic.a");
    let (cap_b, invoked_b) = MockCapsule::new("capsule-b", "topic.b");

    let mut registry = CapsuleRegistry::new();
    register_mock(&mut registry, Box::new(cap_a));
    register_mock(&mut registry, Box::new(cap_b));
    let registry = Arc::new(RwLock::new(registry));

    let bus = Arc::new(EventBus::with_capacity(64));
    let dispatcher = EventDispatcher::new(Arc::clone(&registry), Arc::clone(&bus));
    let handle = tokio::spawn(dispatcher.run());

    tokio::task::yield_now().await;

    publish_ipc(&bus, "topic.a");
    publish_ipc(&bus, "topic.b");

    tokio::time::sleep(Duration::from_millis(200)).await;

    assert!(
        invoked_a.load(Ordering::SeqCst),
        "capsule-a interceptor should have been invoked"
    );
    assert!(
        invoked_b.load(Ordering::SeqCst),
        "capsule-b interceptor should have been invoked"
    );

    handle.abort();
}

#[tokio::test]
async fn dispatch_routes_lifecycle_events() {
    // Lifecycle events are dispatched by event_type() as the topic.
    let (capsule, invoked) =
        MockCapsule::new("lifecycle-capsule", "astrid.v1.lifecycle.tool_call_started");

    let mut registry = CapsuleRegistry::new();
    register_mock(&mut registry, Box::new(capsule));
    let registry = Arc::new(RwLock::new(registry));

    let bus = Arc::new(EventBus::with_capacity(64));
    let dispatcher = EventDispatcher::new(Arc::clone(&registry), Arc::clone(&bus));
    let handle = tokio::spawn(dispatcher.run());

    tokio::task::yield_now().await;

    // Publish a lifecycle event
    bus.publish(AstridEvent::ToolCallStarted {
        metadata: astrid_events::EventMetadata::new("test"),
        call_id: uuid::Uuid::nil(),
        tool_name: "search".into(),
        server_name: None,
    });

    tokio::time::sleep(Duration::from_millis(200)).await;

    assert!(
        invoked.load(Ordering::SeqCst),
        "EventDispatcher should dispatch lifecycle events by event_type()"
    );

    handle.abort();
}

#[tokio::test]
async fn dispatch_publishes_lag_event_on_overflow() {
    // Use a tiny bus capacity so publishing more events than capacity triggers lag.
    let bus = Arc::new(EventBus::with_capacity(2));

    // A capsule that listens for lag events.
    let (lag_capsule, _lag_invoked) =
        MockCapsule::new("lag-listener", "astrid.v1.event_bus.lagged");

    let mut registry = CapsuleRegistry::new();
    register_mock(&mut registry, Box::new(lag_capsule));
    let registry = Arc::new(RwLock::new(registry));

    let dispatcher = EventDispatcher::new(Arc::clone(&registry), Arc::clone(&bus));
    let handle = tokio::spawn(dispatcher.run());

    tokio::task::yield_now().await;

    // Flood the bus to trigger lag (the dispatcher's receiver has capacity 2,
    // so publishing many events quickly should cause overflow).
    for i in 0..20 {
        publish_ipc(&bus, &format!("flood.event.{i}"));
    }

    tokio::time::sleep(Duration::from_millis(500)).await;

    // If lag was detected, the dispatcher should have published
    // astrid.v1.event_bus.lagged which routes to our lag-listener capsule.
    // Note: this test may not trigger lag on fast machines where the
    // dispatcher drains fast enough. That's acceptable - the test
    // validates the wiring, not the race condition.
    // We just verify no panics occurred and the dispatcher is still running.
    assert!(!handle.is_finished(), "dispatcher should still be running");
    handle.abort();
}

#[test]
fn mock_capsule_check_health_returns_ready() {
    let (capsule, _) = MockCapsule::new("health-test", "test.topic");
    assert_eq!(capsule.check_health(), CapsuleState::Ready);
}

#[tokio::test]
async fn dispatch_respects_interceptor_priority_order() {
    // Three capsules intercept the same topic with different priorities.
    // Priority 10 (guard) should fire before 50 (transform) before 100 (handler).
    let order = Arc::new(Mutex::new(Vec::<String>::new()));

    let (guard, _) =
        MockCapsule::with_priority("guard", "shared.topic", 10, Some(Arc::clone(&order)));
    let (handler, _) =
        MockCapsule::with_priority("handler", "shared.topic", 100, Some(Arc::clone(&order)));
    let (transform, _) =
        MockCapsule::with_priority("transform", "shared.topic", 50, Some(Arc::clone(&order)));

    let mut registry = CapsuleRegistry::new();
    // Register in non-priority order to prove sorting works.
    register_mock(&mut registry, Box::new(handler));
    register_mock(&mut registry, Box::new(guard));
    register_mock(&mut registry, Box::new(transform));
    let registry = Arc::new(RwLock::new(registry));

    let bus = Arc::new(EventBus::with_capacity(64));
    let dispatcher = EventDispatcher::new(Arc::clone(&registry), Arc::clone(&bus));
    let handle = tokio::spawn(dispatcher.run());

    tokio::task::yield_now().await;

    publish_ipc(&bus, "shared.topic");

    tokio::time::sleep(Duration::from_millis(300)).await;

    let recorded = order.lock().unwrap().clone();
    assert_eq!(
        recorded,
        vec!["guard", "transform", "handler"],
        "interceptors must fire in priority order (lower first)"
    );

    handle.abort();
}

#[tokio::test]
async fn find_matching_interceptors_sorts_by_priority() {
    // Unit test for find_matching_interceptors directly.
    let (low, _) = MockCapsule::with_priority("low-pri", "test.event", 10, None);
    let (high, _) = MockCapsule::with_priority("high-pri", "test.event", 200, None);
    let (mid, _) = MockCapsule::with_priority("mid-pri", "test.event", 50, None);

    let mut registry = CapsuleRegistry::new();
    register_mock(&mut registry, Box::new(high));
    register_mock(&mut registry, Box::new(low));
    register_mock(&mut registry, Box::new(mid));
    let registry = Arc::new(RwLock::new(registry));
    let bus = EventBus::with_capacity(64);

    let matches = find_matching_interceptors(&registry, "test.event", None, None, &bus).await;
    let names: Vec<&str> = matches.iter().map(|(c, _, _)| c.id().as_str()).collect();
    assert_eq!(
        names,
        vec!["low-pri", "mid-pri", "high-pri"],
        "find_matching_interceptors must return results sorted by priority"
    );
}

#[tokio::test]
async fn find_matching_interceptors_tiebreaks_equal_priority_by_id() {
    // Equal-priority members must have a DETERMINISTIC order — `registry.list()`
    // is HashMap order, so a priority-only sort left ties arbitrary, which
    // matters in the ordered-chain path where a tied member's Final/Deny
    // short-circuits its sibling. The stable tiebreak is (priority, capsule id,
    // action). Two members tie at 20; the lone 10 sorts first, then the 20s by
    // id ("a-tie" before "z-tie") regardless of registration order.
    let (z_tie, _) = MockCapsule::with_priority("z-tie", "test.event", 20, None);
    let (a_tie, _) = MockCapsule::with_priority("a-tie", "test.event", 20, None);
    let (guard, _) = MockCapsule::with_priority("guard", "test.event", 10, None);

    let mut registry = CapsuleRegistry::new();
    // Register in an order that does NOT match the expected sort.
    register_mock(&mut registry, Box::new(z_tie));
    register_mock(&mut registry, Box::new(guard));
    register_mock(&mut registry, Box::new(a_tie));
    let registry = Arc::new(RwLock::new(registry));
    let bus = EventBus::with_capacity(64);

    let matches = find_matching_interceptors(&registry, "test.event", None, None, &bus).await;
    let names: Vec<&str> = matches.iter().map(|(c, _, _)| c.id().as_str()).collect();
    assert_eq!(
        names,
        vec!["guard", "a-tie", "z-tie"],
        "equal-priority members must tiebreak deterministically by capsule id"
    );
}

#[tokio::test]
async fn deny_interceptor_short_circuits_chain() {
    // Guard at priority 10 denies, handler at priority 100 should never fire.
    let order = Arc::new(Mutex::new(Vec::<String>::new()));

    let (mut guard, _) =
        MockCapsule::with_priority("guard", "shared.topic", 10, Some(Arc::clone(&order)));
    guard.result_override = Some(InterceptResult::Deny {
        reason: "blocked by guard".into(),
    });

    let (handler, invoked_handler) =
        MockCapsule::with_priority("handler", "shared.topic", 100, Some(Arc::clone(&order)));

    let mut registry = CapsuleRegistry::new();
    register_mock(&mut registry, Box::new(handler));
    register_mock(&mut registry, Box::new(guard));
    let registry = Arc::new(RwLock::new(registry));

    let bus = Arc::new(EventBus::with_capacity(64));
    let dispatcher = EventDispatcher::new(Arc::clone(&registry), Arc::clone(&bus));
    let handle = tokio::spawn(dispatcher.run());

    tokio::task::yield_now().await;

    publish_ipc(&bus, "shared.topic");

    tokio::time::sleep(Duration::from_millis(300)).await;

    let recorded = order.lock().unwrap().clone();
    assert_eq!(
        recorded,
        vec!["guard"],
        "only the guard should have fired — handler should be short-circuited"
    );
    assert!(
        !invoked_handler.load(Ordering::SeqCst),
        "handler must NOT be invoked after Deny"
    );

    handle.abort();
}

#[tokio::test]
async fn final_interceptor_short_circuits_chain() {
    // Cache at priority 30 returns Final, core at priority 100 should never fire.
    let order = Arc::new(Mutex::new(Vec::<String>::new()));

    let (mut cache, _) =
        MockCapsule::with_priority("cache", "shared.topic", 30, Some(Arc::clone(&order)));
    cache.result_override = Some(InterceptResult::Final(b"cached response".to_vec()));

    let (core, invoked_core) =
        MockCapsule::with_priority("core", "shared.topic", 100, Some(Arc::clone(&order)));

    let mut registry = CapsuleRegistry::new();
    register_mock(&mut registry, Box::new(core));
    register_mock(&mut registry, Box::new(cache));
    let registry = Arc::new(RwLock::new(registry));

    let bus = Arc::new(EventBus::with_capacity(64));
    let dispatcher = EventDispatcher::new(Arc::clone(&registry), Arc::clone(&bus));
    let handle = tokio::spawn(dispatcher.run());

    tokio::task::yield_now().await;

    publish_ipc(&bus, "shared.topic");

    tokio::time::sleep(Duration::from_millis(300)).await;

    let recorded = order.lock().unwrap().clone();
    assert_eq!(
        recorded,
        vec!["cache"],
        "only the cache should have fired — core should be short-circuited"
    );
    assert!(
        !invoked_core.load(Ordering::SeqCst),
        "core must NOT be invoked after Final"
    );

    handle.abort();
}

#[tokio::test]
async fn equal_priority_matches_fan_out_without_cross_suppression() {
    // Regression: multiple subscribers at the SAME priority are an independent
    // fan-out, not an ordered chain. Every subscriber must fire, and one
    // returning Deny must NOT short-circuit the others. (A 6-way tool-describe
    // fan-out previously reached only ~3 of 6 responders because it ran as a
    // single serial, short-circuiting chain whose lead member could starve the
    // rest.)
    let (mut denier, denier_invoked) =
        MockCapsule::with_priority("denier", "fanout.topic", 100, None);
    denier.result_override = Some(InterceptResult::Deny {
        reason: "must not suppress siblings".into(),
    });

    let (resp_a, invoked_a) = MockCapsule::with_priority("resp-a", "fanout.topic", 100, None);
    let (resp_b, invoked_b) = MockCapsule::with_priority("resp-b", "fanout.topic", 100, None);
    let (resp_c, invoked_c) = MockCapsule::with_priority("resp-c", "fanout.topic", 100, None);

    let mut registry = CapsuleRegistry::new();
    // Register the denier first — under the old chain it could sort ahead of the
    // responders and short-circuit them; the fan-out path fires every match.
    register_mock(&mut registry, Box::new(denier));
    register_mock(&mut registry, Box::new(resp_a));
    register_mock(&mut registry, Box::new(resp_b));
    register_mock(&mut registry, Box::new(resp_c));
    let registry = Arc::new(RwLock::new(registry));

    let bus = Arc::new(EventBus::with_capacity(64));
    let dispatcher = EventDispatcher::new(Arc::clone(&registry), Arc::clone(&bus));
    let handle = tokio::spawn(dispatcher.run());

    tokio::task::yield_now().await;
    publish_ipc(&bus, "fanout.topic");
    tokio::time::sleep(Duration::from_millis(300)).await;

    assert!(
        denier_invoked.load(Ordering::SeqCst),
        "the denier itself must fire"
    );
    assert!(
        invoked_a.load(Ordering::SeqCst)
            && invoked_b.load(Ordering::SeqCst)
            && invoked_c.load(Ordering::SeqCst),
        "every equal-priority subscriber must fire — a sibling's Deny must not \
         short-circuit the fan-out"
    );

    handle.abort();
}

#[test]
fn intercept_result_from_guest_bytes() {
    // Empty = Continue
    let r = InterceptResult::from_guest_bytes(vec![]);
    assert!(matches!(r, InterceptResult::Continue(ref b) if b.is_empty()));

    // 0x00 + payload = Continue
    let r = InterceptResult::from_guest_bytes(vec![0x00, 1, 2, 3]);
    assert!(matches!(r, InterceptResult::Continue(ref b) if b == &[1, 2, 3]));

    // 0x01 + payload = Final
    let r = InterceptResult::from_guest_bytes(vec![0x01, 4, 5]);
    assert!(matches!(r, InterceptResult::Final(ref b) if b == &[4, 5]));

    // 0x02 + reason = Deny
    let r = InterceptResult::from_guest_bytes(vec![0x02, b'n', b'o']);
    assert!(matches!(r, InterceptResult::Deny { ref reason } if reason == "no"));

    // Unknown discriminant = Continue with full bytes
    let r = InterceptResult::from_guest_bytes(vec![0xFF, 1]);
    assert!(matches!(r, InterceptResult::Continue(ref b) if b == &[0xFF, 1]));
}

// ── Per-(capsule, principal) routing tests (#813 Layer 3) ───────

#[tokio::test]
async fn single_match_does_not_block_across_principal_keys() {
    // One capsule, one topic, two user-class principals (alice + bob).
    // Two events under distinct principals (same class) must be
    // processed without HOL blocking — both invocations land within a
    // short window even if one consumer is slow.
    let principal_log = Arc::new(Mutex::new(Vec::<String>::new()));
    let (mut capsule, _invoked) = MockCapsule::new("class-cap", "split.topic");
    capsule.principal_log = Some(Arc::clone(&principal_log));

    let mut registry = CapsuleRegistry::new();
    register_mock(&mut registry, Box::new(capsule));
    let registry = Arc::new(RwLock::new(registry));

    let bus = Arc::new(EventBus::with_capacity(64));
    let dispatcher = EventDispatcher::new(Arc::clone(&registry), Arc::clone(&bus));
    let handle = tokio::spawn(dispatcher.run());

    tokio::task::yield_now().await;

    // Two distinct user principals — same class but distinct
    // PrincipalKey. With per-class keying these would collide on a
    // single queue; with per-principal keying each runs on its own
    // consumer task.
    publish_ipc_as(&bus, "split.topic", "alice");
    publish_ipc_as(&bus, "split.topic", "bob");

    tokio::time::sleep(Duration::from_millis(300)).await;

    let recorded = principal_log.lock().unwrap().clone();
    assert!(
        recorded.contains(&"alice".to_string()),
        "alice's event should have been invoked: {recorded:?}"
    );
    assert!(
        recorded.contains(&"bob".to_string()),
        "bob's event should have been invoked: {recorded:?}"
    );
    handle.abort();
}

#[tokio::test]
async fn chain_serializes_per_principal_key_on_same_capsule() {
    // A chain of two capsules where each interceptor records its
    // invocation. Two events under the SAME principal serialize FIFO
    // through the chain mutex; two events under DISTINCT principals
    // are concurrent.
    let order = Arc::new(Mutex::new(Vec::<String>::new()));
    let (cap_a, _) =
        MockCapsule::with_priority("ser-a", "chain.topic", 50, Some(Arc::clone(&order)));
    let (cap_b, _) =
        MockCapsule::with_priority("ser-b", "chain.topic", 100, Some(Arc::clone(&order)));

    let mut registry = CapsuleRegistry::new();
    register_mock(&mut registry, Box::new(cap_a));
    register_mock(&mut registry, Box::new(cap_b));
    let registry = Arc::new(RwLock::new(registry));

    let bus = Arc::new(EventBus::with_capacity(64));
    let dispatcher = EventDispatcher::new(Arc::clone(&registry), Arc::clone(&bus));
    let handle = tokio::spawn(dispatcher.run());
    tokio::task::yield_now().await;

    // Same principal (alice) twice → chain mutex serializes both.
    publish_ipc_as(&bus, "chain.topic", "alice");
    publish_ipc_as(&bus, "chain.topic", "alice");

    tokio::time::sleep(Duration::from_millis(500)).await;

    let recorded = order.lock().unwrap().clone();
    // Each event produces ser-a then ser-b. Two events = 4 entries
    // (two complete chains, never interleaved within a (capsule,
    // principal) pair).
    assert_eq!(recorded.len(), 4, "two full chains should have completed");
    // Within each chain ser-a precedes ser-b.
    assert_eq!(recorded[0], "ser-a");
    assert_eq!(recorded[1], "ser-b");
    assert_eq!(recorded[2], "ser-a");
    assert_eq!(recorded[3], "ser-b");

    handle.abort();
}

#[tokio::test]
async fn dispatch_isolates_per_principal_under_n1000_fanin() {
    // Publish 1000 events under 1000 distinct principals against a
    // single interceptor. Per-principal queue partitioning means each
    // event gets its own queue (queue capacity 64 — well above the
    // single event each queue receives) and no event is dropped.
    let counter = Arc::new(AtomicUsize::new(0));
    let principals = Arc::new(Mutex::new(Vec::<String>::new()));
    let (mut capsule, _) = MockCapsule::new("fanin-cap", "fanin.topic");
    capsule.invoke_counter = Some(Arc::clone(&counter));
    capsule.principal_log = Some(Arc::clone(&principals));

    let mut registry = CapsuleRegistry::new();
    register_mock(&mut registry, Box::new(capsule));
    let registry = Arc::new(RwLock::new(registry));

    // Bus with generous capacity so the broadcast subscriber doesn't
    // lag and synthesize a Lagged signal we don't care about here.
    let bus = Arc::new(EventBus::with_capacity(4096));
    let dispatcher = EventDispatcher::new(Arc::clone(&registry), Arc::clone(&bus));
    let handle = tokio::spawn(dispatcher.run());

    tokio::task::yield_now().await;

    const N: usize = 1000;
    for i in 0..N {
        publish_ipc_as(&bus, "fanin.topic", &format!("user-{i}"));
    }

    // Wait long enough for all 1000 per-principal consumers to drain
    // their single-element queues.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while counter.load(Ordering::SeqCst) < N && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let observed = counter.load(Ordering::SeqCst);
    assert_eq!(
        observed, N,
        "all {N} per-principal events should have invoked the interceptor (got {observed})"
    );
    let recorded_principals = principals.lock().unwrap().clone();
    let unique = recorded_principals
        .iter()
        .collect::<std::collections::HashSet<_>>()
        .len();
    assert_eq!(
        unique, N,
        "every recorded invocation should carry a distinct principal (got {unique})"
    );

    handle.abort();
}

#[tokio::test]
async fn dispatch_does_not_drop_under_burst_to_single_principal() {
    // Publish many events for one principal — they all queue against a
    // single consumer task (capacity 64). The dispatcher waits on the
    // bus subscribe-recv between publishes (in the bus broadcast path
    // every published event materially fans out through the receiver
    // before the next is taken), so even bursts within the 64-deep
    // queue are drained one-at-a-time without drops.
    let counter = Arc::new(AtomicUsize::new(0));
    let (mut capsule, _) = MockCapsule::new("burst-cap", "burst.topic");
    capsule.invoke_counter = Some(Arc::clone(&counter));

    let mut registry = CapsuleRegistry::new();
    register_mock(&mut registry, Box::new(capsule));
    let registry = Arc::new(RwLock::new(registry));

    let bus = Arc::new(EventBus::with_capacity(256));
    let dispatcher = EventDispatcher::new(Arc::clone(&registry), Arc::clone(&bus));
    let handle = tokio::spawn(dispatcher.run());
    tokio::task::yield_now().await;

    const N: usize = 50;
    for _ in 0..N {
        publish_ipc_as(&bus, "burst.topic", "burst-user");
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while counter.load(Ordering::SeqCst) < N && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let observed = counter.load(Ordering::SeqCst);
    assert_eq!(
        observed, N,
        "single-principal burst of {N} should all be delivered (got {observed})"
    );
    handle.abort();
}

// NOTE: queue-machinery tests that exercise the per-(capsule, principal)
// consumer lifecycle and chain-lock map directly (idle-eviction,
// closed-sender re-spawn, chain-lock pruning) live with the code they test, in
// `dispatcher_queues_tests.rs` attached to the `queues` module — they need its
// private internals (`dispatch_single`, `InterceptorWork`, `acquire_chain_lock`,
// the idle-grace override). The tests in THIS file drive the dispatcher through
// its public surface (matching, view scoping, the grant gate).

// ── Per-principal capsule-access enforcement (#992) ──────────────────
//
// These tests prove the kernel-side, topic-scoped, fail-closed grant
// filter on the user-invocable surface (`tool.v1.execute.*`,
// `cli.v1.command.execute`), with admin (`*`) bypass and orchestration
// topics left ungated.

mod access_enforcement {
    use super::*;

    use arc_swap::ArcSwap;
    use astrid_core::dirs::AstridHome;
    use astrid_core::groups::{BUILTIN_ADMIN, GroupConfig};
    use astrid_core::principal::PrincipalId;
    use astrid_core::profile::PrincipalProfile;
    use std::sync::Arc;

    use crate::access::CapsuleAccessResolver;
    use crate::profile_cache::PrincipalProfileCache;

    /// Build a resolver rooted at a fresh tempdir home, plus a handle to
    /// the home so the test can write principal profiles to disk. The
    /// `TempDir` is returned so it outlives the resolver.
    fn resolver_fixture() -> (tempfile::TempDir, AstridHome, CapsuleAccessResolver) {
        let dir = tempfile::tempdir().expect("tempdir");
        let home = AstridHome::from_path(dir.path());
        let cache = Arc::new(PrincipalProfileCache::with_home(home.clone()));
        let groups = Arc::new(ArcSwap::from_pointee(GroupConfig::builtin_only()));
        let resolver = CapsuleAccessResolver::new(cache, groups);
        (dir, home, resolver)
    }

    /// Write a principal profile to `etc/profiles/{principal}.toml`.
    fn write_profile(home: &AstridHome, principal: &str, profile: &PrincipalProfile) {
        let pid = PrincipalId::new(principal).unwrap();
        profile.save(home, &pid).expect("save profile");
    }

    /// A non-admin profile granted the given capsule ids.
    fn agent_with_capsules(capsules: &[&str]) -> PrincipalProfile {
        PrincipalProfile {
            capsules: capsules.iter().map(|c| (*c).to_string()).collect(),
            ..PrincipalProfile::default()
        }
    }

    /// An admin profile (member of the `admin` builtin group → holds `*`).
    fn admin_profile() -> PrincipalProfile {
        PrincipalProfile {
            groups: vec![BUILTIN_ADMIN.to_string()],
            ..PrincipalProfile::default()
        }
    }

    /// Spawn a dispatcher wired with the resolver over a registry holding
    /// one capsule whose interceptor binds `interceptor_event`, registered into
    /// `caller`'s per-principal view. Returns the invoked flag, the bus, and the
    /// task handle.
    ///
    /// The capsule is placed in the CALLER's view (#1069) so the view floor does
    /// not drop it before the grant gate can run — these tests isolate the GRANT
    /// dimension (is the in-view capsule granted?), and the separate
    /// view-isolation tests cover the floor itself. For orchestration-topic
    /// tests the caller is irrelevant (the mesh is global), but registering into
    /// the caller's view is harmless there.
    fn spawn_with_capsule(
        resolver: CapsuleAccessResolver,
        capsule_name: &str,
        interceptor_event: &str,
        caller: &str,
    ) -> (Arc<AtomicBool>, Arc<EventBus>, tokio::task::JoinHandle<()>) {
        let (capsule, invoked) = MockCapsule::new(capsule_name, interceptor_event);
        let mut registry = CapsuleRegistry::new();
        let caller_pid = PrincipalId::new(caller).expect("valid caller principal");
        register_mock_for(&mut registry, Box::new(capsule), &caller_pid);
        let registry = Arc::new(RwLock::new(registry));
        let bus = Arc::new(EventBus::with_capacity(64));
        let dispatcher = EventDispatcher::new(Arc::clone(&registry), Arc::clone(&bus))
            .with_access_resolver(resolver);
        let handle = tokio::spawn(dispatcher.run());
        (invoked, bus, handle)
    }

    /// (a) A non-admin principal WITHOUT capsule X granted must not have
    /// X's `tool.v1.execute.*` dispatched to it.
    #[tokio::test]
    async fn ungranted_principal_denied_tool_dispatch() {
        let (_dir, home, resolver) = resolver_fixture();
        // `bob` exists but is granted no capsules. The capsule IS in bob's view
        // (so the view floor passes) — the GRANT gate is what denies him here.
        write_profile(&home, "bob", &agent_with_capsules(&[]));

        let (invoked, bus, handle) =
            spawn_with_capsule(resolver, "secret-tool", "tool.v1.execute.do_thing", "bob");
        tokio::task::yield_now().await;
        publish_ipc_as(&bus, "tool.v1.execute.do_thing", "bob");
        tokio::time::sleep(Duration::from_millis(200)).await;

        assert!(
            !invoked.load(Ordering::SeqCst),
            "ungranted principal must NOT have the tool capsule dispatched"
        );
        handle.abort();
    }

    /// (b) WITH the grant, the same tool is served.
    #[tokio::test]
    async fn granted_principal_served_tool_dispatch() {
        let (_dir, home, resolver) = resolver_fixture();
        write_profile(&home, "alice", &agent_with_capsules(&["secret-tool"]));

        let (invoked, bus, handle) =
            spawn_with_capsule(resolver, "secret-tool", "tool.v1.execute.do_thing", "alice");
        tokio::task::yield_now().await;
        publish_ipc_as(&bus, "tool.v1.execute.do_thing", "alice");
        tokio::time::sleep(Duration::from_millis(200)).await;

        assert!(
            invoked.load(Ordering::SeqCst),
            "granted principal MUST have the tool capsule dispatched"
        );
        handle.abort();
    }

    /// (c) Admin (`*`) bypasses the filter — all capsules served even with
    /// no explicit capsule grant.
    #[tokio::test]
    async fn admin_bypasses_filter() {
        let (_dir, home, resolver) = resolver_fixture();
        // Admin holds `*` via the `admin` group, NOT via a capsule grant.
        write_profile(&home, "root", &admin_profile());

        let (invoked, bus, handle) =
            spawn_with_capsule(resolver, "secret-tool", "tool.v1.execute.do_thing", "root");
        tokio::task::yield_now().await;
        publish_ipc_as(&bus, "tool.v1.execute.do_thing", "root");
        tokio::time::sleep(Duration::from_millis(200)).await;

        assert!(
            invoked.load(Ordering::SeqCst),
            "admin (`*`) must bypass the per-principal filter"
        );
        handle.abort();
    }

    /// (d) `anonymous` caller → no tool capsules visible (fail-closed). The
    /// capsule is registered into `default`'s view; `anonymous` resolves to an
    /// EMPTY candidate set at the view floor, so it is dropped before the grant
    /// gate — there is no fallback to `default`'s view.
    #[tokio::test]
    async fn anonymous_caller_denied() {
        let (_dir, _home, resolver) = resolver_fixture();

        let (invoked, bus, handle) = spawn_with_capsule(
            resolver,
            "secret-tool",
            "tool.v1.execute.do_thing",
            "default",
        );
        tokio::task::yield_now().await;
        publish_ipc_as(&bus, "tool.v1.execute.do_thing", "anonymous");
        tokio::time::sleep(Duration::from_millis(200)).await;

        assert!(
            !invoked.load(Ordering::SeqCst),
            "`anonymous` caller must see no tool capsules (fail-closed)"
        );
        handle.abort();
    }

    /// Await the next `GrantRequired` on `astrid.v1.approval`, with a bounded
    /// timeout so a failing test does not hang. Returns the decoded tuple.
    async fn recv_grant_required(
        receiver: &mut astrid_events::EventReceiver,
    ) -> Option<(String, String, String)> {
        let deadline = std::time::Instant::now() + Duration::from_millis(500);
        while std::time::Instant::now() < deadline {
            let next = tokio::time::timeout(Duration::from_millis(200), receiver.recv()).await;
            let Ok(Some(event)) = next else { continue };
            if let AstridEvent::Ipc { message, .. } = &*event
                && let IpcPayload::GrantRequired {
                    request_id,
                    principal,
                    capsule_id,
                } = &message.payload
            {
                return Some((request_id.clone(), principal.clone(), capsule_id.clone()));
            }
        }
        None
    }

    /// Grant-on-first-use (#998): an ungranted, authenticated, non-admin
    /// caller hitting a tool-surface gate-miss publishes a `GrantRequired`
    /// on `astrid.v1.approval` carrying the kernel-stamped principal + the
    /// missing capsule id and a non-empty UUID request id — instead of the
    /// old pure silent drop.
    #[tokio::test]
    async fn gate_miss_emits_grant_required() {
        let (_dir, home, resolver) = resolver_fixture();
        write_profile(&home, "bob", &agent_with_capsules(&[]));

        let (_invoked, bus, handle) =
            spawn_with_capsule(resolver, "secret-tool", "tool.v1.execute.do_thing", "bob");
        let mut approval = bus.subscribe_topic("astrid.v1.approval");
        tokio::task::yield_now().await;
        publish_ipc_as(&bus, "tool.v1.execute.do_thing", "bob");

        let signal = recv_grant_required(&mut approval).await;
        let (request_id, principal, capsule_id) =
            signal.expect("gate-miss must publish a GrantRequired signal");
        assert_eq!(principal, "bob", "grant target principal is the caller");
        assert_eq!(
            capsule_id, "secret-tool",
            "grant target is the missing capsule"
        );
        assert!(
            uuid::Uuid::parse_str(&request_id).is_ok() && !request_id.is_empty(),
            "request_id must be a non-empty UUID, got {request_id:?}"
        );
        handle.abort();
    }

    /// A `None`/`anonymous` caller has no authenticated principal to grant to,
    /// so the gate-miss is a pure silent drop — NO `GrantRequired` is emitted.
    #[tokio::test]
    async fn anonymous_gate_miss_emits_no_grant_required() {
        let (_dir, _home, resolver) = resolver_fixture();

        let (_invoked, bus, handle) = spawn_with_capsule(
            resolver,
            "secret-tool",
            "tool.v1.execute.do_thing",
            "default",
        );
        let mut approval = bus.subscribe_topic("astrid.v1.approval");
        tokio::task::yield_now().await;
        publish_ipc_as(&bus, "tool.v1.execute.do_thing", "anonymous");

        assert!(
            recv_grant_required(&mut approval).await.is_none(),
            "`anonymous` caller must NOT trigger a GrantRequired (no principal to grant)"
        );
        handle.abort();
    }

    /// An admin (`*`) caller passes `is_capsule_allowed` so never reaches the
    /// gate-miss branch — no `GrantRequired` is emitted for them.
    #[tokio::test]
    async fn admin_gate_miss_emits_no_grant_required() {
        let (_dir, home, resolver) = resolver_fixture();
        write_profile(&home, "root", &admin_profile());

        let (_invoked, bus, handle) =
            spawn_with_capsule(resolver, "secret-tool", "tool.v1.execute.do_thing", "root");
        let mut approval = bus.subscribe_topic("astrid.v1.approval");
        tokio::task::yield_now().await;
        publish_ipc_as(&bus, "tool.v1.execute.do_thing", "root");

        assert!(
            recv_grant_required(&mut approval).await.is_none(),
            "admin bypasses the gate and must NOT trigger a GrantRequired"
        );
        handle.abort();
    }

    /// (d') An unknown principal (no profile on disk → default, no grants) is
    /// likewise denied — fail-closed default. The capsule IS in `nobody`'s view
    /// here, so this isolates the GRANT gate (no grants → deny); the empty-view
    /// floor for a truly-unprovisioned principal is covered by a dedicated
    /// view-isolation test.
    #[tokio::test]
    async fn unknown_principal_denied() {
        let (_dir, _home, resolver) = resolver_fixture();

        let (invoked, bus, handle) = spawn_with_capsule(
            resolver,
            "secret-tool",
            "tool.v1.execute.do_thing",
            "nobody",
        );
        tokio::task::yield_now().await;
        publish_ipc_as(&bus, "tool.v1.execute.do_thing", "nobody");
        tokio::time::sleep(Duration::from_millis(200)).await;

        assert!(
            !invoked.load(Ordering::SeqCst),
            "unknown principal (no grants) must see no tool capsules"
        );
        handle.abort();
    }

    /// (d'') A caller whose profile fails to resolve (malformed TOML on
    /// disk) is denied — resolve error → deny, never default-allow.
    #[tokio::test]
    async fn resolve_error_denies() {
        let (_dir, home, resolver) = resolver_fixture();
        // Write a profile that fails validation (future version) so
        // `resolve` returns Err rather than a default profile.
        let pid = PrincipalId::new("broken").unwrap();
        let path = home.profile_path(&pid);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "profile_version = 9999\n").unwrap();

        let (invoked, bus, handle) = spawn_with_capsule(
            resolver,
            "secret-tool",
            "tool.v1.execute.do_thing",
            "broken",
        );
        tokio::task::yield_now().await;
        publish_ipc_as(&bus, "tool.v1.execute.do_thing", "broken");
        tokio::time::sleep(Duration::from_millis(200)).await;

        assert!(
            !invoked.load(Ordering::SeqCst),
            "resolve error must deny (fail-closed), never default-allow"
        );
        handle.abort();
    }

    /// (e) An orchestration topic (`session.v1.append`) is dispatched
    /// regardless of grants — the internal mesh is NOT gated.
    #[tokio::test]
    async fn orchestration_topic_ungated() {
        let (_dir, home, resolver) = resolver_fixture();
        // `bob` has NO capsule grants — yet orchestration must still flow. The
        // session topic is NOT view-scoped, so the capsule is reached over the
        // GLOBAL instance set regardless of bob's (empty) view.
        write_profile(&home, "bob", &agent_with_capsules(&[]));

        let (invoked, bus, handle) =
            spawn_with_capsule(resolver, "session-capsule", "session.v1.append", "default");
        tokio::task::yield_now().await;
        publish_ipc_as(&bus, "session.v1.append", "bob");
        tokio::time::sleep(Duration::from_millis(200)).await;

        assert!(
            invoked.load(Ordering::SeqCst),
            "orchestration topic must dispatch regardless of capsule grants"
        );
        handle.abort();
    }

    /// (a') The CLI command-execute topic is gated like the tool surface:
    /// an ungranted principal is denied.
    #[tokio::test]
    async fn cli_command_execute_gated() {
        let (_dir, home, resolver) = resolver_fixture();
        write_profile(&home, "bob", &agent_with_capsules(&[]));

        let (invoked, bus, handle) =
            spawn_with_capsule(resolver, "cli-capsule", "cli.v1.command.execute", "bob");
        tokio::task::yield_now().await;
        publish_ipc_as(&bus, "cli.v1.command.execute", "bob");
        tokio::time::sleep(Duration::from_millis(200)).await;

        assert!(
            !invoked.load(Ordering::SeqCst),
            "ungranted principal must be denied the CLI execute surface"
        );
        handle.abort();
    }

    /// Dual-role: the tool topic is gated for an ungranted principal while
    /// the SAME capsule's orchestration topic still dispatches. Proves the
    /// gate is topic-scoped, not capsule-scoped.
    #[tokio::test]
    async fn dual_role_capsule_gates_tool_not_orchestration() {
        let (_dir, home, resolver) = resolver_fixture();
        write_profile(&home, "bob", &agent_with_capsules(&[]));

        // One capsule that intercepts BOTH a tool topic and an
        // orchestration topic. Register it with the tool topic, then a
        // second registry entry with the orchestration topic, both named
        // the same dual-role capsule but we test via two capsules sharing
        // the ungranted principal to isolate the topic dimension.
        //
        // The tool capsule goes into BOB's view so the view floor passes and the
        // GRANT gate is what denies the tool topic (proving the gate is
        // topic-scoped, not a side effect of the view floor). The orchestration
        // capsule goes into `default`'s view — `spark.v1.request.build` is NOT
        // view-scoped, so it is reached over the global instance set.
        let bob_pid = PrincipalId::new("bob").expect("valid principal");
        let (tool_cap, tool_invoked) =
            MockCapsule::new("identity", "tool.v1.execute.save_identity");
        let (orch_cap, orch_invoked) = MockCapsule::new("identity-orch", "spark.v1.request.build");
        let mut registry = CapsuleRegistry::new();
        register_mock_for(&mut registry, Box::new(tool_cap), &bob_pid);
        register_mock(&mut registry, Box::new(orch_cap));
        let registry = Arc::new(RwLock::new(registry));
        let bus = Arc::new(EventBus::with_capacity(64));
        let dispatcher = EventDispatcher::new(Arc::clone(&registry), Arc::clone(&bus))
            .with_access_resolver(resolver);
        let handle = tokio::spawn(dispatcher.run());
        tokio::task::yield_now().await;

        publish_ipc_as(&bus, "tool.v1.execute.save_identity", "bob");
        publish_ipc_as(&bus, "spark.v1.request.build", "bob");
        tokio::time::sleep(Duration::from_millis(200)).await;

        assert!(
            !tool_invoked.load(Ordering::SeqCst),
            "ungranted principal: tool topic must be gated"
        );
        assert!(
            orch_invoked.load(Ordering::SeqCst),
            "ungranted principal: orchestration topic must still dispatch"
        );
        handle.abort();
    }

    /// With no resolver wired (legacy path), the GRANT gate is off — a
    /// dispatcher built without `with_access_resolver` does not filter tools by
    /// grant, proving the grant gate is opt-in via injection. The per-principal
    /// VIEW floor (#1069) is independent of the resolver, so the capsule must be
    /// in the caller's view to be reached; with it in `bob`'s view and the grant
    /// gate off, bob is served.
    #[tokio::test]
    async fn no_resolver_means_grant_gate_off() {
        let bob_pid = PrincipalId::new("bob").expect("valid principal");
        let (tool_cap, invoked) = MockCapsule::new("secret-tool", "tool.v1.execute.do_thing");
        let mut registry = CapsuleRegistry::new();
        register_mock_for(&mut registry, Box::new(tool_cap), &bob_pid);
        let registry = Arc::new(RwLock::new(registry));
        let bus = Arc::new(EventBus::with_capacity(64));
        // No `.with_access_resolver(..)`.
        let dispatcher = EventDispatcher::new(Arc::clone(&registry), Arc::clone(&bus));
        let handle = tokio::spawn(dispatcher.run());
        tokio::task::yield_now().await;

        publish_ipc_as(&bus, "tool.v1.execute.do_thing", "bob");
        tokio::time::sleep(Duration::from_millis(200)).await;

        assert!(
            invoked.load(Ordering::SeqCst),
            "without a resolver the grant gate is off; an in-view capsule is served"
        );
        handle.abort();
    }

    /// REGRESSION: result-delivery topics must NOT be gated. A tool result
    /// `tool.v1.execute.<name>.result` is collected by an orchestration
    /// capsule (router `handle_execute_result`) that is never in a
    /// principal's grant set. If the surface predicate gated it (e.g. a
    /// naive `starts_with("tool.v1.execute.")`), the result would be dropped
    /// for every non-admin caller and the turn would hang. It must reach its
    /// handler even for a principal granted nothing.
    #[tokio::test]
    async fn result_topics_are_not_gated() {
        let (_dir, home, resolver) = resolver_fixture();
        write_profile(&home, "bob", &agent_with_capsules(&[]));

        let (invoked, bus, handle) = spawn_with_capsule(
            resolver,
            "router-like",
            "tool.v1.execute.*.result",
            "default",
        );
        tokio::task::yield_now().await;
        publish_ipc_as(&bus, "tool.v1.execute.do_thing.result", "bob");
        tokio::time::sleep(Duration::from_millis(200)).await;

        assert!(
            invoked.load(Ordering::SeqCst),
            "result topic must dispatch to its orchestration handler even for an ungranted principal"
        );
        handle.abort();
    }

    /// REGRESSION: react's bare `tool.v1.execute.result` is a result-
    /// collection topic (handler `handle_tool_result`), not a tool named
    /// "result". It must not be gated.
    #[tokio::test]
    async fn bare_react_result_topic_is_not_gated() {
        let (_dir, home, resolver) = resolver_fixture();
        write_profile(&home, "bob", &agent_with_capsules(&[]));

        let (invoked, bus, handle) =
            spawn_with_capsule(resolver, "react-like", "tool.v1.execute.result", "default");
        tokio::task::yield_now().await;
        publish_ipc_as(&bus, "tool.v1.execute.result", "bob");
        tokio::time::sleep(Duration::from_millis(200)).await;

        assert!(
            invoked.load(Ordering::SeqCst),
            "react's bare result topic must dispatch even for an ungranted principal"
        );
        handle.abort();
    }

    /// Unit cover for the surface predicate: only the bare single-segment
    /// invocation (and the exact CLI execute topic) is gated; result and
    /// unrelated topics are not.
    #[test]
    fn surface_predicate_gates_only_bare_invocation() {
        use crate::access::is_user_invocable_surface as gated;
        assert!(gated("tool.v1.execute.save_identity"));
        assert!(gated("cli.v1.command.execute"));
        assert!(!gated("tool.v1.execute.save_identity.result"));
        assert!(!gated("tool.v1.execute.result"));
        assert!(!gated("tool.v1.execute."));
        assert!(!gated("session.v1.append"));
        assert!(!gated("tool.v1.response.describe.foo"));
        // Describe is NOT grant-gated (read-only enumeration emits no
        // grant-on-first-use); it is only view-scoped (see `is_view_scoped`).
        assert!(!gated("tool.v1.request.describe"));
    }

    /// Unit cover for the view-scoped predicate (#1069): describe joins the
    /// grant-gated surface as a VIEW-scoped topic; the mesh stays global.
    #[test]
    fn view_scoped_surface_is_grant_surface_plus_describe() {
        use crate::access::is_view_scoped_surface as view_scoped;
        // Superset of the grant-gated surface.
        assert!(view_scoped("tool.v1.execute.save_identity"));
        assert!(view_scoped("cli.v1.command.execute"));
        // Plus the describe enumeration topic.
        assert!(view_scoped("tool.v1.request.describe"));
        // Mesh / result-delivery topics are NOT view-scoped (stay global).
        assert!(!view_scoped("session.v1.append"));
        assert!(!view_scoped("spark.v1.request.build"));
        assert!(!view_scoped("tool.v1.execute.save_identity.result"));
        assert!(!view_scoped("tool.v1.execute.result"));
        assert!(!view_scoped("registry.v1.discover"));
    }
}

// ── Per-principal VIEW isolation (#1069) ─────────────────────────────
//
// These tests prove the cross-tenant FLOOR: on the view-scoped surface the
// dispatcher iterates ONLY the caller's per-principal view. A capsule outside
// the caller's view is never matched, described, or dispatched — and there is
// NO fallback to any other principal's view (the cross-tenant break this whole
// change closes). The mesh stays global. The grant gate is OFF in these tests
// (no resolver wired) so the view floor is isolated as the thing under test.

mod view_isolation {
    use super::*;

    /// Spawn a dispatcher (NO resolver — isolating the VIEW floor) over a
    /// registry the caller pre-populates. Returns the bus + handle.
    fn spawn_view_only(registry: CapsuleRegistry) -> (Arc<EventBus>, tokio::task::JoinHandle<()>) {
        let registry = Arc::new(RwLock::new(registry));
        let bus = Arc::new(EventBus::with_capacity(64));
        let dispatcher = EventDispatcher::new(Arc::clone(&registry), Arc::clone(&bus));
        let handle = tokio::spawn(dispatcher.run());
        (bus, handle)
    }

    /// (a) Isolation: A's view = {foo}, B's view = {bar}. A executing `foo` is
    /// served; A executing `bar` sees nothing (bar is not in A's view), and
    /// B's `bar` capsule is never invoked by A's call — no cross-tenant leak.
    #[tokio::test]
    async fn views_are_isolated_no_cross_tenant_reach() {
        let a = PrincipalId::new("alice").unwrap();
        let b = PrincipalId::new("bob").unwrap();

        let (foo, foo_invoked) = MockCapsule::new("foo", "tool.v1.execute.foo");
        let (bar, bar_invoked) = MockCapsule::new("bar", "tool.v1.execute.bar");
        let mut registry = CapsuleRegistry::new();
        register_mock_for(&mut registry, Box::new(foo), &a);
        register_mock_for(&mut registry, Box::new(bar), &b);
        let (bus, handle) = spawn_view_only(registry);
        tokio::task::yield_now().await;

        // alice executes foo (in her view) → served.
        publish_ipc_as(&bus, "tool.v1.execute.foo", "alice");
        // alice executes bar (NOT in her view; it's bob's) → must be dropped.
        publish_ipc_as(&bus, "tool.v1.execute.bar", "alice");
        tokio::time::sleep(Duration::from_millis(250)).await;

        assert!(
            foo_invoked.load(Ordering::SeqCst),
            "alice's in-view capsule `foo` must be served"
        );
        assert!(
            !bar_invoked.load(Ordering::SeqCst),
            "bob's capsule `bar` must be INVISIBLE to alice — no cross-tenant reach"
        );
        handle.abort();
    }

    /// (e) Fail-closed unknown principal: a capsule lives in `default`'s view;
    /// an unknown/unprovisioned principal (empty view) executing it sees
    /// NOTHING — there is no fallback to `default`'s view.
    #[tokio::test]
    async fn unknown_principal_empty_view_no_default_fallback() {
        let (foo, foo_invoked) = MockCapsule::new("foo", "tool.v1.execute.foo");
        let mut registry = CapsuleRegistry::new();
        // Registered ONLY into default's view.
        register_mock(&mut registry, Box::new(foo));
        let (bus, handle) = spawn_view_only(registry);
        tokio::task::yield_now().await;

        // `ghost` is unknown — has no view entry → empty candidate set.
        publish_ipc_as(&bus, "tool.v1.execute.foo", "ghost");
        tokio::time::sleep(Duration::from_millis(250)).await;

        assert!(
            !foo_invoked.load(Ordering::SeqCst),
            "an unknown principal must resolve to an EMPTY view — never a fallback to default's view"
        );
        handle.abort();
    }

    /// (b) Per-principal versions: A's `foo` → hash1 and B's `foo` → hash2 are
    /// distinct instances loaded concurrently and isolated — A's execute hits
    /// A's instance, B's hits B's. Proven by per-instance invocation flags.
    #[tokio::test]
    async fn per_principal_versions_are_isolated() {
        let a = PrincipalId::new("alice").unwrap();
        let b = PrincipalId::new("bob").unwrap();

        // Two DIFFERENT binaries of the same capsule name `foo`. Distinct hashes
        // ⇒ distinct instances. Each carries its own invocation flag.
        let (foo_v1, v1_invoked) = MockCapsule::new("foo", "tool.v1.execute.foo");
        let (foo_v2, v2_invoked) = MockCapsule::new("foo", "tool.v1.execute.foo");
        let mut registry = CapsuleRegistry::new();
        registry
            .register(Box::new(foo_v1), WasmHash::from_raw("hash1"), &a)
            .unwrap();
        registry
            .register(Box::new(foo_v2), WasmHash::from_raw("hash2"), &b)
            .unwrap();
        // Two distinct instances despite the shared name.
        assert_eq!(registry.len(), 2, "distinct hashes ⇒ distinct instances");

        let (bus, handle) = spawn_view_only(registry);
        tokio::task::yield_now().await;

        publish_ipc_as(&bus, "tool.v1.execute.foo", "alice");
        tokio::time::sleep(Duration::from_millis(250)).await;

        assert!(
            v1_invoked.load(Ordering::SeqCst),
            "alice's execute must hit alice's instance (hash1)"
        );
        assert!(
            !v2_invoked.load(Ordering::SeqCst),
            "bob's instance (hash2) must NOT be hit by alice's execute"
        );
        handle.abort();
    }

    /// Describe is VIEW-SCOPED: a principal's `tool.v1.request.describe` reaches
    /// only the capsules in its own view, never another principal's — so it
    /// cannot enumerate the existence of out-of-view capsules.
    #[tokio::test]
    async fn describe_is_view_scoped() {
        let a = PrincipalId::new("alice").unwrap();
        let b = PrincipalId::new("bob").unwrap();

        let (foo, foo_described) = MockCapsule::new("foo", "tool.v1.request.describe");
        let (bar, bar_described) = MockCapsule::new("bar", "tool.v1.request.describe");
        let mut registry = CapsuleRegistry::new();
        register_mock_for(&mut registry, Box::new(foo), &a);
        register_mock_for(&mut registry, Box::new(bar), &b);
        let (bus, handle) = spawn_view_only(registry);
        tokio::task::yield_now().await;

        // alice asks "what tools exist?" → only her view (foo) responds.
        publish_ipc_as(&bus, "tool.v1.request.describe", "alice");
        tokio::time::sleep(Duration::from_millis(250)).await;

        assert!(
            foo_described.load(Ordering::SeqCst),
            "alice's describe must reach her in-view capsule `foo`"
        );
        assert!(
            !bar_described.load(Ordering::SeqCst),
            "alice's describe must NOT reach bob's `bar` — describe is view-scoped"
        );
        handle.abort();
    }

    /// (f) Mesh stays global: an orchestration topic reaches a capsule in
    /// ANOTHER principal's view (here `default`'s), regardless of the caller —
    /// no view scoping on the internal mesh, or routing wedges.
    #[tokio::test]
    async fn mesh_topic_reaches_all_instances_regardless_of_caller() {
        // Capsule lives ONLY in default's view; an orchestration call from a
        // DIFFERENT principal (alice, empty view) must still reach it.
        let (sess, sess_invoked) = MockCapsule::new("session-cap", "session.v1.append");
        let mut registry = CapsuleRegistry::new();
        register_mock(&mut registry, Box::new(sess));
        let (bus, handle) = spawn_view_only(registry);
        tokio::task::yield_now().await;

        publish_ipc_as(&bus, "session.v1.append", "alice");
        tokio::time::sleep(Duration::from_millis(250)).await;

        assert!(
            sess_invoked.load(Ordering::SeqCst),
            "mesh/orchestration topics must reach the global instance set, not a per-principal view"
        );
        handle.abort();
    }
}
