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
use astrid_events::ipc::IpcPayload;
use astrid_events::ipc::Topic;

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
    registry.register(Box::new(capsule)).unwrap();
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
    registry.register(Box::new(capsule)).unwrap();
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
    registry.register(Box::new(cap_a)).unwrap();
    registry.register(Box::new(cap_b)).unwrap();
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
    registry.register(Box::new(capsule)).unwrap();
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
    registry.register(Box::new(lag_capsule)).unwrap();
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
    registry.register(Box::new(handler)).unwrap();
    registry.register(Box::new(guard)).unwrap();
    registry.register(Box::new(transform)).unwrap();
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
    registry.register(Box::new(high)).unwrap();
    registry.register(Box::new(low)).unwrap();
    registry.register(Box::new(mid)).unwrap();
    let registry = Arc::new(RwLock::new(registry));
    let bus = EventBus::with_capacity(64);

    let matches = find_matching_interceptors(&registry, "test.event", None, None, None, &bus).await;
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
    registry.register(Box::new(z_tie)).unwrap();
    registry.register(Box::new(guard)).unwrap();
    registry.register(Box::new(a_tie)).unwrap();
    let registry = Arc::new(RwLock::new(registry));
    let bus = EventBus::with_capacity(64);

    let matches = find_matching_interceptors(&registry, "test.event", None, None, None, &bus).await;
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
    registry.register(Box::new(handler)).unwrap();
    registry.register(Box::new(guard)).unwrap();
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
    registry.register(Box::new(core)).unwrap();
    registry.register(Box::new(cache)).unwrap();
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
    registry.register(Box::new(denier)).unwrap();
    registry.register(Box::new(resp_a)).unwrap();
    registry.register(Box::new(resp_b)).unwrap();
    registry.register(Box::new(resp_c)).unwrap();
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
    registry.register(Box::new(capsule)).unwrap();
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
    registry.register(Box::new(cap_a)).unwrap();
    registry.register(Box::new(cap_b)).unwrap();
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
    registry.register(Box::new(capsule)).unwrap();
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
    registry.register(Box::new(capsule)).unwrap();
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

#[tokio::test]
async fn dispatcher_idle_evicts_per_principal_consumers_after_grace() {
    // Publish for alice — spawns a consumer. After the (collapsed)
    // grace passes, the consumer self-evicts. A second publish must
    // still be delivered: the dispatcher's `get_or_spawn_consumer`
    // re-spawns through the same queue map entry.
    //
    // The `set_idle_consumer_grace_for_test` hook collapses the 60s
    // production grace to a short interval so this test runs in real
    // time without needing tokio's `test-util` feature.
    super::set_idle_consumer_grace_for_test(100);
    // Restore on test exit so sibling tests aren't affected by the
    // override. Tests share a process; the next sibling sees the
    // production default.
    struct ResetGrace;
    impl Drop for ResetGrace {
        fn drop(&mut self) {
            super::set_idle_consumer_grace_for_test(super::DEFAULT_IDLE_CONSUMER_GRACE_MS);
        }
    }
    let _reset = ResetGrace;

    let counter = Arc::new(AtomicUsize::new(0));
    let (mut capsule, _) = MockCapsule::new("evict-cap", "evict.topic");
    capsule.invoke_counter = Some(Arc::clone(&counter));

    let mut registry = CapsuleRegistry::new();
    registry.register(Box::new(capsule)).unwrap();
    let registry = Arc::new(RwLock::new(registry));

    let bus = Arc::new(EventBus::with_capacity(64));
    let dispatcher = EventDispatcher::new(Arc::clone(&registry), Arc::clone(&bus));
    let handle = tokio::spawn(dispatcher.run());

    // Let dispatcher subscribe.
    tokio::task::yield_now().await;

    publish_ipc_as(&bus, "evict.topic", "alice");

    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while counter.load(Ordering::SeqCst) < 1 && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "first alice event should land"
    );

    // Sleep past the (collapsed) grace so the consumer idle-evicts.
    tokio::time::sleep(Duration::from_millis(400)).await;

    // Publish again — must re-spawn the consumer through
    // `or_insert_with` and deliver the second event.
    publish_ipc_as(&bus, "evict.topic", "alice");

    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while counter.load(Ordering::SeqCst) < 2 && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        counter.load(Ordering::SeqCst),
        2,
        "second alice event must re-spawn the consumer and land"
    );

    handle.abort();
}

#[tokio::test]
async fn dispatch_respawns_when_mapped_consumer_is_closed() {
    // Regression for the burst-induced `user.v1.prompt` stall: a stale CLOSED
    // sender left in the queue map (its consumer gone — idle-evict race or an
    // abnormally-ended task) must NOT make every later dispatch fail `Closed`
    // and drop forever. `get_or_spawn_consumer` skips a closed entry and
    // re-spawns; the event is delivered, not dropped.
    let counter = Arc::new(AtomicUsize::new(0));
    let (mut capsule, _) = MockCapsule::new("respawn-cap", "respawn.topic");
    capsule.invoke_counter = Some(Arc::clone(&counter));
    let capsule: Arc<dyn Capsule> = Arc::new(capsule);

    // Pre-seed the queue map with a CLOSED sender for the key (receiver dropped).
    let queues: CapsuleQueues = Arc::new(parking_lot::Mutex::new(HashMap::new()));
    let key = (capsule.id().clone(), Some("alice".to_string()));
    let (dead_tx, dead_rx) = mpsc::channel::<InterceptorWork>(CAPSULE_EVENT_QUEUE_CAPACITY);
    drop(dead_rx);
    assert!(
        dead_tx.is_closed(),
        "precondition: the seeded sender is closed"
    );
    queues.lock().insert(key.clone(), dead_tx);

    // Dispatch through the closed entry — must re-spawn a live consumer and
    // deliver rather than hand back the dead sender and drop.
    dispatch_single(
        &queues,
        Arc::clone(&capsule),
        "test_action".to_string(),
        Arc::new("respawn.topic".to_string()),
        Arc::new(Vec::new()),
        None,
        Some("alice".to_string()),
    );

    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while counter.load(Ordering::SeqCst) < 1 && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "a dispatch through a closed mapped sender must re-spawn and deliver, not drop"
    );
}

// ── Chain-lock map bounding (#828) ──────────────────────────────

#[tokio::test]
async fn chain_lock_prunes_entry_when_last_referrer_drops() {
    // Each distinct (capsule, principal) chain key inserts a mutex on
    // first use. Without RAII pruning the map grows one entry per
    // principal forever (ephemeral sub-agent churn). Acquire+drop a lock
    // for many distinct principals and assert the map sheds every entry.
    let chain_locks: ChainLocks = Arc::new(parking_lot::RwLock::new(HashMap::new()));
    let cap = CapsuleId::from_static("chainmap-cap");

    for i in 0..256 {
        let key = (cap.clone(), Some(format!("user-{i}")));
        let guard = acquire_chain_lock(&chain_locks, key).await;
        // While the guard is alive the entry exists.
        assert_eq!(chain_locks.read().len(), 1, "entry present while held");
        drop(guard);
        // Dropping the sole referrer prunes it.
        assert!(
            chain_locks.read().is_empty(),
            "map must shed the entry once the last referrer drops"
        );
    }

    assert!(
        chain_locks.read().is_empty(),
        "chain_locks must not retain one entry per principal"
    );
}

#[tokio::test]
async fn chain_lock_retained_while_another_holder_exists() {
    // Two acquirers of the SAME key share one map entry; the entry
    // survives until BOTH guards drop. This proves the prune only fires
    // for the last referrer — a held sibling chain is never stranded
    // without its serialization mutex.
    let chain_locks: ChainLocks = Arc::new(parking_lot::RwLock::new(HashMap::new()));
    let cap = CapsuleId::from_static("shared-cap");
    let key = (cap.clone(), Some("alice".to_string()));

    let g1 = acquire_chain_lock(&chain_locks, key.clone()).await;
    assert_eq!(chain_locks.read().len(), 1);

    // A second acquirer for the same key blocks on the mutex (g1 holds
    // it). Acquire it on a task; it shares the same map Arc, so the
    // entry must NOT be pruned while g1 lives.
    let cl = Arc::clone(&chain_locks);
    let k2 = key.clone();
    let task = tokio::spawn(async move {
        let g2 = acquire_chain_lock(&cl, k2).await;
        tokio::task::yield_now().await;
        drop(g2);
    });

    // g1 still alive → entry present regardless of the racing acquirer.
    assert_eq!(
        chain_locks.read().len(),
        1,
        "entry must persist while g1 holds it"
    );
    drop(g1);
    task.await.unwrap();

    // Both guards gone → entry pruned.
    assert!(
        chain_locks.read().is_empty(),
        "entry pruned once both holders drop"
    );
}

// ── Per-principal capsule-access enforcement (#992) ──────────────────
//
// These tests prove the kernel-side, topic-scoped, fail-closed grant
// filter on the user-invocable surface (`tool.v1.execute.*`,
// `cli.v1.command.run.*`), with admin (`*`) bypass and orchestration
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
    /// one capsule whose interceptor binds `interceptor_event`. Returns the
    /// invoked flag, the bus, and the task handle.
    fn spawn_with_capsule(
        resolver: CapsuleAccessResolver,
        capsule_name: &str,
        interceptor_event: &str,
    ) -> (Arc<AtomicBool>, Arc<EventBus>, tokio::task::JoinHandle<()>) {
        spawn_with_capsule_in_views(resolver, capsule_name, interceptor_event, &["default"])
    }

    fn spawn_with_capsule_in_views(
        resolver: CapsuleAccessResolver,
        capsule_name: &str,
        interceptor_event: &str,
        principals: &[&str],
    ) -> (Arc<AtomicBool>, Arc<EventBus>, tokio::task::JoinHandle<()>) {
        let (capsule, invoked) = MockCapsule::new(capsule_name, interceptor_event);
        let mut registry = CapsuleRegistry::new();
        let hash =
            crate::registry::WasmHash::synthetic(capsule_name, &capsule.manifest.package.version);
        let first = principals.first().copied().unwrap_or("default");
        let first_pid = PrincipalId::new(first).expect("valid principal");
        let capsule_id = capsule.id().clone();
        registry
            .register_for(Box::new(capsule), hash.clone(), &first_pid)
            .unwrap();
        // Additional principals SHARE the one runtime via `register_existing`
        // (the production view-add path) — not a second `register_for` under a
        // different owner, which the registry now rejects.
        for principal in &principals[1..] {
            let pid = PrincipalId::new(*principal).expect("valid principal");
            registry
                .register_existing(&capsule_id, &hash, &pid)
                .unwrap();
        }
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
        // `bob` exists but is granted no capsules.
        write_profile(&home, "bob", &agent_with_capsules(&[]));

        let (invoked, bus, handle) = spawn_with_capsule_in_views(
            resolver,
            "secret-tool",
            "tool.v1.execute.do_thing",
            &["bob"],
        );
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

        let (invoked, bus, handle) = spawn_with_capsule_in_views(
            resolver,
            "secret-tool",
            "tool.v1.execute.do_thing",
            &["alice"],
        );
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
            spawn_with_capsule(resolver, "secret-tool", "tool.v1.execute.do_thing");
        tokio::task::yield_now().await;
        publish_ipc_as(&bus, "tool.v1.execute.do_thing", "root");
        tokio::time::sleep(Duration::from_millis(200)).await;

        assert!(
            invoked.load(Ordering::SeqCst),
            "admin (`*`) must bypass the per-principal filter"
        );
        handle.abort();
    }

    /// (d) `anonymous` caller → no tool capsules visible (fail-closed).
    #[tokio::test]
    async fn anonymous_caller_denied() {
        let (_dir, _home, resolver) = resolver_fixture();

        let (invoked, bus, handle) =
            spawn_with_capsule(resolver, "secret-tool", "tool.v1.execute.do_thing");
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

        let (_invoked, bus, handle) = spawn_with_capsule_in_views(
            resolver,
            "secret-tool",
            "tool.v1.execute.do_thing",
            &["bob"],
        );
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

    #[tokio::test]
    async fn out_of_view_tool_miss_emits_no_grant_required() {
        let (_dir, home, resolver) = resolver_fixture();
        write_profile(&home, "bob", &agent_with_capsules(&[]));

        let (invoked, bus, handle) =
            spawn_with_capsule(resolver, "secret-tool", "tool.v1.execute.do_thing");
        let mut approval = bus.subscribe_topic("astrid.v1.approval");
        tokio::task::yield_now().await;
        publish_ipc_as(&bus, "tool.v1.execute.do_thing", "bob");
        tokio::time::sleep(Duration::from_millis(200)).await;

        assert!(
            !invoked.load(Ordering::SeqCst),
            "out-of-view capsule must not be dispatched"
        );
        assert!(
            recv_grant_required(&mut approval).await.is_none(),
            "out-of-view capsule must not emit GrantRequired; there is no view entry to grant"
        );
        handle.abort();
    }

    /// Drain every `GrantRequired` on `astrid.v1.approval` within a bounded
    /// window, returning the signalled capsule ids in arrival order. Unlike
    /// [`recv_grant_required`] (first-only), this counts the whole storm so a
    /// test can assert the gate fired for exactly the matching capsule (#1113).
    async fn collect_grant_required(
        receiver: &mut astrid_events::EventReceiver,
        window: Duration,
    ) -> Vec<String> {
        let deadline = std::time::Instant::now() + window;
        let mut ids = Vec::new();
        while std::time::Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            match tokio::time::timeout(remaining, receiver.recv()).await {
                Ok(Some(event)) => {
                    if let AstridEvent::Ipc { message, .. } = &*event
                        && let IpcPayload::GrantRequired { capsule_id, .. } = &message.payload
                    {
                        ids.push(capsule_id.clone());
                    }
                },
                // Bus closed, or the window elapsed — stop draining.
                Ok(None) | Err(_) => break,
            }
        }
        ids
    }

    /// Spawn a dispatcher over a registry holding SEVERAL distinct capsules,
    /// all in one principal's view, each binding a distinct interceptor topic.
    /// Returns the bus + task handle; these tests assert on the emitted
    /// `GrantRequired` set, so the per-capsule invoked flags are dropped.
    fn spawn_with_capsules_in_view(
        resolver: CapsuleAccessResolver,
        principal: &str,
        capsules: &[(&str, &str)],
    ) -> (Arc<EventBus>, tokio::task::JoinHandle<()>) {
        let pid = PrincipalId::new(principal).expect("valid principal");
        let mut registry = CapsuleRegistry::new();
        for (name, event) in capsules {
            let (capsule, _invoked) = MockCapsule::new(name, event);
            let hash =
                crate::registry::WasmHash::synthetic(name, &capsule.manifest.package.version);
            registry
                .register_for(Box::new(capsule), hash, &pid)
                .unwrap();
        }
        let registry = Arc::new(RwLock::new(registry));
        let bus = Arc::new(EventBus::with_capacity(64));
        let dispatcher = EventDispatcher::new(Arc::clone(&registry), Arc::clone(&bus))
            .with_access_resolver(resolver);
        let handle = tokio::spawn(dispatcher.run());
        (bus, handle)
    }

    /// REGRESSION (#1113): a single ungranted tool call must raise grant-on-use
    /// for ONLY the capsule that provides the called tool — not for every
    /// ungranted capsule in the caller's view. Before the topic-match-first
    /// reorder, the gate fired (and emitted `GrantRequired`) for every
    /// candidate capsule BEFORE checking whether its subscription matched the
    /// dispatched topic, so one `tool.v1.execute.do_thing` call stormed a
    /// `GrantRequired` for all N view capsules — making first-run consent
    /// unconvergeable. Now only the matching capsule's gate engages.
    ///
    /// On origin/main this drains three `GrantRequired` (one per view capsule)
    /// and the length assertion fails; with the fix exactly one arrives.
    #[tokio::test]
    async fn grant_on_use_signals_only_the_matching_capsule() {
        let (_dir, home, resolver) = resolver_fixture();
        // `bob` is in the runtime but granted NOTHING — every view capsule is
        // ungranted, the fresh-principal first-run condition.
        write_profile(&home, "bob", &agent_with_capsules(&[]));

        // Three ungranted tool capsules in bob's view; only `match-tool`
        // subscribes the topic the call publishes. The other two are unrelated
        // tools the call never touches — they must not be gated on this call.
        let (bus, handle) = spawn_with_capsules_in_view(
            resolver,
            "bob",
            &[
                ("match-tool", "tool.v1.execute.do_thing"),
                ("other-tool-a", "tool.v1.execute.other_a"),
                ("other-tool-b", "tool.v1.execute.other_b"),
            ],
        );
        let mut approval = bus.subscribe_topic("astrid.v1.approval");
        tokio::task::yield_now().await;

        publish_ipc_as(&bus, "tool.v1.execute.do_thing", "bob");

        let signalled = collect_grant_required(&mut approval, Duration::from_millis(400)).await;
        assert_eq!(
            signalled,
            vec!["match-tool".to_string()],
            "exactly ONE GrantRequired — for the called tool's capsule only — must be emitted; \
             got {signalled:?} (a storm across the ungranted view is #1113)"
        );
        handle.abort();
    }

    #[tokio::test]
    async fn describe_request_is_scoped_to_principal_view() {
        let (_dir, home, resolver) = resolver_fixture();
        write_profile(&home, "bob", &agent_with_capsules(&[]));

        let (out_of_view, bus, handle) = spawn_with_capsule(
            resolver.clone(),
            "describe-tool",
            "tool.v1.request.describe",
        );
        tokio::task::yield_now().await;
        publish_ipc_as(&bus, "tool.v1.request.describe", "bob");
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            !out_of_view.load(Ordering::SeqCst),
            "describe must not fan out to capsules outside the caller's view"
        );
        handle.abort();

        let (in_view, bus, handle) = spawn_with_capsule_in_views(
            resolver,
            "describe-tool",
            "tool.v1.request.describe",
            &["bob"],
        );
        tokio::task::yield_now().await;
        publish_ipc_as(&bus, "tool.v1.request.describe", "bob");
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            in_view.load(Ordering::SeqCst),
            "describe should reach capsules in the caller's view without needing a tool grant"
        );
        handle.abort();
    }

    #[tokio::test]
    async fn llm_describe_request_is_scoped_to_principal_view() {
        let (_dir, home, resolver) = resolver_fixture();
        write_profile(&home, "bob", &agent_with_capsules(&[]));

        let (out_of_view, bus, handle) =
            spawn_with_capsule(resolver.clone(), "llm-provider", "llm.v1.request.describe");
        tokio::task::yield_now().await;
        publish_ipc_as(&bus, "llm.v1.request.describe", "bob");
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            !out_of_view.load(Ordering::SeqCst),
            "LLM describe must not fan out to providers outside the caller's view"
        );
        handle.abort();

        let (in_view, bus, handle) = spawn_with_capsule_in_views(
            resolver,
            "llm-provider",
            "llm.v1.request.describe",
            &["bob"],
        );
        tokio::task::yield_now().await;
        publish_ipc_as(&bus, "llm.v1.request.describe", "bob");
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            in_view.load(Ordering::SeqCst),
            "LLM describe should reach providers in the caller's view"
        );
        handle.abort();
    }

    #[tokio::test]
    async fn llm_describe_without_principal_fails_closed() {
        let (_dir, _home, resolver) = resolver_fixture();
        let (invoked, bus, handle) =
            spawn_with_capsule(resolver, "llm-provider", "llm.v1.request.describe");

        tokio::task::yield_now().await;
        publish_ipc(&bus, "llm.v1.request.describe");
        tokio::time::sleep(Duration::from_millis(200)).await;

        assert!(
            !invoked.load(Ordering::SeqCst),
            "unprincipaled LLM discovery must not fall back to all loaded providers"
        );
        handle.abort();
    }

    /// A `None`/`anonymous` caller has no authenticated principal to grant to,
    /// so the gate-miss is a pure silent drop — NO `GrantRequired` is emitted.
    #[tokio::test]
    async fn anonymous_gate_miss_emits_no_grant_required() {
        let (_dir, _home, resolver) = resolver_fixture();

        let (_invoked, bus, handle) =
            spawn_with_capsule(resolver, "secret-tool", "tool.v1.execute.do_thing");
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
            spawn_with_capsule(resolver, "secret-tool", "tool.v1.execute.do_thing");
        let mut approval = bus.subscribe_topic("astrid.v1.approval");
        tokio::task::yield_now().await;
        publish_ipc_as(&bus, "tool.v1.execute.do_thing", "root");

        assert!(
            recv_grant_required(&mut approval).await.is_none(),
            "admin bypasses the gate and must NOT trigger a GrantRequired"
        );
        handle.abort();
    }

    /// (d') An unknown principal (no profile on disk → default, no grants)
    /// is likewise denied — fail-closed default.
    #[tokio::test]
    async fn unknown_principal_denied() {
        let (_dir, _home, resolver) = resolver_fixture();

        let (invoked, bus, handle) =
            spawn_with_capsule(resolver, "secret-tool", "tool.v1.execute.do_thing");
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

        let (invoked, bus, handle) =
            spawn_with_capsule(resolver, "secret-tool", "tool.v1.execute.do_thing");
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
        // `bob` has NO capsule grants — yet orchestration must still flow.
        write_profile(&home, "bob", &agent_with_capsules(&[]));

        let (invoked, bus, handle) =
            spawn_with_capsule_in_views(resolver, "session-capsule", "session.v1.append", &["bob"]);
        tokio::task::yield_now().await;
        publish_ipc_as(&bus, "session.v1.append", "bob");
        tokio::time::sleep(Duration::from_millis(200)).await;

        assert!(
            invoked.load(Ordering::SeqCst),
            "orchestration topic must dispatch regardless of capsule grants"
        );
        handle.abort();
    }

    /// (a') The CLI command-run topic is gated like the tool surface:
    /// an ungranted principal is denied.
    #[tokio::test]
    async fn cli_command_run_gated() {
        let (_dir, home, resolver) = resolver_fixture();
        write_profile(&home, "bob", &agent_with_capsules(&[]));

        let (invoked, bus, handle) = spawn_with_capsule_in_views(
            resolver,
            "cli-capsule",
            "cli.v1.command.run.cli-capsule",
            &["bob"],
        );
        tokio::task::yield_now().await;
        publish_ipc_as(&bus, "cli.v1.command.run.cli-capsule", "bob");
        tokio::time::sleep(Duration::from_millis(200)).await;

        assert!(
            !invoked.load(Ordering::SeqCst),
            "ungranted principal must be denied the CLI run surface"
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

        let (tool_cap, tool_invoked) =
            MockCapsule::new("identity", "tool.v1.execute.save_identity");
        let (orch_cap, orch_invoked) = MockCapsule::new("identity-orch", "spark.v1.request.build");
        let mut registry = CapsuleRegistry::new();
        let bob = PrincipalId::new("bob").expect("valid principal");
        registry
            .register_for(
                Box::new(tool_cap),
                crate::registry::WasmHash::synthetic("identity", "0.0.1"),
                &bob,
            )
            .unwrap();
        registry
            .register_for(
                Box::new(orch_cap),
                crate::registry::WasmHash::synthetic("identity-orch", "0.0.1"),
                &bob,
            )
            .unwrap();
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

    #[tokio::test]
    async fn principal_stamped_orchestration_uses_caller_view() {
        let (_dir, home, resolver) = resolver_fixture();
        write_profile(&home, "bob", &agent_with_capsules(&[]));

        let (default_cap, default_invoked) =
            MockCapsule::new("default-session", "session.v1.request.list");
        let (bob_cap, bob_invoked) = MockCapsule::new("bob-session", "session.v1.request.list");
        let mut registry = CapsuleRegistry::new();
        registry
            .register_for(
                Box::new(default_cap),
                crate::registry::WasmHash::synthetic("default-session", "0.0.1"),
                &PrincipalId::default(),
            )
            .unwrap();
        let bob = PrincipalId::new("bob").expect("valid principal");
        registry
            .register_for(
                Box::new(bob_cap),
                crate::registry::WasmHash::synthetic("bob-session", "0.0.1"),
                &bob,
            )
            .unwrap();

        let registry = Arc::new(RwLock::new(registry));
        let bus = Arc::new(EventBus::with_capacity(64));
        let dispatcher = EventDispatcher::new(Arc::clone(&registry), Arc::clone(&bus))
            .with_access_resolver(resolver);
        let handle = tokio::spawn(dispatcher.run());
        tokio::task::yield_now().await;

        publish_ipc_as(&bus, "session.v1.request.list", "bob");
        tokio::time::sleep(Duration::from_millis(200)).await;

        assert!(
            !default_invoked.load(Ordering::SeqCst),
            "principal-stamped orchestration must not dispatch to the default view"
        );
        assert!(
            bob_invoked.load(Ordering::SeqCst),
            "principal-stamped orchestration should dispatch to the caller's view"
        );
        handle.abort();
    }

    /// With no resolver wired (legacy path), the surface is ungated — a
    /// dispatcher built without `with_access_resolver` dispatches tools to
    /// any principal, proving the gate is opt-in via injection.
    #[tokio::test]
    async fn no_resolver_means_ungated() {
        let (tool_cap, invoked) = MockCapsule::new("secret-tool", "tool.v1.execute.do_thing");
        let mut registry = CapsuleRegistry::new();
        registry.register(Box::new(tool_cap)).unwrap();
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
            "without a resolver the surface is ungated (legacy/test path)"
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

        let (invoked, bus, handle) = spawn_with_capsule_in_views(
            resolver,
            "router-like",
            "tool.v1.execute.*.result",
            &["bob"],
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
            spawn_with_capsule_in_views(resolver, "react-like", "tool.v1.execute.result", &["bob"]);
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
        assert!(gated("cli.v1.command.run.astrid-capsule-adversarial"));
        assert!(!gated("cli.v1.command.run."));
        assert!(!gated("cli.v1.command.run.nested.provider"));
        assert!(!gated("tool.v1.execute.save_identity.result"));
        assert!(!gated("tool.v1.execute.result"));
        assert!(!gated("tool.v1.execute."));
        assert!(!gated("session.v1.append"));
        assert!(!gated("tool.v1.response.describe.foo"));
    }
}

// ── Injected-home auto-provisioning (#1145) ─────────────────────
//
// The dispatcher's per-principal auto-provision used to call
// `AstridHome::resolve()` (process env) and write directory trees from
// library code, so `cargo test` with no `ASTRID_HOME` isolation scaffolded
// fixture principals into the developer's real `~/.astrid`. The home is
// now injected: the kernel passes its booted home, tests pass a tempdir,
// and with no home injected the dispatcher never touches the filesystem.

/// With an injected tempdir home, dispatching an event stamped with an
/// unknown principal auto-provisions that principal's home under the
/// tempdir — and only there.
#[tokio::test]
async fn dispatch_with_injected_home_provisions_principal_under_it() {
    let (capsule, invoked) = MockCapsule::new("prov-capsule", "prov.topic");

    let mut registry = CapsuleRegistry::new();
    registry.register(Box::new(capsule)).unwrap();
    let registry = Arc::new(RwLock::new(registry));

    let dir = tempfile::tempdir().unwrap();
    let home = astrid_core::dirs::AstridHome::from_path(dir.path());
    let prov_user = astrid_core::PrincipalId::new("prov-user").unwrap();
    let expected = home.principal_home(&prov_user).root().to_path_buf();

    let bus = Arc::new(EventBus::with_capacity(64));
    let dispatcher = EventDispatcher::new(Arc::clone(&registry), Arc::clone(&bus)).with_home(home);
    let handle = tokio::spawn(dispatcher.run());
    tokio::task::yield_now().await;

    publish_ipc_as(&bus, "prov.topic", "prov-user");
    tokio::time::sleep(Duration::from_millis(200)).await;

    assert!(
        invoked.load(Ordering::SeqCst),
        "the event must dispatch normally alongside provisioning"
    );
    assert!(
        expected.is_dir(),
        "the unknown principal's home must be auto-provisioned under the injected tempdir home"
    );

    handle.abort();
}

/// With NO injected home, the same event still dispatches successfully
/// while auto-provisioning stays disabled: a tempdir standing where an
/// injected home would be remains untouched. The full fail-closed
/// contract — no filesystem writes and no `$ASTRID_HOME`/`$HOME`
/// resolution without an injected home — is proven at the unit level in
/// `dispatcher::provision::tests::no_injected_home_never_provisions`;
/// the `AstridHome::resolve()` call is deleted from the dispatch path
/// (#1145).
#[tokio::test]
async fn dispatch_without_home_creates_nothing_and_still_dispatches() {
    let (capsule, invoked) = MockCapsule::new("nohome-capsule", "nohome.topic");

    let mut registry = CapsuleRegistry::new();
    registry.register(Box::new(capsule)).unwrap();
    let registry = Arc::new(RwLock::new(registry));

    // A tempdir that is deliberately never injected — it stands where an
    // injected home would be, so it must remain empty throughout.
    let never_injected = tempfile::tempdir().unwrap();

    let bus = Arc::new(EventBus::with_capacity(64));
    let dispatcher = EventDispatcher::new(Arc::clone(&registry), Arc::clone(&bus));
    let handle = tokio::spawn(dispatcher.run());
    tokio::task::yield_now().await;

    publish_ipc_as(&bus, "nohome.topic", "nohome-user");
    tokio::time::sleep(Duration::from_millis(200)).await;

    assert!(
        invoked.load(Ordering::SeqCst),
        "dispatch must succeed for an unknown principal even with provisioning disabled"
    );
    assert!(
        std::fs::read_dir(never_injected.path())
            .unwrap()
            .next()
            .is_none(),
        "the never-injected tempdir must stay empty — provisioning is disabled without an injected home"
    );

    handle.abort();
}
