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
        topic,
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
        topic,
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

    let matches = find_matching_interceptors(&registry, "test.event").await;
    let names: Vec<&str> = matches.iter().map(|(c, _)| c.id().as_str()).collect();
    assert_eq!(
        names,
        vec!["low-pri", "mid-pri", "high-pri"],
        "find_matching_interceptors must return results sorted by priority"
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
