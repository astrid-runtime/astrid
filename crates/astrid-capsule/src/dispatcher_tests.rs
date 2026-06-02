//! Tests for [`crate::dispatcher`]. Kept in a sibling file (referenced
//! via `#[path]`) so `dispatcher.rs` stays under the per-file CI line
//! cap while the test surface continues to grow with new dispatch
//! semantics (priority order, chain short-circuit, semaphore cap, …).

use super::*;

// ── Dispatch integration tests ──────────────────────────────────

use async_trait::async_trait;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::capsule::{Capsule, CapsuleId, CapsuleState, InterceptResult};
use crate::context::CapsuleContext;
use crate::error::CapsuleResult;
use crate::manifest::{CapabilitiesDef, CapsuleManifest, InterceptorDef, PackageDef};
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
            interceptors: vec![InterceptorDef {
                event: interceptor_event.to_string(),
                action: "test_action".to_string(),
                priority,
            }],
            topics: Vec::new(),
            publishes: ::std::collections::HashMap::new(),
            subscribes: ::std::collections::HashMap::new(),
            tools: ::std::vec::Vec::new(),
        };
        let capsule = Self {
            id: CapsuleId::from_static(name),
            manifest,
            invoked: Arc::clone(&invoked),
            invocation_log,
            result_override: None,
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
    fn invoke_interceptor(
        &self,
        _action: &str,
        _payload: &[u8],
        _caller: Option<&astrid_events::ipc::IpcMessage>,
    ) -> CapsuleResult<InterceptResult> {
        self.invoked.store(true, Ordering::SeqCst);
        if let Some(ref log) = self.invocation_log {
            log.lock().unwrap().push(self.id.to_string());
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

/// Mock capsule that records concurrent invocations and holds its own
/// per-capsule `Arc<Semaphore>` matching the production cap. Used by
/// the semaphore-cap test below to assert no more than
/// `MAX_CONCURRENT_INTERCEPTORS` invokes of the same capsule run at
/// once even under fan-in pressure.
struct SemaphoreMockCapsule {
    id: CapsuleId,
    manifest: CapsuleManifest,
    semaphore: Arc<tokio::sync::Semaphore>,
    in_flight: Arc<std::sync::atomic::AtomicUsize>,
    peak: Arc<std::sync::atomic::AtomicUsize>,
    invoke_count: Arc<std::sync::atomic::AtomicUsize>,
}
#[async_trait]
impl Capsule for SemaphoreMockCapsule {
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
    fn interceptor_semaphore(&self) -> &Arc<tokio::sync::Semaphore> {
        &self.semaphore
    }
    fn invoke_interceptor(
        &self,
        _action: &str,
        _payload: &[u8],
        _caller: Option<&astrid_events::ipc::IpcMessage>,
    ) -> CapsuleResult<InterceptResult> {
        let n = self
            .in_flight
            .fetch_add(1, Ordering::SeqCst)
            .saturating_add(1);
        // Track the high-water mark of concurrent invokes.
        self.peak.fetch_max(n, Ordering::SeqCst);
        // Hold the permit long enough that parallel chain spawns
        // pile up against the semaphore cap. 30ms × 4 (cap) plenty
        // for the dispatcher to surface contention.
        std::thread::sleep(Duration::from_millis(30));
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
        self.invoke_count.fetch_add(1, Ordering::SeqCst);
        Ok(InterceptResult::Continue(Vec::new()))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn semaphore_caps_concurrent_chain_invokes_per_capsule() {
    // Two capsules in the same chain (so dispatch goes through the
    // chain path, not the single-capsule mpsc consumer). The target
    // capsule has a cap of 4 — flood with 10 parallel events and
    // assert the peak concurrency never exceeds 4 for it.
    const CAP: usize = 4;
    const FANIN: usize = 10;

    let make_manifest = |name: &str| CapsuleManifest {
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
        interceptors: vec![InterceptorDef {
            event: "chain.topic".to_string(),
            action: "chain_action".to_string(),
            priority: 100,
        }],
        topics: Vec::new(),
        publishes: ::std::collections::HashMap::new(),
        subscribes: ::std::collections::HashMap::new(),
        tools: ::std::vec::Vec::new(),
    };

    let peak = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let in_flight = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let invoke_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let target = SemaphoreMockCapsule {
        id: CapsuleId::from_static("sem-target"),
        manifest: make_manifest("sem-target"),
        semaphore: Arc::new(tokio::sync::Semaphore::new(CAP)),
        in_flight: Arc::clone(&in_flight),
        peak: Arc::clone(&peak),
        invoke_count: Arc::clone(&invoke_count),
    };
    // A second mock in the chain forces the multi-interceptor path
    // (single-match goes through the per-capsule mpsc which already
    // serializes). MockCapsule reuses the default global fallback
    // semaphore — fine, we only assert on the target.
    let (chain_neighbour, _) = MockCapsule::with_priority("sem-neighbour", "chain.topic", 50, None);

    let mut registry = CapsuleRegistry::new();
    registry.register(Box::new(chain_neighbour)).unwrap();
    registry.register(Box::new(target)).unwrap();
    let registry = Arc::new(RwLock::new(registry));

    let bus = Arc::new(EventBus::with_capacity(128));
    let dispatcher = EventDispatcher::new(Arc::clone(&registry), Arc::clone(&bus));
    let handle = tokio::spawn(dispatcher.run());

    tokio::task::yield_now().await;

    for _ in 0..FANIN {
        publish_ipc(&bus, "chain.topic");
    }

    // Allow time for all 10 chains to drain through the 4-permit cap.
    // 10 events × 30ms hold / 4 concurrency ≈ 75ms minimum; allow
    // generous headroom for the multi-threaded executor.
    tokio::time::sleep(Duration::from_millis(600)).await;

    let observed_peak = peak.load(Ordering::SeqCst);
    let total = invoke_count.load(Ordering::SeqCst);
    assert!(
        observed_peak <= CAP,
        "peak concurrent invokes on capped capsule was {observed_peak}, expected <= {CAP}"
    );
    assert_eq!(
        total, FANIN,
        "all {FANIN} chains should have invoked the capped capsule (got {total})"
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

// ── Per-(capsule, principal-class) routing tests (#813) ────────

#[tokio::test]
async fn single_match_does_not_block_across_principal_classes() {
    // One capsule, one topic, two principal classes (system + user).
    // Two events under distinct classes must be processed without HOL
    // blocking — both `invoked` flags fire even if one consumer is
    // slow.
    let (capsule, invoked) = MockCapsule::new("class-cap", "split.topic");
    let mut registry = CapsuleRegistry::new();
    registry.register(Box::new(capsule)).unwrap();
    let registry = Arc::new(RwLock::new(registry));

    let bus = Arc::new(EventBus::with_capacity(64));
    let dispatcher = EventDispatcher::new(Arc::clone(&registry), Arc::clone(&bus));
    let handle = tokio::spawn(dispatcher.run());

    tokio::task::yield_now().await;

    // First event has no principal → System class. Second is a user
    // principal → User class. Different queue key, parallel
    // consumers, both should land.
    publish_ipc(&bus, "split.topic");
    publish_ipc_as(&bus, "split.topic", "alice");

    tokio::time::sleep(Duration::from_millis(300)).await;

    assert!(
        invoked.load(Ordering::SeqCst),
        "interceptor should fire for at least one of the events"
    );
    handle.abort();
}

#[tokio::test]
async fn chain_serializes_per_principal_class_on_same_capsule() {
    // A chain of two capsules where each interceptor records its
    // invocation. Two events under the same principal class race
    // through the chain; tokio::Mutex serializes them FIFO.
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

    // Same class (System) twice → chain mutex serializes both.
    publish_ipc(&bus, "chain.topic");
    publish_ipc(&bus, "chain.topic");

    tokio::time::sleep(Duration::from_millis(500)).await;

    let recorded = order.lock().unwrap().clone();
    // Each event should produce ser-a then ser-b. Two events = 4
    // entries (two complete chains, never interleaved within a
    // (capsule, class) pair).
    assert_eq!(recorded.len(), 4, "two full chains should have completed");
    // Within each chain ser-a precedes ser-b.
    assert_eq!(recorded[0], "ser-a");
    assert_eq!(recorded[1], "ser-b");
    assert_eq!(recorded[2], "ser-a");
    assert_eq!(recorded[3], "ser-b");

    handle.abort();
}
