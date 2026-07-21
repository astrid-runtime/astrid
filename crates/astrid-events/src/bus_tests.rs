//! Tests for `crate::bus`. Kept in a sibling file (referenced via
//! `#[path]`) so `bus.rs` stays under the per-file CI line cap after
//! the per-(capsule, topic, principal) routing additions (#813).

use super::*;
use crate::event::EventMetadata;
use crate::ipc::Topic;

#[tokio::test]
async fn test_event_bus_creation() {
    let bus = EventBus::new();
    assert_eq!(bus.capacity(), DEFAULT_CHANNEL_CAPACITY);
    assert_eq!(bus.subscriber_count(), 0);
}

#[tokio::test]
async fn test_event_bus_with_capacity() {
    let bus = EventBus::with_capacity(100);
    assert_eq!(bus.capacity(), 100);
}

#[tokio::test]
async fn test_publish_and_receive() {
    let bus = EventBus::new();
    let mut receiver = bus.subscribe();

    let event = AstridEvent::RuntimeStarted {
        metadata: EventMetadata::new("test"),
        version: "0.1.0".to_string(),
    };

    let count = bus.publish(event);
    assert_eq!(count, 1);

    let msg = receiver.recv().await.unwrap();
    assert_eq!(msg.event_type(), "astrid.v1.lifecycle.runtime_started");
}

#[tokio::test]
async fn test_multiple_subscribers() {
    let bus = EventBus::new();
    let mut receiver1 = bus.subscribe();
    let mut receiver2 = bus.subscribe();

    let event = AstridEvent::RuntimeStarted {
        metadata: EventMetadata::new("test"),
        version: "0.1.0".to_string(),
    };

    let count = bus.publish(event);
    assert_eq!(count, 2);

    let obj1 = receiver1.recv().await.unwrap();
    let obj2 = receiver2.recv().await.unwrap();

    assert_eq!(obj1.event_type(), "astrid.v1.lifecycle.runtime_started");
    assert_eq!(obj2.event_type(), "astrid.v1.lifecycle.runtime_started");
}

#[tokio::test]
async fn test_no_subscribers() {
    let bus = EventBus::new();

    let event = AstridEvent::RuntimeStarted {
        metadata: EventMetadata::new("test"),
        version: "0.1.0".to_string(),
    };

    let count = bus.publish(event);
    assert_eq!(count, 0);
}

#[tokio::test]
async fn test_try_recv_empty() {
    let bus = EventBus::new();
    let mut receiver = bus.subscribe();

    let result = receiver.try_recv();
    assert!(result.is_none());
}

#[tokio::test]
async fn test_try_recv_with_event() {
    let bus = EventBus::new();
    let mut receiver = bus.subscribe();

    let event = AstridEvent::RuntimeStarted {
        metadata: EventMetadata::new("test"),
        version: "0.1.0".to_string(),
    };

    bus.publish(event);

    let result = receiver.try_recv();
    assert!(result.is_some());
}

#[tokio::test]
async fn test_subscriber_count() {
    let bus = EventBus::new();
    assert_eq!(bus.subscriber_count(), 0);

    let receiver1 = bus.subscribe();
    assert_eq!(bus.subscriber_count(), 1);

    let _receiver2 = bus.subscribe();
    assert_eq!(bus.subscriber_count(), 2);

    drop(receiver1);
    // Note: subscriber count may not immediately reflect dropped receivers
}

#[tokio::test]
async fn test_cloned_bus_synchronous_subscriber() {
    use crate::subscriber::FilterSubscriber;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let bus = EventBus::new();
    let cloned_bus = bus.clone();

    let counter = Arc::new(AtomicUsize::new(0));
    let counter_clone = Arc::clone(&counter);

    let subscriber = FilterSubscriber::new("test_sync", move |_| {
        counter_clone.fetch_add(1, Ordering::SeqCst);
    });

    // Register on the cloned bus
    cloned_bus.registry().register(Arc::new(subscriber));

    // Publish on the original bus
    let event = AstridEvent::RuntimeStarted {
        metadata: EventMetadata::new("test"),
        version: "0.1.0".to_string(),
    };
    bus.publish(event);

    // The subscriber registered on the cloned bus should have received it
    assert_eq!(counter.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn test_event_bus_drop_cleans_up_registry() {
    use crate::subscriber::FilterSubscriber;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct DropNotify(Arc<AtomicUsize>);
    impl Drop for DropNotify {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    let drop_count = Arc::new(AtomicUsize::new(0));
    let drop_count_clone = Arc::clone(&drop_count);

    let notifier = DropNotify(drop_count_clone);
    let bus = EventBus::new();

    let subscriber = FilterSubscriber::new("test_drop", move |_| {
        let _ = &notifier; // Capture notifier so it drops when the subscriber drops
    });

    bus.registry().register(Arc::new(subscriber));

    // The subscriber shouldn't drop until the bus drops
    assert_eq!(drop_count.load(Ordering::SeqCst), 0);

    drop(bus);

    // Dropping the bus should drop the registry, dropping the subscriber, triggering DropNotify
    assert_eq!(drop_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn test_reentrancy_unregister_from_on_event() {
    use crate::subscriber::{EventSubscriber, SubscriberId};
    use std::sync::Mutex;

    struct UnregisteringSubscriber {
        my_id: Mutex<Option<SubscriberId>>,
    }

    impl EventSubscriber for UnregisteringSubscriber {
        fn on_event(&self, _event: &AstridEvent, bus: &EventBus) {
            let id = self.my_id.lock().unwrap().expect("id not set");
            // This shouldn't deadlock against notify's read lock
            bus.registry().unregister(id);
        }
    }

    let bus = EventBus::new();

    let subscriber = Arc::new(UnregisteringSubscriber {
        my_id: Mutex::new(None),
    });

    let id = bus
        .registry()
        .register(Arc::clone(&subscriber) as Arc<dyn EventSubscriber>);
    *subscriber.my_id.lock().unwrap() = Some(id);

    let event = AstridEvent::RuntimeStarted {
        metadata: EventMetadata::new("test"),
        version: "0.1.0".to_string(),
    };

    // This will trigger on_event, which calls unregister.
    bus.publish(event);

    assert_eq!(bus.registry().len(), 0);
}

#[tokio::test]
async fn test_drop_deadlock_publish_from_drop() {
    use crate::subscriber::EventSubscriber;

    struct DroppingSubscriber {
        bus: EventBus,
    }

    impl EventSubscriber for DroppingSubscriber {
        fn on_event(&self, _event: &AstridEvent, _bus: &EventBus) {}
    }

    impl Drop for DroppingSubscriber {
        fn drop(&mut self) {
            let event = AstridEvent::RuntimeStarted {
                metadata: EventMetadata::new("test"),
                version: "0.1.0".to_string(),
            };
            // If unregister holds the write lock while dropping us, this will deadlock
            // when notify tries to get the read lock.
            self.bus.publish(event);
        }
    }

    let bus = EventBus::new();

    let id = bus
        .registry()
        .register(Arc::new(DroppingSubscriber { bus: bus.clone() }));

    // This shouldn't deadlock
    bus.registry().unregister(id);
}

#[tokio::test]
async fn test_topic_subscription_exact() {
    let bus = EventBus::new();
    let mut all_receiver = bus.subscribe();
    let mut specific_receiver = bus.subscribe_topic("astrid.cli.input");

    let msg = crate::ipc::IpcMessage::new(
        Topic::from_raw("astrid.cli.input"),
        crate::ipc::IpcPayload::UserInput {
            text: "hello".into(),
            session_id: "default".into(),
            context: None,
        },
        uuid::Uuid::new_v4(),
    );

    let event = AstridEvent::Ipc {
        metadata: EventMetadata::new("test"),
        message: msg,
    };

    bus.publish(event);

    assert!(all_receiver.try_recv().is_some());
    assert!(specific_receiver.try_recv().is_some());

    // Publish to a different topic
    let msg2 = crate::ipc::IpcMessage::new(
        Topic::from_raw("astrid.telegram.input"),
        crate::ipc::IpcPayload::UserInput {
            text: "hello".into(),
            session_id: "default".into(),
            context: None,
        },
        uuid::Uuid::new_v4(),
    );

    let event2 = AstridEvent::Ipc {
        metadata: EventMetadata::new("test"),
        message: msg2,
    };

    bus.publish(event2);

    assert!(all_receiver.try_recv().is_some());
    // Specific receiver should ignore this
    assert!(specific_receiver.try_recv().is_none());
}

#[tokio::test]
async fn test_topic_subscription_wildcard() {
    let bus = EventBus::new();
    // Trailing `*` matches 1+ segments; "astrid.*" is a namespace subscription
    // that matches any topic starting with "astrid." regardless of depth.
    let mut wildcard_receiver = bus.subscribe_topic("astrid.*");

    let msg1 = crate::ipc::IpcMessage::new(
        Topic::from_raw("astrid.cli.input"),
        crate::ipc::IpcPayload::UserInput {
            text: "hello".into(),
            session_id: "default".into(),
            context: None,
        },
        uuid::Uuid::new_v4(),
    );
    let event1 = AstridEvent::Ipc {
        metadata: EventMetadata::new("test"),
        message: msg1,
    };

    let msg2 = crate::ipc::IpcMessage::new(
        Topic::from_raw("system.log"),
        crate::ipc::IpcPayload::UserInput {
            text: "hello".into(),
            session_id: "default".into(),
            context: None,
        },
        uuid::Uuid::new_v4(),
    );
    let event2 = AstridEvent::Ipc {
        metadata: EventMetadata::new("test"),
        message: msg2,
    };

    bus.publish(event1);
    bus.publish(event2);

    // Should receive the matching one, but not the non-matching one
    let received = wildcard_receiver.try_recv().unwrap();
    if let AstridEvent::Ipc { message, .. } = &*received {
        assert_eq!(message.topic, "astrid.cli.input");
    } else {
        panic!("Expected IPC event");
    }

    assert!(wildcard_receiver.try_recv().is_none());
}

#[tokio::test]
async fn test_topic_subscription_ignores_non_ipc() {
    let bus = EventBus::new();
    let mut specific_receiver = bus.subscribe_topic("astrid.cli.input");

    // Publish a non-IPC event
    let event = AstridEvent::RuntimeStarted {
        metadata: EventMetadata::new("test"),
        version: "0.1.0".into(),
    };

    bus.publish(event);

    // Specific receiver should strictly ignore non-IPC events
    assert!(specific_receiver.try_recv().is_none());
}

/// Helper to create an IPC event with a given topic.
fn ipc_event(topic: &str) -> AstridEvent {
    AstridEvent::Ipc {
        metadata: EventMetadata::new("test"),
        message: crate::ipc::IpcMessage::new(
            Topic::from_raw(topic),
            crate::ipc::IpcPayload::UserInput {
                text: "x".into(),
                session_id: "default".into(),
                context: None,
            },
            uuid::Uuid::new_v4(),
        ),
    }
}

#[tokio::test]
async fn test_wildcard_matches_multiple_depths() {
    let bus = EventBus::new();
    let mut receiver = bus.subscribe_topic("astrid.v1.request.*");

    // 4 segments: should match (1 segment after prefix)
    bus.publish(ipc_event("astrid.v1.request.list_capsules"));
    assert!(receiver.try_recv().is_some());

    // 5 segments: should also match (trailing * = 1+ segments)
    bus.publish(ipc_event("astrid.v1.request.foo.bar"));
    assert!(receiver.try_recv().is_some());

    // 3 segments (fewer than prefix + 1): should NOT match
    bus.publish(ipc_event("astrid.v1.request"));
    assert!(receiver.try_recv().is_none());

    // Different prefix: should NOT match
    bus.publish(ipc_event("system.v1.request.foo"));
    assert!(receiver.try_recv().is_none());
}

#[tokio::test]
async fn test_wildcard_rejects_deep_topics() {
    let bus = EventBus::new();
    let mut receiver = bus.subscribe_topic("a.*");

    // 21 segments: exceeds MAX_TOPIC_DEPTH of 20
    let deep = (0..21)
        .map(|i| format!("s{i}"))
        .collect::<Vec<_>>()
        .join(".");
    let topic = format!("a.{deep}");
    bus.publish(ipc_event(&topic));
    assert!(receiver.try_recv().is_none());
}

#[tokio::test]
async fn test_middle_wildcard_matches_one_segment() {
    let bus = EventBus::new();
    let mut receiver = bus.subscribe_topic("astrid.*.input");

    // Exact match with one middle segment
    bus.publish(ipc_event("astrid.cli.input"));
    assert!(receiver.try_recv().is_some());

    // Different middle segment also matches
    bus.publish(ipc_event("astrid.telegram.input"));
    assert!(receiver.try_recv().is_some());

    // Wrong last segment: should NOT match
    bus.publish(ipc_event("astrid.cli.output"));
    assert!(receiver.try_recv().is_none());

    // Extra segment: should NOT match (segment count mismatch)
    bus.publish(ipc_event("astrid.cli.sub.input"));
    assert!(receiver.try_recv().is_none());
}

#[tokio::test]
async fn test_drain_lagged_initially_zero() {
    let bus = EventBus::new();
    let mut receiver = bus.subscribe();
    assert_eq!(receiver.drain_lagged(), 0);
}

#[tokio::test]
async fn test_drain_lagged_resets_after_read() {
    // Use a tiny channel so we can force lag easily.
    let bus = EventBus::with_capacity(2);
    let mut receiver = bus.subscribe();

    // Publish 5 events into a capacity-2 channel — the receiver will lag.
    for i in 0..5 {
        let event = AstridEvent::RuntimeStarted {
            metadata: EventMetadata::new("test"),
            version: format!("{i}"),
        };
        bus.publish(event);
    }

    // try_recv will encounter the Lagged error and accumulate it.
    let _ = receiver.try_recv();

    let lagged = receiver.drain_lagged();
    assert!(lagged > 0, "expected lag count > 0, got {lagged}");

    // Second drain should be zero — it was reset.
    assert_eq!(receiver.drain_lagged(), 0);
}

#[tokio::test]
async fn test_drain_lagged_accumulates_across_calls() {
    let bus = EventBus::with_capacity(2);
    let mut receiver = bus.subscribe();

    // First burst: overflow the channel.
    for _ in 0..4 {
        bus.publish(AstridEvent::RuntimeStarted {
            metadata: EventMetadata::new("test"),
            version: "v1".into(),
        });
    }
    // Drain available messages to trigger the Lagged error.
    while receiver.try_recv().is_some() {}

    let lag1 = receiver.drain_lagged();

    // Second burst: overflow again.
    for _ in 0..4 {
        bus.publish(AstridEvent::RuntimeStarted {
            metadata: EventMetadata::new("test"),
            version: "v2".into(),
        });
    }
    while receiver.try_recv().is_some() {}

    let lag2 = receiver.drain_lagged();

    // Both bursts should have caused lag independently.
    assert!(lag1 > 0, "first burst should lag");
    assert!(lag2 > 0, "second burst should lag");
}

#[tokio::test]
async fn test_recv_blocking_with_timeout() {
    let bus = EventBus::new();
    let mut receiver = bus.subscribe();

    // With no messages, recv should return None after timeout.
    let result = tokio::time::timeout(std::time::Duration::from_millis(50), receiver.recv()).await;

    // Timeout should fire — no messages published.
    assert!(result.is_err(), "expected timeout, got a message");
}

#[tokio::test]
async fn test_recv_blocking_wakes_on_message() {
    let bus = EventBus::new();
    let mut receiver = bus.subscribe();

    // Spawn a task that publishes after a short delay.
    let bus_clone = bus.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        bus_clone.publish(AstridEvent::RuntimeStarted {
            metadata: EventMetadata::new("test"),
            version: "wake".into(),
        });
    });

    // recv should wake when the message arrives, well before 5s.
    let result = tokio::time::timeout(std::time::Duration::from_secs(5), receiver.recv()).await;

    assert!(result.is_ok(), "recv should have woken up");
    let event = result.unwrap().unwrap();
    assert_eq!(event.event_type(), "astrid.v1.lifecycle.runtime_started");
}

#[tokio::test]
async fn test_try_recv_drains_burst() {
    let bus = EventBus::new();
    let mut receiver = bus.subscribe();

    // Publish 10 messages in a burst.
    for i in 0..10 {
        bus.publish(AstridEvent::RuntimeStarted {
            metadata: EventMetadata::new("test"),
            version: format!("{i}"),
        });
    }

    // Drain all with try_recv.
    let mut count = 0;
    while receiver.try_recv().is_some() {
        count += 1;
    }
    assert_eq!(count, 10);

    // No more messages.
    assert!(receiver.try_recv().is_none());
}

#[test]
fn lag_and_publish_metrics_record_with_labels() {
    use metrics_util::debugging::DebuggingRecorder;

    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();

    // A small-capacity bus with 5 un-drained publishes forces the
    // receiver to lag; the first `try_recv` then reports it and records
    // the per-subscriber counter. Scoped to a thread-local recorder so
    // this never touches a global recorder another test may install.
    metrics::with_local_recorder(&recorder, || {
        let bus = EventBus::with_capacity(2);
        let mut rx = bus.subscribe_as("test_subscriber");
        for _ in 0..5 {
            bus.publish(AstridEvent::RuntimeStarted {
                metadata: EventMetadata::new("test"),
                version: "0.1.0".to_string(),
            });
        }
        // First call records the lag; the rest drain the survivors.
        while rx.try_recv().is_some() {}
    });

    let mut published = false;
    let mut lag_labelled = false;
    for (composite, _unit, _desc, _value) in snapshotter.snapshot().into_vec() {
        let (_kind, key) = composite.into_parts();
        let name = key.name();
        if name == METRIC_BUS_EVENTS_PUBLISHED_TOTAL {
            published = true;
        } else if name == METRIC_BUS_RECEIVER_LAGGED_TOTAL {
            lag_labelled = key
                .labels()
                .any(|l| l.key() == "subscriber" && l.value() == "test_subscriber");
        }
    }
    assert!(published, "publish counter not recorded");
    assert!(
        lag_labelled,
        "lag counter missing or not labelled with the subscriber tag"
    );
}

// ── Routed-path tests (#813) ────────────────────────────────────

fn ipc_evt(topic: &str, principal: Option<&str>) -> AstridEvent {
    let mut msg = crate::ipc::IpcMessage::new(
        Topic::from_raw(topic),
        crate::ipc::IpcPayload::RawJson(serde_json::json!({})),
        uuid::Uuid::nil(),
    );
    msg.principal = principal.map(String::from);
    AstridEvent::Ipc {
        metadata: EventMetadata::new("test"),
        message: msg,
    }
}

#[tokio::test]
async fn routed_demux_no_broadcast_storm() {
    // 5 routed subs, each with a distinct capsule_uuid on the same
    // pattern. Each subscription should be independent — publishing 10
    // messages to the pattern delivers 10 to each subscription, not 50
    // shared.
    let bus = EventBus::new();
    let mut subs = Vec::new();
    for _ in 0..5 {
        subs.push(bus.subscribe_topic_routed(uuid::Uuid::new_v4(), "t.*", "capsule-x", "test_sub"));
    }
    assert_eq!(bus.routed_subscription_count(), 5);

    for i in 0..10 {
        bus.publish(ipc_evt(&format!("t.x{i}"), Some("alice")));
    }

    for sub in &mut subs {
        let drained = sub.try_drain(super::MAX_SUBSCRIPTION_BUDGET_BYTES);
        assert_eq!(
            drained.len(),
            10,
            "each routed sub should receive 10 events"
        );
    }
}

#[tokio::test]
async fn routed_subscription_isolates_principals_under_burst() {
    let bus = EventBus::new();
    let cap_uuid = uuid::Uuid::new_v4();
    let mut sub = bus.subscribe_topic_routed(cap_uuid, "t.*", "capsule-y", "test_sub");

    // Alice publishes 200 messages; bob is idle.
    for _ in 0..200 {
        bus.publish(ipc_evt("t.x", Some("alice")));
    }

    // Alice's bucket exists; bob's does not (demand-allocation).
    assert_eq!(sub.active_principals(), 1);

    let drained = sub.try_drain(super::MAX_SUBSCRIPTION_BUDGET_BYTES);
    assert!(!drained.is_empty(), "alice's burst should drain");
    // Every drained event is alice's.
    for ev in &drained {
        if let AstridEvent::Ipc { message, .. } = &**ev {
            assert_eq!(message.principal.as_deref(), Some("alice"));
        }
    }
}

#[tokio::test]
async fn routed_subscription_dropped_on_drop() {
    let bus = EventBus::new();
    let sub = bus.subscribe_topic_routed(uuid::Uuid::new_v4(), "t.*", "capsule-z", "test_sub");
    assert_eq!(bus.routed_subscription_count(), 1);
    drop(sub);
    assert_eq!(bus.routed_subscription_count(), 0);
}

#[tokio::test]
async fn routed_recv_wakes_on_publish() {
    let bus = EventBus::new();
    let cap_uuid = uuid::Uuid::new_v4();
    let mut sub = bus.subscribe_topic_routed(cap_uuid, "t.*", "capsule-w", "test_sub");

    let bus2 = bus.clone();
    let publisher = tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        bus2.publish(ipc_evt("t.wake", Some("alice")));
    });

    let got = sub
        .recv(Some(std::time::Duration::from_secs(2)))
        .await
        .expect("recv should wake");
    if let AstridEvent::Ipc { message, .. } = &*got {
        assert_eq!(message.topic, "t.wake");
    } else {
        panic!("expected IPC event");
    }
    publisher.await.expect("publisher task");
}

#[tokio::test]
async fn routed_ready_wakes_without_consuming() {
    let bus = EventBus::new();
    let mut sub =
        bus.subscribe_topic_routed(uuid::Uuid::new_v4(), "t.*", "capsule-ready", "test_sub");

    let publisher_bus = bus.clone();
    let publisher = tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        publisher_bus.publish(ipc_evt("t.ready", Some("alice")));
    });

    tokio::time::timeout(std::time::Duration::from_secs(2), sub.ready())
        .await
        .expect("readiness should wake");
    assert!(sub.total_bytes() > 0, "ready must not consume the event");
    let event = sub.try_recv_one().expect("event remains queued");
    if let AstridEvent::Ipc { message, .. } = &*event {
        assert_eq!(message.topic, "t.ready");
    } else {
        panic!("expected IPC event");
    }
    publisher.await.expect("publisher task");
}

#[tokio::test]
async fn routed_recv_timeout_returns_none_when_idle() {
    let bus = EventBus::new();
    let cap_uuid = uuid::Uuid::new_v4();
    let mut sub = bus.subscribe_topic_routed(cap_uuid, "t.*", "capsule-w", "test_sub");
    let got = sub.recv(Some(std::time::Duration::from_millis(20))).await;
    assert!(
        got.is_none(),
        "timeout should expire when no publish arrives"
    );
}

#[tokio::test]
async fn routed_path_does_not_disturb_broadcast_subscribers() {
    // A broadcast subscriber and a routed subscriber both see the
    // publish, but the routed sub doesn't influence broadcast lag.
    let bus = EventBus::new();
    let mut broad = bus.subscribe_as("broad_sub");
    let mut routed =
        bus.subscribe_topic_routed(uuid::Uuid::new_v4(), "t.*", "capsule-a", "test_sub");

    bus.publish(ipc_evt("t.x", Some("alice")));

    // Broadcast subscriber sees the event.
    let b = broad.try_recv().expect("broadcast sub should receive");
    assert!(matches!(&*b, AstridEvent::Ipc { .. }));

    // Routed subscriber also sees it.
    let drained = routed.try_drain(super::MAX_SUBSCRIPTION_BUDGET_BYTES);
    assert_eq!(drained.len(), 1);
}

#[tokio::test]
async fn routed_5000_principals_demand_allocate() {
    // A burst of 5000 distinct principals on the same routed sub
    // creates 5000 buckets and a single drr_drain should empty them
    // all under the quantum floor.
    let bus = EventBus::new();
    let mut sub =
        bus.subscribe_topic_routed(uuid::Uuid::new_v4(), "t.*", "capsule-load", "test_sub");
    for i in 0..5000 {
        bus.publish(ipc_evt("t.x", Some(&format!("p{i}"))));
    }
    assert_eq!(sub.active_principals(), 5000);
    let drained = sub.try_drain(super::MAX_SUBSCRIPTION_BUDGET_BYTES);
    assert_eq!(drained.len(), 5000);
    assert_eq!(sub.active_principals(), 0);
}

#[tokio::test]
async fn routed_receiver_drain_under_n1000_fanin_via_try_drain() {
    // Pins that 1000 distinct principals routed into one receiver land
    // in the entry's per-principal buckets without back-pressure
    // collapse. Drains through `try_drain` (the diagnostic path the
    // gateway can poll under saturation alarms); the SSE-shaped `recv`
    // path is exercised by `routed_recv_wakes_on_publish` above.
    let bus = EventBus::new();
    let mut sub =
        bus.subscribe_topic_routed(uuid::Uuid::new_v4(), "t.*", "capsule-fanin", "test_sub");
    for i in 0..1000 {
        bus.publish(ipc_evt("t.x", Some(&format!("p{i}"))));
    }
    assert_eq!(sub.active_principals(), 1000);
    let drained = sub.try_drain(super::MAX_SUBSCRIPTION_BUDGET_BYTES);
    let mut seen = std::collections::HashSet::new();
    for ev in &drained {
        if let AstridEvent::Ipc { message, .. } = &**ev
            && let Some(p) = &message.principal
        {
            seen.insert(p.clone());
        }
    }
    assert_eq!(seen.len(), 1000, "every distinct principal should drain");
}

#[tokio::test]
async fn routed_receiver_isolation_between_subscriptions() {
    // Two routed subscriptions for the same topic each get their own
    // RouteEntry. Draining one doesn't drain the other — they're
    // independent fan-out targets.
    let bus = EventBus::new();
    let mut a = bus.subscribe_topic_routed(uuid::Uuid::new_v4(), "t.*", "capsule-a", "test_sub");
    let mut b = bus.subscribe_topic_routed(uuid::Uuid::new_v4(), "t.*", "capsule-b", "test_sub");

    for _ in 0..10 {
        bus.publish(ipc_evt("t.x", Some("alice")));
    }

    let drained_a = a.try_drain(super::MAX_SUBSCRIPTION_BUDGET_BYTES);
    assert_eq!(drained_a.len(), 10, "a should see all 10");
    // b's queue is untouched by a's drain.
    let drained_b = b.try_drain(super::MAX_SUBSCRIPTION_BUDGET_BYTES);
    assert_eq!(drained_b.len(), 10, "b independently sees all 10");
}

// ── Self-scoped routed subscriptions (Option B audit scoping) ────

/// The audit topic, mirrored from `astrid-kernel`'s `AUDIT_TOPIC` and
/// `astrid-gateway`'s `events::AUDIT_TOPIC`. Used only as a routing
/// pattern in these tests; the bus does not special-case it.
const AUDIT_TOPIC: &str = "astrid.v1.audit.entry";

#[tokio::test]
async fn cross_principal_audit_isolation_at_bus() {
    // A subscription scoped to alice over the audit topic receives ONLY
    // alice's entries; bob's and the system (None) entries never arrive.
    // On today's firehose-default (scope=None) this would drain all of
    // them — that is exactly the security gap this closes.
    let bus = EventBus::new();
    let mut sub = bus.subscribe_topic_routed_scoped(
        uuid::Uuid::new_v4(),
        AUDIT_TOPIC,
        "audit-consumer",
        "test_sub",
        Some(Some("alice".into())),
    );

    for _ in 0..7 {
        bus.publish(ipc_evt(AUDIT_TOPIC, Some("alice")));
    }
    for _ in 0..4 {
        bus.publish(ipc_evt(AUDIT_TOPIC, Some("bob")));
    }
    // A system/kernel (None-principal) audit entry must also be excluded.
    bus.publish(ipc_evt(AUDIT_TOPIC, None));

    // Only alice's bucket ever materialised.
    assert_eq!(sub.active_principals(), 1);

    let drained = sub.try_drain(super::MAX_SUBSCRIPTION_BUDGET_BYTES);
    assert_eq!(drained.len(), 7, "only alice's seven entries are delivered");
    for ev in &drained {
        if let AstridEvent::Ipc { message, .. } = &**ev {
            assert_eq!(message.principal.as_deref(), Some("alice"));
        } else {
            panic!("expected IPC event");
        }
    }
}

#[tokio::test]
async fn unscoped_route_unchanged_regression() {
    // The unscoped path (subscribe_topic_routed, scope=None) over the same
    // publish mix delivers EVERY event — the gateway firehose path is
    // intact and the #813 fan-out is undisturbed.
    let bus = EventBus::new();
    let mut sub = bus.subscribe_topic_routed(
        uuid::Uuid::new_v4(),
        AUDIT_TOPIC,
        "audit-firehose",
        "test_sub",
    );

    for _ in 0..7 {
        bus.publish(ipc_evt(AUDIT_TOPIC, Some("alice")));
    }
    for _ in 0..4 {
        bus.publish(ipc_evt(AUDIT_TOPIC, Some("bob")));
    }
    bus.publish(ipc_evt(AUDIT_TOPIC, None));

    // alice, bob, and system → three distinct buckets.
    assert_eq!(sub.active_principals(), 3);

    let drained = sub.try_drain(super::MAX_SUBSCRIPTION_BUDGET_BYTES);
    assert_eq!(drained.len(), 12, "firehose delivers all 7 + 4 + 1 events");
}

#[tokio::test]
async fn scoped_drop_no_spurious_notify() {
    // A scoped route fed only foreign-principal events must not wake its
    // receiver: dispatch_to_routes skips notify_one on the accepts()==false
    // continue, so a bounded recv on the idle owner times out.
    let bus = EventBus::new();
    let mut sub = bus.subscribe_topic_routed_scoped(
        uuid::Uuid::new_v4(),
        AUDIT_TOPIC,
        "audit-consumer",
        "test_sub",
        Some(Some("alice".into())),
    );

    // Burst of bob-only audit entries — all dropped, none notified.
    for _ in 0..50 {
        bus.publish(ipc_evt(AUDIT_TOPIC, Some("bob")));
    }

    // recv parks and must time out: no wakeup was delivered.
    let got = sub.recv(Some(std::time::Duration::from_millis(50))).await;
    assert!(got.is_none(), "foreign-only burst must not wake the owner");
    assert_eq!(sub.active_principals(), 0, "no bucket ever allocated");
}
