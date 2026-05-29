//! Event bus for broadcasting events to subscribers.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::broadcast;
use tracing::{debug, trace, warn};

use crate::event::AstridEvent;
use crate::subscriber::SubscriberRegistry;

/// Default channel capacity for the event bus.
pub(crate) const DEFAULT_CHANNEL_CAPACITY: usize = 1024;

/// Counter: events published to the bus, labelled by the bounded
/// `event_kind` (`AstridEvent::event_type`, a closed `&'static str` set).
pub(crate) const METRIC_BUS_EVENTS_PUBLISHED_TOTAL: &str = "astrid_bus_events_published_total";

/// Counter: events a receiver dropped by falling behind the sender,
/// labelled by `subscriber`. A non-zero `rate()` on any subscriber is the
/// signature of bus backpressure / a feedback storm — the failure mode
/// that pegs CPU by waking every broadcast subscriber. Subscriber labels
/// are a fixed, code-assigned set (see [`EventBus::subscribe_as`]);
/// untagged subscriptions collapse to `"untagged"`.
pub(crate) const METRIC_BUS_RECEIVER_LAGGED_TOTAL: &str = "astrid_bus_receiver_lagged_total";

/// Subscriber label applied to receivers created without an explicit tag.
/// Keeps the `subscriber` label cardinality bounded even for dynamic
/// (capsule-supplied) topic subscriptions.
const SUBSCRIBER_UNTAGGED: &str = "untagged";

/// Event bus for broadcasting events to all subscribers.
///
/// The event bus uses a broadcast channel to deliver events to all
/// connected receivers. Events are delivered asynchronously and in order.
///
/// **WARNING:** Synchronous subscribers (`SubscriberRegistry`) are shared
/// across clones. Storing a cloned `EventBus` inside a synchronous subscriber
/// will create a memory leak via an `Arc` reference cycle. If a synchronous
/// subscriber needs to publish events, store a `std::sync::Weak<EventBus>`
/// or communicate via a separate channel.
#[derive(Debug)]
pub struct EventBus {
    /// Sender for broadcasting events.
    sender: broadcast::Sender<Arc<AstridEvent>>,
    /// Registry for synchronous subscribers.
    registry: Arc<SubscriberRegistry>,
    /// Channel capacity.
    capacity: usize,
    /// Monotonic sequence counter for IPC message ordering.
    ipc_seq: Arc<AtomicU64>,
}

impl EventBus {
    /// Create a new event bus with default capacity.
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CHANNEL_CAPACITY)
    }

    /// Create a new event bus with specified capacity.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self {
            sender,
            registry: Arc::new(SubscriberRegistry::new()),
            capacity,
            ipc_seq: Arc::new(AtomicU64::new(1)),
        }
    }

    /// Publish an event to all subscribers.
    ///
    /// This method broadcasts the event to all async subscribers and
    /// notifies all synchronous subscribers in the registry.
    ///
    /// Returns the number of async receivers that received the event.
    pub fn publish(&self, mut event: AstridEvent) -> usize {
        // Stamp IPC messages with a monotonic sequence number for ordered delivery.
        if let AstridEvent::Ipc {
            ref mut message, ..
        } = event
        {
            message.seq = self.ipc_seq.fetch_add(1, Ordering::Relaxed);
        }
        let event = Arc::new(event);

        // Publish throughput by bounded event kind. `rate()` shows bus
        // load; paired with the per-subscriber lag counter it localises a
        // feedback storm. `event_type()` is a closed `&'static str` set,
        // so cardinality is fixed (IPC traffic collapses to `"ipc"`).
        metrics::counter!(METRIC_BUS_EVENTS_PUBLISHED_TOTAL, "event_kind" => event.event_type())
            .increment(1);

        trace!(event_type = %event.event_type(), "Publishing event");

        // Broadcast to async subscribers first so they don't wait for synchronous subscribers
        let count = if let Ok(c) = self.sender.send(Arc::clone(&event)) {
            debug!(
                event_type = %event.event_type(),
                receiver_count = c,
                "Event published"
            );
            c
        } else {
            // No receivers - this is fine
            trace!(event_type = %event.event_type(), "No receivers for event");
            0
        };

        // Notify synchronous subscribers
        self.registry.notify(&event, self);

        count
    }

    /// Subscribe to events.
    ///
    /// Returns a receiver that will receive all published events. The
    /// receiver's lag is attributed to the `"untagged"` subscriber in
    /// [`METRIC_BUS_RECEIVER_LAGGED_TOTAL`]; use [`subscribe_as`] to give a
    /// long-lived consumer a stable label.
    ///
    /// [`subscribe_as`]: Self::subscribe_as
    #[must_use]
    pub fn subscribe(&self) -> EventReceiver {
        self.subscribe_as(SUBSCRIBER_UNTAGGED)
    }

    /// Subscribe to all events, attributing this receiver's lag to a
    /// stable `subscriber` label. Pass a fixed `&'static str` (never
    /// caller/remote text) so the lag-counter cardinality stays bounded.
    #[must_use]
    pub fn subscribe_as(&self, subscriber: &'static str) -> EventReceiver {
        EventReceiver::new(self.sender.subscribe(), None, subscriber)
    }

    /// Subscribe to IPC events matching a specific topic pattern.
    ///
    /// The pattern can be an exact match (e.g. `astrid.cli.input`)
    /// or end with a trailing `*` (e.g. `astrid.v1.request.*`) which matches
    /// one or more remaining dot-separated segments up to a maximum depth of 20.
    /// Middle wildcards (e.g. `astrid.*.event`) match exactly one segment.
    ///
    /// Lag is attributed to `"untagged"`; use [`subscribe_topic_as`] for a
    /// long-lived consumer.
    ///
    /// [`subscribe_topic_as`]: Self::subscribe_topic_as
    #[must_use]
    pub fn subscribe_topic(&self, topic_pattern: impl Into<String>) -> EventReceiver {
        self.subscribe_topic_as(topic_pattern, SUBSCRIBER_UNTAGGED)
    }

    /// Topic subscription that attributes this receiver's lag to a stable
    /// `subscriber` label. Pass a fixed `&'static str` (never the topic
    /// pattern itself, which can be capsule-supplied) so the lag-counter
    /// cardinality stays bounded.
    #[must_use]
    pub fn subscribe_topic_as(
        &self,
        topic_pattern: impl Into<String>,
        subscriber: &'static str,
    ) -> EventReceiver {
        EventReceiver::new(
            self.sender.subscribe(),
            Some(topic_pattern.into()),
            subscriber,
        )
    }

    /// Get the synchronous subscriber registry (test-only).
    #[cfg(test)]
    #[must_use]
    pub(crate) fn registry(&self) -> &SubscriberRegistry {
        &self.registry
    }

    /// Get the current number of active subscribers (both async and synchronous).
    #[must_use]
    pub fn subscriber_count(&self) -> usize {
        self.sender
            .receiver_count()
            .saturating_add(self.registry.len())
    }

    /// Get the channel capacity.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for EventBus {
    fn clone(&self) -> Self {
        // Create a new bus that shares the same sender,
        // subscriber registry, and sequence counter.
        Self {
            sender: self.sender.clone(),
            registry: Arc::clone(&self.registry),
            capacity: self.capacity,
            ipc_seq: Arc::clone(&self.ipc_seq),
        }
    }
}

/// Receiver for events from the event bus.
pub struct EventReceiver {
    receiver: broadcast::Receiver<Arc<AstridEvent>>,
    /// Optional topic pattern. If specified, only `AstridEvent::Ipc` messages matching
    /// this pattern will be yielded (non-IPC events will be strictly filtered out).
    topic_pattern: Option<String>,
    /// Cumulative count of messages lost due to broadcast channel lag.
    /// Incremented each time the receiver falls behind the sender.
    lagged_count: u64,
    /// Stable label for this receiver in [`METRIC_BUS_RECEIVER_LAGGED_TOTAL`].
    /// A fixed `&'static str` (code-assigned, never caller text) so the
    /// lag counter's cardinality is bounded.
    subscriber: &'static str,
}

impl EventReceiver {
    /// Create a new receiver with an optional topic filter and a stable
    /// subscriber label for lag attribution.
    pub(crate) fn new(
        receiver: broadcast::Receiver<Arc<AstridEvent>>,
        topic_pattern: Option<String>,
        subscriber: &'static str,
    ) -> Self {
        Self {
            receiver,
            topic_pattern,
            lagged_count: 0,
            subscriber,
        }
    }

    /// Maximum allowed topic depth (dot-separated segments).
    const MAX_TOPIC_DEPTH: usize = 20;

    /// Check if an event matches our topic pattern.
    ///
    /// Uses segment-aware matching. A `*` in a non-trailing position matches
    /// exactly one segment. A trailing `*` (last segment) matches one or more
    /// remaining segments, enabling namespace-level subscriptions (e.g.
    /// `astrid.v1.lifecycle.*` matches all lifecycle events regardless of depth).
    ///
    /// Note: this differs from `dispatcher::topic_matches` used for interceptor
    /// routing, where `*` always matches exactly one segment (equal segment
    /// count is required). Topics deeper than 20 segments are rejected.
    fn matches(&self, event: &AstridEvent) -> bool {
        let Some(pattern) = &self.topic_pattern else {
            return true;
        };

        let AstridEvent::Ipc { message, .. } = event else {
            // If a topic pattern is set, we ONLY care about matching IPC events.
            return false;
        };

        let topic = &message.topic;

        // Reject topics deeper than the maximum allowed depth.
        if topic.split('.').count() > Self::MAX_TOPIC_DEPTH {
            return false;
        }

        // Trailing wildcard: last segment is `*` and matches 1+ remaining segments.
        if let Some(prefix_pat) = pattern.strip_suffix(".*") {
            let mut prefix_segs = prefix_pat.split('.');
            let mut topic_segs = topic.split('.');

            // All prefix segments must match (with single-segment `*` support).
            let prefix_matched = prefix_segs
                .by_ref()
                .zip(topic_segs.by_ref())
                .all(|(p, t)| p == "*" || p == t);

            // Prefix must be fully consumed and topic must have 1+ remaining
            // segments (the trailing `*` matches 1+ segments).
            prefix_matched && prefix_segs.next().is_none() && topic_segs.next().is_some()
        } else {
            // Exact segment-count match with single-segment `*` wildcards.
            let mut pat_segs = pattern.split('.');
            let mut topic_segs = topic.split('.');

            let all_matched = pat_segs
                .by_ref()
                .zip(topic_segs.by_ref())
                .all(|(p, t)| p == "*" || p == t);

            // Both iterators must be exhausted (equal segment count).
            all_matched && pat_segs.next().is_none() && topic_segs.next().is_none()
        }
    }

    /// Returns and resets the cumulative count of messages lost due to
    /// broadcast channel lag since the last call.
    pub fn drain_lagged(&mut self) -> u64 {
        std::mem::take(&mut self.lagged_count)
    }

    /// Receive the next event.
    ///
    /// Returns `None` if the channel is closed or if events were dropped
    /// due to the receiver being too slow.
    pub async fn recv(&mut self) -> Option<Arc<AstridEvent>> {
        let mut skipped: usize = 0;
        loop {
            match self.receiver.recv().await {
                Ok(event) => {
                    if self.matches(&event) {
                        return Some(event);
                    }
                    skipped = skipped.wrapping_add(1);
                    if skipped.is_multiple_of(100) {
                        #[cfg(not(target_os = "wasi"))]
                        tokio::task::yield_now().await;
                        #[cfg(target_os = "wasi")]
                        std::hint::spin_loop();
                    }
                },
                Err(broadcast::error::RecvError::Lagged(count)) => {
                    warn!(skipped = count, "Event receiver lagged, events dropped");
                    self.lagged_count = self.lagged_count.saturating_add(count);
                    metrics::counter!(
                        METRIC_BUS_RECEIVER_LAGGED_TOTAL,
                        "subscriber" => self.subscriber,
                    )
                    .increment(count);
                    // Continue receiving
                },
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    }

    /// Try to receive the next event without blocking.
    ///
    /// Returns `Some(event)` if an event is available, or `None` if no event
    /// is available or the channel is closed.
    pub fn try_recv(&mut self) -> Option<Arc<AstridEvent>> {
        loop {
            match self.receiver.try_recv() {
                Ok(event) => {
                    if self.matches(&event) {
                        return Some(event);
                    }
                },
                Err(broadcast::error::TryRecvError::Lagged(count)) => {
                    warn!(skipped = count, "Event receiver lagged, events dropped");
                    self.lagged_count = self.lagged_count.saturating_add(count);
                    metrics::counter!(
                        METRIC_BUS_RECEIVER_LAGGED_TOTAL,
                        "subscriber" => self.subscriber,
                    )
                    .increment(count);
                    // Continue receiving
                },
                Err(
                    broadcast::error::TryRecvError::Empty | broadcast::error::TryRecvError::Closed,
                ) => return None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::EventMetadata;

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
            "astrid.cli.input",
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
            "astrid.telegram.input",
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
            "astrid.cli.input",
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
            "system.log",
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
                topic,
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
        let result =
            tokio::time::timeout(std::time::Duration::from_millis(50), receiver.recv()).await;

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
}
