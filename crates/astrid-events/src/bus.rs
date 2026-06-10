//! Event bus for broadcasting events to subscribers.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::broadcast;
use tracing::{debug, trace, warn};

use crate::event::AstridEvent;
use crate::route::{
    MAX_SUBSCRIPTION_BUDGET_BYTES, PrincipalKey, RouteEntry, RouteKey, RoutedEventReceiver,
    SubscriptionRepAllocator, TopicMatcher,
};
use crate::subscriber::SubscriberRegistry;

/// Default channel capacity for the event bus.
pub(crate) const DEFAULT_CHANNEL_CAPACITY: usize = 1024;

/// How many consecutive non-matching events a topic-filtered subscriber may
/// drain before yielding to the scheduler. A subscriber filtering a backlog
/// under a broadcast storm would otherwise hold its worker for this many
/// synchronous iterations (`broadcast::recv` returns buffered items without
/// awaiting). Kept small to bound that monopolization, but not 1 — yielding on
/// every event would slow the drain enough to risk self-induced lag. Normal
/// operation rarely reaches it: `recv().await` parks between events when the
/// channel isn't backlogged.
const YIELD_AFTER_SKIPPED: usize = 32;

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
    /// Per-(capsule, topic, principal) routing table for guest
    /// subscriptions. Demand-allocated entries; an idle principal has
    /// zero entries even when the bus has 5000 active subscribers (#813).
    /// `parking_lot::RwLock` keeps `publish` synchronous so the
    /// reentrant `SubscriberRegistry::notify` path does not need to be
    /// rewritten as async.
    routes: Arc<parking_lot::RwLock<HashMap<RouteKey, Arc<parking_lot::Mutex<RouteEntry>>>>>,
    /// Allocator for new `RouteKey.subscription_rep` ids; monotonic and
    /// shared across all `EventBus` clones.
    next_subscription_rep: Arc<SubscriptionRepAllocator>,
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
            routes: Arc::new(parking_lot::RwLock::new(HashMap::new())),
            next_subscription_rep: Arc::new(SubscriptionRepAllocator::default()),
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

        // Fan out to routed subscriptions AFTER broadcast::send so a
        // slow routed enqueue can never delay untargeted consumers
        // (kernel_router, admin_router, bus_monitor — all still on
        // broadcast). Routed receivers attached to the bus get full
        // per-(capsule, topic, principal) delivery via the demux here.
        self.dispatch_to_routes(&event);

        count
    }

    /// Iterate the routes table, fan out matching events into each
    /// route's per-principal queue. The read-lock is released as soon
    /// as the matching set is cloned out so a slow per-route push can
    /// never block a sibling publish or a `subscribe_topic_routed`
    /// write-lock acquisition.
    fn dispatch_to_routes(&self, event: &Arc<AstridEvent>) {
        // Snapshot matching route Arcs under the read lock, then
        // release the lock before doing any per-route enqueue work.
        // Without this, a publisher loop would hold the read lock
        // across every route's lock-and-push, blocking
        // `subscribe_topic_routed` callers (which need the write lock).
        let matched: Vec<(RouteKey, Arc<parking_lot::Mutex<RouteEntry>>)> = {
            let routes = self.routes.read();
            if routes.is_empty() {
                return;
            }
            routes
                .iter()
                .filter_map(|(k, e)| {
                    let entry = e.lock();
                    if entry.matcher.matches(event) {
                        // Hold a shared label snapshot before drop so we
                        // can release the per-entry lock between the
                        // matcher check and the actual push (push needs
                        // its own write lock).
                        drop(entry);
                        Some((k.clone(), Arc::clone(e)))
                    } else {
                        None
                    }
                })
                .collect()
        };
        if matched.is_empty() {
            return;
        }

        let principal: PrincipalKey = match &**event {
            AstridEvent::Ipc { message, .. } => message.principal.clone(),
            _ => None,
        };

        for (_key, entry_arc) in matched {
            let mut entry = entry_arc.lock();
            // Self-scope gate: a route scoped to a single principal drops a
            // foreign-principal event here, skipping BOTH the push and the
            // wakeup. Without the notify-skip the receiver would be woken to
            // drain nothing and immediately re-park. Unscoped routes
            // (`scope == None`) accept every publisher, so this is a pure
            // no-op for them and the push path is byte-identical to before.
            if !entry.accepts(&principal) {
                continue;
            }
            entry.push_with_eviction(
                Arc::clone(event),
                principal.clone(),
                MAX_SUBSCRIPTION_BUDGET_BYTES,
            );
            // Capture the notify Arc before drop so we can wake the
            // receiver without holding the entry lock across the wake.
            let notify = Arc::clone(&entry.notify);
            drop(entry);
            notify.notify_one();
        }
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

    /// Subscribe with publish-side per-(capsule, topic, principal)
    /// routing.
    ///
    /// Allocates a [`RouteEntry`] in the bus's `routes` table and
    /// returns a [`RoutedEventReceiver`] that drains its own queues
    /// with deficit-round-robin fairness across principals. Two
    /// receivers of the same `(capsule_uuid, topic_pattern)` get
    /// distinct routes — each receives its own copy of every matching
    /// event, unlike the broadcast channel which shares one queue.
    ///
    /// Dropping the receiver removes its route from the bus.
    #[must_use]
    pub fn subscribe_topic_routed(
        &self,
        capsule_uuid: uuid::Uuid,
        topic_pattern: impl Into<String>,
        capsule_id_label: impl Into<String>,
        subscriber: &'static str,
    ) -> RoutedEventReceiver {
        self.subscribe_topic_routed_scoped(
            capsule_uuid,
            topic_pattern,
            capsule_id_label,
            subscriber,
            None,
        )
    }

    /// Routed subscription self-scoped to a single publisher principal.
    ///
    /// Identical to [`subscribe_topic_routed`](Self::subscribe_topic_routed)
    /// except the route only ever admits events whose publisher
    /// [`PrincipalKey`] equals `scope`; foreign-principal events are dropped
    /// at enqueue so they never enter this route's byte budget (see
    /// [`RouteEntry::accepts`](crate::route::RouteEntry::accepts)). Pass
    /// `scope == None` for the unscoped, all-principals behaviour —
    /// `subscribe_topic_routed` is exactly that delegation.
    ///
    /// The scope is the authorization seam for capability-gated firehose
    /// topics (e.g. the audit feed): a non-privileged subscriber is scoped
    /// to its own principal so it can never observe another principal's
    /// events, while a privileged firehose holder subscribes with
    /// `scope == None`.
    ///
    /// Dropping the receiver removes its route from the bus.
    #[must_use]
    pub fn subscribe_topic_routed_scoped(
        &self,
        capsule_uuid: uuid::Uuid,
        topic_pattern: impl Into<String>,
        capsule_id_label: impl Into<String>,
        subscriber: &'static str,
        scope: Option<PrincipalKey>,
    ) -> RoutedEventReceiver {
        let topic_pattern = topic_pattern.into();
        let capsule_label = capsule_id_label.into();
        let route_key = RouteKey {
            capsule_uuid,
            topic_pattern: topic_pattern.clone(),
            subscription_rep: self.next_subscription_rep.next(),
        };
        let matcher = TopicMatcher::new(topic_pattern);
        let entry = Arc::new(parking_lot::Mutex::new(RouteEntry::new(
            matcher,
            capsule_label,
            scope,
        )));
        let notify = Arc::clone(&entry.lock().notify);
        {
            let mut routes = self.routes.write();
            routes.insert(route_key.clone(), Arc::clone(&entry));
        }
        RoutedEventReceiver {
            route_key,
            route_entry: entry,
            notify,
            routes: Arc::clone(&self.routes),
            lagged_count: 0,
            subscriber,
        }
    }

    /// Number of active routed subscriptions (diagnostic).
    #[must_use]
    pub fn routed_subscription_count(&self) -> usize {
        self.routes.read().len()
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
        // subscriber registry, sequence counter, and routes table so
        // a routed subscription created via one handle is visible to
        // every publisher holding any clone of the bus.
        Self {
            sender: self.sender.clone(),
            registry: Arc::clone(&self.registry),
            capacity: self.capacity,
            ipc_seq: Arc::clone(&self.ipc_seq),
            routes: Arc::clone(&self.routes),
            next_subscription_rep: Arc::clone(&self.next_subscription_rep),
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

        crate::topic_pattern_matches(pattern, &message.topic)
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
                    // Filtered-out event. Yield every `YIELD_AFTER_SKIPPED`
                    // non-matching events so a subscriber draining a backlog
                    // under a broadcast storm can't hold the worker for an
                    // unbounded synchronous run.
                    skipped = skipped.wrapping_add(1);
                    if skipped.is_multiple_of(YIELD_AFTER_SKIPPED) {
                        #[cfg(not(target_os = "wasi"))]
                        tokio::task::yield_now().await;
                        #[cfg(target_os = "wasi")]
                        std::hint::spin_loop();
                    }
                },
                Err(broadcast::error::RecvError::Lagged(count)) => {
                    tracing::error!(target: "astrid.bus", security_event = true, skipped = count, subscriber = self.subscriber, "Event receiver lagged, events dropped");
                    self.lagged_count = self.lagged_count.saturating_add(count);
                    metrics::counter!(
                        METRIC_BUS_RECEIVER_LAGGED_TOTAL,
                        "subscriber" => self.subscriber,
                    )
                    .increment(count);
                    // A lag means the broadcast buffer overran this receiver —
                    // i.e. a storm is in progress. Yield before catching up so
                    // the catch-up doesn't monopolize the worker at the worst
                    // possible moment.
                    #[cfg(not(target_os = "wasi"))]
                    tokio::task::yield_now().await;
                    #[cfg(target_os = "wasi")]
                    std::hint::spin_loop();
                    // Just yielded — reset so the next non-matching event can't
                    // trigger an immediate back-to-back yield.
                    skipped = 0;
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
#[path = "bus_tests.rs"]
mod tests;
