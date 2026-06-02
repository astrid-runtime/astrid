//! Per-(capsule, topic, principal) IPC routing demux.
//!
//! `EventBus` owns a publish-side router that fans `Arc<AstridEvent>`s out
//! into per-(capsule, `topic_pattern`, subscription) routes and within each
//! route into per-principal FIFO queues. Guests obtain a [`RoutedEventReceiver`]
//! via [`crate::EventBus::subscribe_topic_routed`], which drains its own
//! queues with deficit-round-robin (DRR) fairness so no single principal
//! can starve another even under sustained burst.
//!
//! ## Why publish-side
//!
//! Pre-#813 every guest subscription consumed the global broadcast channel
//! and filtered by topic + principal on the consumer side. Under a 100-wide
//! cross-principal burst the broadcast channel shed events at its capacity
//! (`DEFAULT_CHANNEL_CAPACITY = 1024`) and the per-receiver post-filter
//! truncated mixed-principal batches. The result was a "concurrency cliff"
//! where orchestration collapsed once principal-count exceeded buffer head
//! room. The publish-side demux owned here is the structural fix: each
//! route gets its own bounded byte budget, each principal gets its own
//! FIFO sub-queue, and fan-out happens before any broadcast-channel back
//! pressure.
//!
//! ## Routing topology
//!
//! ```text
//! EventBus
//!  └── routes: RwLock<HashMap<RouteKey, Mutex<RouteEntry>>>
//!       │      RouteKey = (capsule_uuid, topic_pattern, subscription_rep)
//!       │      RouteEntry { matcher, fanout, total_bytes, notify }
//!       │                                ↑
//!       └─ fanout: HashMap<PrincipalKey, PrincipalQueue>
//!                                          ↑
//!                                          DRR rotated via principal_order
//! ```
//!
//! ## Fairness: deficit round-robin (DRR)
//!
//! Each per-principal sub-queue accrues a `deficit` over rounds; on each
//! visit the queue may emit as many messages as fit under its accumulated
//! deficit (bounded above by [`DRR_QUANTUM_MIN_BYTES`]). 5000 idle
//! principals = zero entries (sub-map is demand-allocated). N active = N
//! entries; the quantum-floor guarantees per-round progress even under
//! extreme principal counts.
//!
//! ## Eviction: oldest-head-first under byte pressure
//!
//! When `entry.total_bytes + msg_size > MAX_SUBSCRIPTION_BUDGET_BYTES` on
//! the publish path, the bucket whose head was enqueued earliest gives up
//! its head message until the new payload fits. Streaming response
//! terminators are preserved by construction: they're always the tail of
//! their principal's queue, so head-eviction trims the prefix not the tail.

pub(crate) mod entry;
pub(crate) mod matcher;
pub(crate) mod receiver;

pub use entry::{
    DRR_QUANTUM_MIN_BYTES, MAX_SUBSCRIPTION_BUDGET_BYTES, METRIC_ROUTE_BYTE_EVICTIONS_TOTAL,
    METRIC_ROUTE_QUANTUM_STARVED_TOTAL, PrincipalKey, RouteKey,
};
pub(crate) use entry::{RouteEntry, SubscriptionRepAllocator};
pub use matcher::{TopicMatcher, ipc_size_of, principal_class_label};
pub use receiver::{
    METRIC_ROUTE_ACTIVE_PRINCIPALS, METRIC_ROUTE_BUDGET_BYTES_IN_USE, RoutedEventReceiver,
};
