//! Receiver-side handle returned by `EventBus::subscribe_topic_routed`.
//! Owns the lifetime of its `RouteEntry`: on drop, the entry is removed
//! from the bus's `routes` map.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::{Mutex, RwLock};
use tokio::sync::Notify;

use crate::event::AstridEvent;
use crate::route::entry::{RouteEntry, RouteKey};

/// Gauge: number of active principal sub-queues currently held by a
/// route. Labelled by `capsule`.
pub const METRIC_ROUTE_ACTIVE_PRINCIPALS: &str = "astrid_capsule_route_active_principals";

/// Gauge: bytes currently held by a route across all its sub-queues.
/// Labelled by `capsule`.
pub const METRIC_ROUTE_BUDGET_BYTES_IN_USE: &str = "astrid_capsule_route_budget_bytes_in_use";

/// Receiver-side handle returned by `EventBus::subscribe_topic_routed`.
pub struct RoutedEventReceiver {
    pub(crate) route_key: RouteKey,
    pub(crate) route_entry: Arc<Mutex<RouteEntry>>,
    pub(crate) notify: Arc<Notify>,
    pub(crate) routes: Arc<RwLock<HashMap<RouteKey, Arc<Mutex<RouteEntry>>>>>,
    pub(crate) lagged_count: u64,
    pub(crate) subscriber: &'static str,
}

impl std::fmt::Debug for RoutedEventReceiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoutedEventReceiver")
            .field("route_key", &self.route_key)
            .field("subscriber", &self.subscriber)
            .finish_non_exhaustive()
    }
}

impl RoutedEventReceiver {
    /// Non-blocking receive of one event from the next DRR round.
    ///
    /// This is the host-boundary counterpart to [`recv`](Self::recv): WASM
    /// subscription envelopes install one principal context for the whole
    /// envelope, so the host must hand back at most one routed IPC event at a
    /// time. Bulk diagnostic drains remain available through
    /// [`try_drain`](Self::try_drain).
    pub fn try_recv_one(&mut self) -> Option<Arc<AstridEvent>> {
        let mut entry = self.route_entry.lock();
        let event = entry.drr_pop_one()?;
        entry.gate().release(event)
    }

    /// Receive one event, optionally bounded by `timeout`. Returns the
    /// first event from the next DRR round.
    pub async fn recv(&mut self, timeout: Option<std::time::Duration>) -> Option<Arc<AstridEvent>> {
        let gate = self.route_entry.lock().gate().clone();
        loop {
            if let Some(event) = self.try_recv_one() {
                return Some(event);
            }
            let notified = async {
                tokio::select! {
                    () = gate.wait_until_retired() => false,
                    () = self.notify.notified() => true,
                }
            };
            let retry = match timeout {
                Some(limit) => astrid_runtime::time::timeout(limit, notified)
                    .await
                    .unwrap_or(false),
                None => notified.await,
            };
            if !retry {
                return None;
            }
        }
    }

    /// Drain as many events as fit in `budget` from the route entry,
    /// applying DRR across principal sub-queues. Non-blocking.
    pub fn try_drain(&mut self, budget: usize) -> Vec<Arc<AstridEvent>> {
        let mut out = Vec::new();
        let mut entry = self.route_entry.lock();
        let _ = entry.drr_drain(&mut out, budget);
        entry.gate().release(out).unwrap_or_default()
    }

    /// Returns and resets the cumulative count of dropped messages.
    /// Currently routed receivers don't drop on the receiver side —
    /// dropping happens publish-side via the byte-budget eviction — so
    /// this always returns 0 unless wired to a publish-side drop
    /// signal in a follow-up.
    pub fn drain_lagged(&mut self) -> u64 {
        std::mem::take(&mut self.lagged_count)
    }

    /// Stable label for the subscribing consumer.
    #[must_use]
    pub fn subscriber(&self) -> &'static str {
        self.subscriber
    }

    /// Snapshot the route's active-principal count. Test/diagnostic only.
    #[must_use]
    pub fn active_principals(&self) -> usize {
        self.route_entry.lock().active_principals()
    }

    /// Snapshot the route's total byte usage. Test/diagnostic only.
    #[must_use]
    pub fn total_bytes(&self) -> usize {
        self.route_entry.lock().total_bytes
    }
}

impl Drop for RoutedEventReceiver {
    fn drop(&mut self) {
        let mut routes = self.routes.write();
        routes.remove(&self.route_key);
    }
}
