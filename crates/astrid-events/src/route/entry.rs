//! `RouteEntry` state machine: per-route fan-out, DRR drain, and
//! oldest-head eviction under the global byte budget.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use tokio::sync::Notify;
use uuid::Uuid;

use crate::event::AstridEvent;
use crate::route::matcher::{TopicMatcher, ipc_size_of, principal_class_label};

/// Maximum bytes a single subscription will hold across all its
/// per-principal sub-queues before publish-side head-eviction kicks in.
/// Matches the per-call IPC payload ceiling so any single message still
/// fits within one budget.
pub const MAX_SUBSCRIPTION_BUDGET_BYTES: usize = 1024 * 1024;

/// Per-round DRR floor. 5000 active principals × 4 `KiB` = 20 `MiB` of
/// theoretical per-round throughput, well above the 1 `MiB` total budget,
/// so a round always serves something for every principal in the
/// rotation rather than starving the long tail.
pub const DRR_QUANTUM_MIN_BYTES: usize = 4 * 1024;

/// Defence-in-depth message-count cap per principal sub-queue. The byte
/// budget is the primary admission control; this just stops a flood of
/// 0-byte messages from monopolising one bucket.
pub(crate) const PENDING_PER_PRINCIPAL_FALLBACK: usize = 256;

/// Counter: head messages evicted from a per-principal sub-queue because
/// the route's global byte budget would otherwise be exceeded. Labelled
/// by `capsule` (the subscribing capsule) and bounded `principal_class`.
pub const METRIC_ROUTE_BYTE_EVICTIONS_TOTAL: &str = "astrid_capsule_route_byte_evictions_total";

/// Counter: rounds in which a principal's deficit-round-robin quantum
/// could not cover its queue head message (sustained back pressure).
/// Diagnostic — not a drop signal.
pub const METRIC_ROUTE_QUANTUM_STARVED_TOTAL: &str = "astrid_capsule_route_quantum_starved_total";

/// Composite identity of a single routed subscription on the bus.
///
/// Two guest capsules subscribing to the same pattern receive distinct
/// `RouteKey`s — `subscription_rep` is unique per call — so messages
/// fan out per subscriber rather than being shared like the broadcast
/// channel.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RouteKey {
    /// Capsule UUID owning the subscription. Bounded by deployed
    /// capsule count.
    pub capsule_uuid: Uuid,
    /// Topic pattern as supplied to `subscribe_topic_routed`.
    pub topic_pattern: String,
    /// Monotonic per-bus subscription id; distinguishes multiple
    /// subscriptions of the same `(capsule_uuid, topic_pattern)` pair.
    pub subscription_rep: u64,
}

/// Principal identity key for a fan-out bucket. `None` = system (kernel)
/// principal; `Some(s)` = user/agent principal string.
pub type PrincipalKey = Option<String>;

/// Per-principal FIFO sub-queue inside a route.
#[derive(Debug)]
pub(crate) struct PrincipalQueue {
    /// Queued events in publish order.
    pub(crate) queue: VecDeque<Arc<AstridEvent>>,
    /// Sum of `ipc_size_of(event)` for every event currently in `queue`.
    pub(crate) bytes: usize,
    /// Enqueue time of the current head, used for oldest-head eviction
    /// under byte pressure. `None` ⇔ `queue.is_empty()`.
    pub(crate) head_enqueued_at: Option<Instant>,
    /// DRR deficit carried over rounds.
    pub(crate) deficit: usize,
}

impl PrincipalQueue {
    fn new() -> Self {
        Self {
            queue: VecDeque::new(),
            bytes: 0,
            head_enqueued_at: None,
            deficit: 0,
        }
    }
}

/// Route-side fan-out entry. One per `(capsule, topic_pattern, subscription)`.
#[derive(Debug)]
pub(crate) struct RouteEntry {
    /// Compiled topic matcher.
    pub(crate) matcher: TopicMatcher,
    /// Per-principal FIFO sub-queues. Demand-allocated: an idle principal
    /// has zero entries.
    pub(crate) fanout: HashMap<PrincipalKey, PrincipalQueue>,
    /// FIFO order of distinct principal keys for DRR rotation.
    pub(crate) principal_order: VecDeque<PrincipalKey>,
    /// Sum of all per-principal `bytes`.
    pub(crate) total_bytes: usize,
    /// Stable capsule label for telemetry. Bounded by deployed capsule
    /// count.
    pub(crate) capsule_id_label: String,
    /// Authz self-scope. `Some(p)` ⇒ only events whose publisher
    /// [`PrincipalKey`] equals `p` are admitted; foreign-principal events
    /// are dropped at enqueue ([`accepts`](Self::accepts) → `false`) so
    /// they never consume this route's 1 `MiB` byte budget, never enter
    /// the [`fanout`](Self::fanout) map, and can never head-evict the
    /// owner's own entries. `None` ⇒ unscoped (all principals) — the
    /// default and the only behaviour pre-existing subscriptions get.
    ///
    /// This is orthogonal to the per-principal DRR fan-out buckets, which
    /// remain fairness-only (#813): scoping decides *admission*, DRR
    /// decides *order* among whatever was admitted. A scoped route admits
    /// at most one principal, so its DRR rotation holds exactly one
    /// bucket — strictly less work than an unscoped firehose route.
    ///
    /// COMPLETENESS is CROSS-PRINCIPAL ONLY. The guarantee above ("can never
    /// head-evict the owner's own entries") is about FOREIGN principals — a
    /// noisy co-principal cannot evict the owner. A scoped route still applies
    /// the 1 `MiB` byte budget and the 256-message per-principal cap to the
    /// owner's OWN bucket, so if the owner publishes faster than the consumer
    /// drains, the owner's OWN oldest entries can still self-evict (host
    /// `tracing::error!`/metric only — no in-band guest signal). A
    /// completeness-critical consumer (e.g. an audit-to-blockchain mint
    /// pipeline) must therefore drain promptly or treat the persisted audit
    /// log (`append_with_principal`) as the source of truth, not the live bus
    /// feed. In-band drop-signalling / log reconciliation is a future
    /// (Phase 2) concern.
    pub(crate) scope: Option<PrincipalKey>,
    /// Wakeup for `RoutedEventReceiver::recv`.
    pub(crate) notify: Arc<Notify>,
}

impl RouteEntry {
    /// Construct a new entry for the given matcher.
    ///
    /// `scope` self-scopes the route to a single publisher principal (see
    /// [`scope`](Self::scope)); pass `None` for the unscoped, all-principals
    /// behaviour that every pre-existing subscription relies on. The
    /// argument is mandatory so every constructor must state its intent —
    /// a forgotten scope is a compile error, the secure-by-default failure
    /// mode.
    pub(crate) fn new(
        matcher: TopicMatcher,
        capsule_id_label: String,
        scope: Option<PrincipalKey>,
    ) -> Self {
        Self {
            matcher,
            fanout: HashMap::new(),
            principal_order: VecDeque::new(),
            total_bytes: 0,
            capsule_id_label,
            scope,
            notify: Arc::new(Notify::new()),
        }
    }

    /// Whether an event published by `publisher` is admitted into this
    /// route. Unscoped routes (`scope == None`) admit every publisher;
    /// scoped routes admit only their own principal. This is the single
    /// named home of the authz rule — both the [`dispatch_to_routes`]
    /// notify-skip and the [`push_with_eviction`](Self::push_with_eviction)
    /// defence-in-depth guard consult it.
    ///
    /// [`dispatch_to_routes`]: crate::bus::EventBus
    pub(crate) fn accepts(&self, publisher: &PrincipalKey) -> bool {
        self.scope.as_ref().is_none_or(|s| s == publisher)
    }

    /// Push an event into the route, applying oldest-head eviction under
    /// the global byte budget. Returns the number of evictions that
    /// happened to make room.
    pub(crate) fn push_with_eviction(
        &mut self,
        event: Arc<AstridEvent>,
        principal: PrincipalKey,
        budget_bytes: usize,
    ) -> usize {
        // Defence in depth: enforce the self-scope at the very TOP, before
        // the oversize reject and the eviction loop, so a foreign-principal
        // event never touches `total_bytes`, `fanout`, or `principal_order`
        // even if a future caller forgets the `accepts()` gate in
        // `dispatch_to_routes`. A scoped route's budget is therefore only
        // ever consumable by its own principal.
        if !self.accepts(&principal) {
            return 0;
        }

        let msg_size = ipc_size_of(&event);

        if msg_size > budget_bytes {
            // Pathological: single message exceeds budget. Reject
            // rather than evict everything.
            let class = principal_class_label(principal.as_deref());
            tracing::error!(
                target: "astrid.audit.ipc",
                security_event = true,
                capsule = %self.capsule_id_label,
                principal = principal.as_deref().unwrap_or("<none>"),
                msg_size,
                budget_bytes,
                "ipc::route: incoming message exceeds global byte budget, rejecting publish",
            );
            metrics::counter!(
                METRIC_ROUTE_BYTE_EVICTIONS_TOTAL,
                "capsule" => self.capsule_id_label.clone(),
                "principal_class" => class,
            )
            .increment(1);
            return 1;
        }

        let mut evictions = 0usize;
        while self.total_bytes.saturating_add(msg_size) > budget_bytes {
            if !self.evict_oldest_head() {
                // No queues to evict from but budget would still be
                // exceeded — should not happen since msg_size ≤
                // budget_bytes and total_bytes == 0 implies no queues.
                break;
            }
            evictions = evictions.saturating_add(1);
        }

        let now = Instant::now();
        let is_new = !self.fanout.contains_key(&principal);
        let bucket = self
            .fanout
            .entry(principal.clone())
            .or_insert_with(PrincipalQueue::new);

        if bucket.queue.is_empty() {
            bucket.head_enqueued_at = Some(now);
        }
        bucket.queue.push_back(event);
        bucket.bytes = bucket.bytes.saturating_add(msg_size);
        self.total_bytes = self.total_bytes.saturating_add(msg_size);

        // Defence in depth: per-bucket message-count cap.
        if bucket.queue.len() > PENDING_PER_PRINCIPAL_FALLBACK
            && let Some(dropped) = bucket.queue.pop_front()
        {
            let dropped_size = ipc_size_of(&dropped);
            bucket.bytes = bucket.bytes.saturating_sub(dropped_size);
            self.total_bytes = self.total_bytes.saturating_sub(dropped_size);
            bucket.head_enqueued_at = if bucket.queue.is_empty() {
                None
            } else {
                Some(Instant::now())
            };
            let class = principal_class_label(principal.as_deref());
            tracing::error!(
                target: "astrid.audit.ipc",
                security_event = true,
                capsule = %self.capsule_id_label,
                principal = principal.as_deref().unwrap_or("<none>"),
                cap = PENDING_PER_PRINCIPAL_FALLBACK,
                "ipc::route: per-principal queue cap reached, dropping oldest",
            );
            metrics::counter!(
                METRIC_ROUTE_BYTE_EVICTIONS_TOTAL,
                "capsule" => self.capsule_id_label.clone(),
                "principal_class" => class,
            )
            .increment(1);
        }

        if is_new {
            self.principal_order.push_back(principal);
        }

        evictions
    }

    /// Evict the head of the oldest-head queue. Returns true if an event
    /// was evicted.
    fn evict_oldest_head(&mut self) -> bool {
        let Some(victim_key) = self.oldest_head_key() else {
            return false;
        };
        let Some(bucket) = self.fanout.get_mut(&victim_key) else {
            return false;
        };
        let Some(evicted) = bucket.queue.pop_front() else {
            return false;
        };
        let evicted_size = ipc_size_of(&evicted);
        bucket.bytes = bucket.bytes.saturating_sub(evicted_size);
        self.total_bytes = self.total_bytes.saturating_sub(evicted_size);
        bucket.head_enqueued_at = if bucket.queue.is_empty() {
            None
        } else {
            // We don't track per-event push time, so on subsequent
            // evictions the next head's age is approximated by "now".
            // For correctness of the eviction order this is fine — we
            // only care that the queue we just trimmed is no longer the
            // oldest-head queue.
            Some(Instant::now())
        };

        let evicted_topic = match &*evicted {
            AstridEvent::Ipc { message, .. } => message.topic.to_string(),
            other => other.event_type().to_string(),
        };
        let class = principal_class_label(victim_key.as_deref());
        tracing::error!(
            target: "astrid.audit.ipc",
            security_event = true,
            capsule = %self.capsule_id_label,
            principal = victim_key.as_deref().unwrap_or("<none>"),
            evicted_topic = %evicted_topic,
            total_bytes = self.total_bytes,
            "ipc::route: global byte budget exhausted, dropping head of oldest queue",
        );
        metrics::counter!(
            METRIC_ROUTE_BYTE_EVICTIONS_TOTAL,
            "capsule" => self.capsule_id_label.clone(),
            "principal_class" => class,
        )
        .increment(1);
        true
    }

    /// Linear scan to find the bucket whose `head_enqueued_at` is minimum.
    /// At 5000 principals on one route this is a hot spot under
    /// sustained pressure; the follow-up `BTreeMap<Instant, PrincipalKey>`
    /// head-age index lives in this same module if benchmarks show it
    /// matters.
    fn oldest_head_key(&self) -> Option<PrincipalKey> {
        self.fanout
            .iter()
            .filter_map(|(k, q)| q.head_enqueued_at.map(|t| (t, k.clone())))
            .min_by_key(|(t, _)| *t)
            .map(|(_, k)| k)
    }

    /// Deficit-round-robin drain into `out` up to `budget`. Returns the
    /// total bytes served. Empty queues are removed; partially served
    /// queues remain at the back of the rotation.
    pub(crate) fn drr_drain(&mut self, out: &mut Vec<Arc<AstridEvent>>, budget: usize) -> usize {
        if self.fanout.is_empty() || budget == 0 {
            return 0;
        }

        let mut served = 0usize;
        let total = self.principal_order.len().max(1);
        let quantum = std::cmp::max(
            DRR_QUANTUM_MIN_BYTES,
            budget.checked_div(total).unwrap_or(0),
        );

        loop {
            let mut progress = false;
            let visit = self.principal_order.len();
            for _ in 0..visit {
                let Some(key) = self.principal_order.pop_front() else {
                    break;
                };
                let Some(bucket) = self.fanout.get_mut(&key) else {
                    continue;
                };
                bucket.deficit = bucket.deficit.saturating_add(quantum);

                let mut bucket_progress = false;
                while let Some(front) = bucket.queue.front() {
                    let sz = ipc_size_of(front);
                    if sz > bucket.deficit || served.saturating_add(sz) > budget {
                        break;
                    }
                    let msg = bucket.queue.pop_front().expect("front checked above");
                    bucket.deficit = bucket.deficit.saturating_sub(sz);
                    bucket.bytes = bucket.bytes.saturating_sub(sz);
                    self.total_bytes = self.total_bytes.saturating_sub(sz);
                    served = served.saturating_add(sz);
                    out.push(msg);
                    bucket_progress = true;
                    // Refresh head age to the new head's enqueue time.
                    // We don't track per-message enqueue times, so use
                    // `now()` as a conservative approximation; it
                    // affects only future eviction ordering, never
                    // semantics.
                    bucket.head_enqueued_at = if bucket.queue.is_empty() {
                        None
                    } else {
                        Some(Instant::now())
                    };
                }
                progress |= bucket_progress;

                if !bucket_progress && !bucket.queue.is_empty() {
                    // Could not cover head with this round's deficit.
                    metrics::counter!(
                        METRIC_ROUTE_QUANTUM_STARVED_TOTAL,
                        "capsule" => self.capsule_id_label.clone(),
                        "principal_class" => principal_class_label(key.as_deref()),
                    )
                    .increment(1);
                }

                if bucket.queue.is_empty() {
                    self.fanout.remove(&key);
                } else {
                    self.principal_order.push_back(key);
                }
            }
            if !progress || served >= budget {
                break;
            }
        }

        served
    }

    /// Pop a SINGLE event in round-robin principal order, with the same
    /// rotation/eviction bookkeeping as [`drr_drain`](Self::drr_drain).
    ///
    /// This is the receive fast-path: the caller wants one event now and
    /// collects the remainder via `drr_drain`/`try_drain`. Draining a whole
    /// batch here and returning only its first element would DISCARD (lose)
    /// the rest of the batch — they are already removed from the queue but
    /// never handed back. Serving exactly one event makes the fast path
    /// loss-free no matter how many events are queued (e.g. a fan-out burst
    /// where every responder replies at once).
    pub(crate) fn drr_pop_one(&mut self) -> Option<Arc<AstridEvent>> {
        let visit = self.principal_order.len();
        for _ in 0..visit {
            let Some(key) = self.principal_order.pop_front() else {
                break;
            };
            let Some(bucket) = self.fanout.get_mut(&key) else {
                continue;
            };
            if let Some(msg) = bucket.queue.pop_front() {
                let sz = ipc_size_of(&msg);
                bucket.bytes = bucket.bytes.saturating_sub(sz);
                self.total_bytes = self.total_bytes.saturating_sub(sz);
                bucket.head_enqueued_at = if bucket.queue.is_empty() {
                    None
                } else {
                    Some(Instant::now())
                };
                if bucket.queue.is_empty() {
                    self.fanout.remove(&key);
                } else {
                    // Rotate the served principal to the back so the next
                    // single-pop serves a different bucket (round-robin).
                    self.principal_order.push_back(key);
                }
                return Some(msg);
            }
            // Empty bucket — drop it from the rotation.
            self.fanout.remove(&key);
        }
        None
    }

    /// Number of distinct active principal buckets.
    pub(crate) fn active_principals(&self) -> usize {
        self.fanout.len()
    }
}

/// Monotonic subscription-rep allocator shared across `EventBus` clones.
#[derive(Debug, Default)]
pub(crate) struct SubscriptionRepAllocator(pub(crate) AtomicU64);

impl SubscriptionRepAllocator {
    pub(crate) fn next(&self) -> u64 {
        // Skip zero so it can sentinel "unallocated" if a debug path needs.
        let v = self.0.fetch_add(1, Ordering::Relaxed);
        v.saturating_add(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::EventMetadata;
    use crate::ipc::{IpcMessage, IpcPayload, Topic};
    use serde_json::json;
    use uuid::Uuid;

    fn ipc(topic: &str, principal: Option<&str>) -> Arc<AstridEvent> {
        let mut msg = IpcMessage::new(
            Topic::from_raw(topic),
            IpcPayload::RawJson(json!({})),
            Uuid::nil(),
        );
        msg.principal = principal.map(String::from);
        Arc::new(AstridEvent::Ipc {
            metadata: EventMetadata::new("test"),
            message: msg,
        })
    }

    fn ipc_sized(topic: &str, principal: Option<&str>, payload_bytes: usize) -> Arc<AstridEvent> {
        let blob = "x".repeat(payload_bytes);
        let mut msg = IpcMessage::new(
            Topic::from_raw(topic),
            IpcPayload::RawJson(json!({ "p": blob })),
            Uuid::nil(),
        );
        msg.principal = principal.map(String::from);
        Arc::new(AstridEvent::Ipc {
            metadata: EventMetadata::new("test"),
            message: msg,
        })
    }

    #[test]
    fn push_and_drain_single_principal() {
        let mut entry = RouteEntry::new(TopicMatcher::new("t.*"), "capsule-a".into(), None);
        for _ in 0..3 {
            entry.push_with_eviction(
                ipc("t.x", Some("alice")),
                Some("alice".into()),
                MAX_SUBSCRIPTION_BUDGET_BYTES,
            );
        }
        let mut out = Vec::new();
        entry.drr_drain(&mut out, MAX_SUBSCRIPTION_BUDGET_BYTES);
        assert_eq!(out.len(), 3);
        assert_eq!(entry.fanout.len(), 0);
        assert_eq!(entry.total_bytes, 0);
    }

    #[test]
    fn pop_one_takes_exactly_one_and_keeps_the_rest() {
        // Regression: the receive fast-path takes ONE event and leaves the rest
        // for `try_drain`/`drr_drain`. The old fast-path drained the whole batch
        // and returned only its first element, silently discarding (losing) the
        // remainder — so a fan-out burst lost all-but-one per recv.
        let mut entry = RouteEntry::new(TopicMatcher::new("t.*"), "capsule-a".into(), None);
        for _ in 0..3 {
            entry.push_with_eviction(
                ipc("t.x", Some("alice")),
                Some("alice".into()),
                MAX_SUBSCRIPTION_BUDGET_BYTES,
            );
        }
        // One pop yields exactly one event...
        assert!(entry.drr_pop_one().is_some());
        // ...and the other two are STILL queued — not discarded.
        let mut out = Vec::new();
        entry.drr_drain(&mut out, MAX_SUBSCRIPTION_BUDGET_BYTES);
        assert_eq!(
            out.len(),
            2,
            "the two un-popped events must remain, not be lost"
        );
        assert_eq!(entry.total_bytes, 0);
        assert_eq!(entry.fanout.len(), 0);
    }

    #[test]
    fn pop_one_serves_each_principal_without_loss() {
        let mut entry = RouteEntry::new(TopicMatcher::new("t.*"), "capsule-a".into(), None);
        entry.push_with_eviction(
            ipc("t.x", Some("alice")),
            Some("alice".into()),
            MAX_SUBSCRIPTION_BUDGET_BYTES,
        );
        entry.push_with_eviction(
            ipc("t.x", Some("bob")),
            Some("bob".into()),
            MAX_SUBSCRIPTION_BUDGET_BYTES,
        );
        // Two single-pops serve both queued events (round-robin), losing nothing.
        assert!(entry.drr_pop_one().is_some());
        assert!(entry.drr_pop_one().is_some());
        assert!(
            entry.drr_pop_one().is_none(),
            "only two events were queued; the third pop must be empty"
        );
        assert_eq!(entry.total_bytes, 0);
        assert_eq!(entry.fanout.len(), 0);
    }

    #[test]
    fn drr_two_principals_yield_equal_counts() {
        // With the quantum floor of 4 KiB and tiny payloads, a single
        // round drains every queue completely. Cross-principal
        // fairness is therefore measured by equal *counts* delivered,
        // not strict per-message interleaving — DRR semantics, not
        // pure round-robin. Both principals should each see 2 events.
        let mut entry = RouteEntry::new(TopicMatcher::new("t.*"), "capsule-a".into(), None);
        for _ in 0..2 {
            entry.push_with_eviction(
                ipc("t.x", Some("alice")),
                Some("alice".into()),
                MAX_SUBSCRIPTION_BUDGET_BYTES,
            );
            entry.push_with_eviction(
                ipc("t.x", Some("bob")),
                Some("bob".into()),
                MAX_SUBSCRIPTION_BUDGET_BYTES,
            );
        }
        let mut out = Vec::new();
        entry.drr_drain(&mut out, MAX_SUBSCRIPTION_BUDGET_BYTES);
        assert_eq!(out.len(), 4);
        let mut alice_count = 0;
        let mut bob_count = 0;
        for ev in &out {
            if let AstridEvent::Ipc { message, .. } = &**ev {
                match message.principal.as_deref() {
                    Some("alice") => alice_count += 1,
                    Some("bob") => bob_count += 1,
                    _ => {},
                }
            }
        }
        assert_eq!(alice_count, 2);
        assert_eq!(bob_count, 2);
    }

    #[test]
    fn drr_interleaves_when_quantum_caps_per_round() {
        // Tight budget = small per-principal quantum, so each round
        // serves one message per principal before rotating. Inserted
        // alice (large), bob (large) — drain visits alice, then bob,
        // interleaved.
        let payload_size = 8 * 1024; // 8 KiB > DRR_QUANTUM_MIN_BYTES/2
        let budget = payload_size * 4 + 1024;
        let mut entry = RouteEntry::new(TopicMatcher::new("t.*"), "capsule-a".into(), None);
        entry.push_with_eviction(
            ipc_sized("t.x", Some("alice"), payload_size),
            Some("alice".into()),
            budget,
        );
        entry.push_with_eviction(
            ipc_sized("t.x", Some("bob"), payload_size),
            Some("bob".into()),
            budget,
        );
        entry.push_with_eviction(
            ipc_sized("t.x", Some("alice"), payload_size),
            Some("alice".into()),
            budget,
        );
        entry.push_with_eviction(
            ipc_sized("t.x", Some("bob"), payload_size),
            Some("bob".into()),
            budget,
        );

        let mut out = Vec::new();
        // Drain with budget = payload_size * 4 so 4 messages can be served.
        entry.drr_drain(&mut out, budget);
        // Both principals must each see 2 messages — fairness held.
        let mut alice_count = 0;
        let mut bob_count = 0;
        for ev in &out {
            if let AstridEvent::Ipc { message, .. } = &**ev {
                match message.principal.as_deref() {
                    Some("alice") => alice_count += 1,
                    Some("bob") => bob_count += 1,
                    _ => {},
                }
            }
        }
        assert_eq!(alice_count, 2, "alice fairness");
        assert_eq!(bob_count, 2, "bob fairness");
    }

    #[test]
    fn drr_isolates_principals_under_burst() {
        let mut entry = RouteEntry::new(TopicMatcher::new("t.*"), "capsule-a".into(), None);
        for _ in 0..200 {
            entry.push_with_eviction(
                ipc("t.x", Some("alice")),
                Some("alice".into()),
                MAX_SUBSCRIPTION_BUDGET_BYTES,
            );
        }
        // Only alice; bob has zero entries — demand-allocation invariant.
        assert_eq!(entry.fanout.len(), 1);
        assert!(entry.fanout.contains_key(&Some("alice".into())));
    }

    #[test]
    fn eviction_drops_oldest_head_under_budget() {
        // Budget tuned to ~3 large messages; pushing 4 forces eviction
        // of the oldest head (alice's first), not bob's later message.
        let payload_size = 64 * 1024;
        let budget = payload_size * 3 + 4096;
        let mut entry = RouteEntry::new(TopicMatcher::new("t.*"), "capsule-a".into(), None);

        for _ in 0..3 {
            entry.push_with_eviction(
                ipc_sized("t.alice", Some("alice"), payload_size),
                Some("alice".into()),
                budget,
            );
        }
        // Sanity: alice now holds 3 entries.
        assert_eq!(
            entry
                .fanout
                .get(&Some("alice".into()))
                .map(|q| q.queue.len()),
            Some(3)
        );

        // Push bob — fits without eviction.
        entry.push_with_eviction(
            ipc_sized("t.bob.terminator", Some("bob"), payload_size / 4),
            Some("bob".into()),
            budget,
        );

        // Force budget overflow by pushing a new large alice.
        entry.push_with_eviction(
            ipc_sized("t.alice.new", Some("alice"), payload_size),
            Some("alice".into()),
            budget,
        );

        // Alice's earliest head must have been evicted; bob's tail
        // (the terminator) must still be present.
        let alice_q = entry
            .fanout
            .get(&Some("alice".into()))
            .expect("alice queue");
        let bob_q = entry.fanout.get(&Some("bob".into())).expect("bob queue");
        assert!(bob_q.queue.iter().any(|e| match &**e {
            AstridEvent::Ipc { message, .. } => message.topic == "t.bob.terminator",
            _ => false,
        }));
        // Alice should have evicted at least one of its earlier
        // entries to make room.
        assert!(
            alice_q.queue.len() < 4,
            "alice queue should have shed at least one head"
        );
    }

    #[test]
    fn pathological_message_alone_is_rejected() {
        // budget = 1 KiB; message > 1 KiB → rejected, queue unchanged.
        let small_budget = 1024;
        let mut entry = RouteEntry::new(TopicMatcher::new("t.*"), "capsule-a".into(), None);
        entry.push_with_eviction(
            ipc_sized("t.alice", Some("alice"), 4096),
            Some("alice".into()),
            small_budget,
        );
        assert_eq!(entry.fanout.len(), 0);
        assert_eq!(entry.total_bytes, 0);
    }

    #[test]
    fn fairness_under_5000_principals_makes_progress() {
        let mut entry = RouteEntry::new(TopicMatcher::new("t.*"), "capsule-a".into(), None);
        for i in 0..5000 {
            let p = format!("p{i}");
            entry.push_with_eviction(ipc("t.x", Some(&p)), Some(p), MAX_SUBSCRIPTION_BUDGET_BYTES);
        }
        let mut out = Vec::new();
        entry.drr_drain(&mut out, MAX_SUBSCRIPTION_BUDGET_BYTES);
        // Every principal had exactly one tiny message; one round
        // should drain all of them under the quantum floor.
        assert_eq!(out.len(), 5000);
        assert_eq!(entry.fanout.len(), 0);
    }

    // ── Self-scope (Option B route-level audit scoping) ──────────────

    #[test]
    fn accepts_predicate_authz_rule() {
        // Scoped to alice: only alice's publisher key is admitted.
        let scoped = RouteEntry::new(
            TopicMatcher::new("t.*"),
            "capsule-a".into(),
            Some(Some("alice".into())),
        );
        assert!(scoped.accepts(&Some("alice".into())));
        assert!(!scoped.accepts(&Some("bob".into())));
        // The system/kernel (None) bucket is foreign to a user-scoped route.
        assert!(!scoped.accepts(&None));

        // Unscoped: every publisher (including system None) is admitted.
        let unscoped = RouteEntry::new(TopicMatcher::new("t.*"), "capsule-a".into(), None);
        assert!(unscoped.accepts(&Some("alice".into())));
        assert!(unscoped.accepts(&Some("bob".into())));
        assert!(unscoped.accepts(&None));
    }

    #[test]
    fn scoped_drops_foreign_at_enqueue() {
        // A route scoped to alice must drop bob's events at enqueue: bob's
        // bytes never enter total_bytes, bob gets no fanout bucket, and a
        // drain yields only alice.
        let mut entry = RouteEntry::new(
            TopicMatcher::new("t.*"),
            "capsule-a".into(),
            Some(Some("alice".into())),
        );
        for _ in 0..3 {
            entry.push_with_eviction(
                ipc("t.x", Some("alice")),
                Some("alice".into()),
                MAX_SUBSCRIPTION_BUDGET_BYTES,
            );
        }
        for _ in 0..5 {
            let evicted = entry.push_with_eviction(
                ipc("t.x", Some("bob")),
                Some("bob".into()),
                MAX_SUBSCRIPTION_BUDGET_BYTES,
            );
            assert_eq!(evicted, 0, "foreign push is a no-op, never evicts");
        }
        // Only alice's bucket exists; bob's bytes never accrued.
        assert_eq!(entry.fanout.len(), 1);
        assert!(entry.fanout.contains_key(&Some("alice".into())));
        assert!(!entry.fanout.contains_key(&Some("bob".into())));

        let mut out = Vec::new();
        entry.drr_drain(&mut out, MAX_SUBSCRIPTION_BUDGET_BYTES);
        assert_eq!(out.len(), 3, "only alice's three events drain");
        for ev in &out {
            if let AstridEvent::Ipc { message, .. } = &**ev {
                assert_eq!(message.principal.as_deref(), Some("alice"));
            }
        }
    }

    #[test]
    fn scoped_budget_not_evictable_by_foreign_burst() {
        // THE Option-B completeness guarantee: a foreign-principal burst far
        // past the budget can NEVER evict the owner's entries, because the
        // foreign bytes never enter the budget in the first place. A
        // drain-time-filter design would FAIL this — bob's bytes would
        // occupy the shared budget and head-evict alice before any filter.
        let payload_size = 64 * 1024;
        let budget = payload_size * 3 + 4096;
        let mut entry = RouteEntry::new(
            TopicMatcher::new("t.*"),
            "capsule-a".into(),
            Some(Some("alice".into())),
        );
        // Alice writes one entry well within budget.
        entry.push_with_eviction(
            ipc_sized("t.alice.keep", Some("alice"), payload_size),
            Some("alice".into()),
            budget,
        );
        // Bob floods far past the budget.
        for _ in 0..100 {
            entry.push_with_eviction(
                ipc_sized("t.bob.flood", Some("bob"), payload_size),
                Some("bob".into()),
                budget,
            );
        }
        // Alice's single entry is intact; bob never entered.
        let alice_q = entry
            .fanout
            .get(&Some("alice".into()))
            .expect("alice queue survives");
        assert_eq!(alice_q.queue.len(), 1, "alice's entry never evicted");
        assert!(!entry.fanout.contains_key(&Some("bob".into())));
        assert_eq!(entry.total_bytes, alice_q.bytes);
    }

    #[test]
    fn alloc_increments_monotonically() {
        let a = SubscriptionRepAllocator::default();
        let n1 = a.next();
        let n2 = a.next();
        assert_eq!(n2, n1.saturating_add(1));
    }
}
