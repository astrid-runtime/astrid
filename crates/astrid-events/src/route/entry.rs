//! `RouteEntry` state machine: per-route fan-out, DRR drain, and
//! oldest-head eviction under the global byte budget.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
// `web_time::Instant` = `std::time::Instant` on native; JS performance
// clock on wasm32-unknown-unknown (std's panics there at runtime).
use web_time::Instant;

use tokio::sync::Notify;
use uuid::Uuid;

use crate::event::AstridEvent;
use crate::ipc::RequestOwnerId;
use crate::route::RouteAdmissionGate;
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

/// Defence-in-depth message-count cap per principal sub-queue. The 1 `MiB`
/// byte budget ([`MAX_SUBSCRIPTION_BUDGET_BYTES`]) is the primary admission
/// control; this only stops a flood of tiny (near-0-byte) messages from
/// monopolising a bucket *without* ever tripping that byte budget.
///
/// Sized to admit a legitimate high-rate token stream. An LLM provider
/// emitting one small event per token at ~2000 tok/s produces thousands of
/// tiny messages in a ~1-2s burst — collectively far under the 1 `MiB` byte
/// budget (a 73 `KiB` response is ~80 `KiB` of deltas). At 256 those bursts
/// overran the sub-queue and dropped the oldest events, which silently
/// corrupted a streamed response (dropped interior tokens) or hung the
/// consuming turn outright (a dropped terminal `Done` that react waits on
/// forever). For real (non-empty) deltas the 1 `MiB` byte budget
/// ([`MAX_SUBSCRIPTION_BUDGET_BYTES`]) binds *first* — it trips long before a
/// bucket reaches this count — so the count cap only ever governs a flood of
/// near-0-byte messages the byte budget cannot see. Each queued slot is an
/// `Arc` handle (~8 B), but the `Arc` keeps the whole `AstridEvent` allocation
/// alive, so the true retained heap of such a flood is this cap × per-event
/// struct overhead — on the order of a few `MiB` per bucket, not a few `KiB`.
/// Still bounded per bucket, but the message count is a coarse proxy for
/// memory; a proper memory-based bound for the near-0-byte case is tracked in
/// #1159.
pub(crate) const PENDING_PER_PRINCIPAL_FALLBACK: usize = 16_384;

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

#[derive(Debug)]
enum RouteAdmission {
    All,
    Exact(PrincipalKey),
    PrincipalOrSystem(String),
}

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
    /// the 1 `MiB` byte budget and the per-principal message-count cap
    /// ([`PENDING_PER_PRINCIPAL_FALLBACK`]) to the owner's OWN bucket, so if the
    /// owner publishes faster than the consumer drains, the owner's OWN oldest
    /// entries can still self-evict (host `tracing::error!`/metric only — no
    /// in-band guest signal). A completeness-critical consumer (e.g. an
    /// audit-to-blockchain mint pipeline) must therefore drain promptly or
    /// treat the persisted audit log (`append_with_principal`) as the source of
    /// truth, not the live bus feed. In-band drop-signalling / log
    /// reconciliation is a future (Phase 2) concern.
    scope: RouteAdmission,
    /// Optional authenticated request owner required at enqueue.
    ///
    /// Same-principal peer traffic is rejected before it can consume this
    /// route's byte budget.
    request_owner: Option<RequestOwnerId>,
    /// Private delivery receipts are admitted only for this route owner.
    receipt_publisher: Option<Uuid>,
    /// Runtime-generation publication fence shared by all of its routes.
    gate: RouteAdmissionGate,
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
            scope: scope.map_or(RouteAdmission::All, RouteAdmission::Exact),
            request_owner: None,
            receipt_publisher: None,
            gate: RouteAdmissionGate::default(),
            notify: Arc::new(Notify::new()),
        }
    }

    /// Construct a route that admits one principal plus kernel/system events.
    pub(crate) fn new_principal_or_system(
        matcher: TopicMatcher,
        capsule_id_label: String,
        principal: String,
    ) -> Self {
        Self {
            matcher,
            fanout: HashMap::new(),
            principal_order: VecDeque::new(),
            total_bytes: 0,
            capsule_id_label,
            scope: RouteAdmission::PrincipalOrSystem(principal),
            request_owner: None,
            receipt_publisher: None,
            gate: RouteAdmissionGate::default(),
            notify: Arc::new(Notify::new()),
        }
    }

    pub(crate) fn with_receipt_publisher(mut self, publisher: Uuid) -> Self {
        self.receipt_publisher = Some(publisher);
        self
    }

    pub(crate) fn with_gate(mut self, gate: RouteAdmissionGate) -> Self {
        self.gate = gate;
        self
    }

    pub(crate) fn with_request_owner(mut self, request_owner: RequestOwnerId) -> Self {
        self.request_owner = Some(request_owner);
        self
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
        if !self.gate.is_published() {
            return false;
        }
        match &self.scope {
            RouteAdmission::All => true,
            RouteAdmission::Exact(expected) => expected == publisher,
            RouteAdmission::PrincipalOrSystem(expected) => {
                publisher.as_ref().is_none_or(|actual| actual == expected)
            },
        }
    }

    pub(crate) fn accepts_event(&self, publisher: &PrincipalKey, event: &AstridEvent) -> bool {
        if !self.accepts(publisher) {
            return false;
        }
        if let (Some(owner), AstridEvent::Ipc { message, .. }) = (self.receipt_publisher, event)
            && !crate::ipc::delivery_failure::visible_to(message, owner)
        {
            return false;
        }
        let Some(expected_owner) = self.request_owner else {
            return true;
        };
        matches!(
            event,
            AstridEvent::Ipc { message, .. }
                if message.request_owner == Some(expected_owner)
        )
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
        if !self.accepts_event(&principal, &event) {
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

#[cfg(test)]
#[path = "entry_tests.rs"]
mod tests;
