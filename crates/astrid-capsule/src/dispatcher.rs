//! Event dispatcher for routing events to capsule interceptors.
//!
//! The dispatcher is a host-side async task that subscribes to the global
//! `EventBus`, matches incoming events against capsule interceptor patterns
//! (from `Capsule.toml`), and invokes the corresponding WASM
//! `astrid_hook_trigger` export on each matching capsule.
//!
//! # Event Routing
//!
//! The dispatcher handles two categories of events:
//!
//! - **IPC events**: matched by their `topic` field (e.g. `user.prompt`)
//! - **Lifecycle events**: matched by `event_type()` (e.g. `tool_call_started`,
//!   `session_created`). This enables WASM capsules (like the Hook Bridge) to
//!   subscribe to lifecycle events and apply policy (merge strategies, hook
//!   fan-out) on top of the kernel's dispatch mechanism.
//!
//! All dispatch is fire-and-forget from the dispatcher's perspective. Capsules
//! that need request-response semantics (e.g. collecting responses from multiple
//! subscribers) use `hooks::trigger` — the kernel syscall for fan-out with
//! response collection.
//!
//! # Topic Matching
//!
//! Interceptor event patterns support:
//! - Exact match: `user.prompt` matches only `user.prompt`
//! - Single-segment wildcard: `tool.execute.*.result` matches
//!   `tool.execute.search.result` but not `tool.execute.result`

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{RwLock, mpsc};
use tracing::{debug, warn};

use crate::access::CapsuleAccessResolver;
use crate::capsule::{Capsule, CapsuleId};
use crate::dispatcher::locks::{ChainLocks, acquire_chain_lock};
use crate::registry::CapsuleRegistry;
use astrid_events::PrincipalKey;
use astrid_events::{AstridEvent, EventBus, EventReceiver};

mod locks;
mod provision;

/// Capacity of each per-(capsule, principal) event dispatch queue.
///
/// Per-principal partitioning means the working set per queue is much
/// smaller than the legacy per-class queue. A queue full event is dropped
/// with a warning rather than blocking the dispatcher; 64 is generous for
/// per-principal traffic and tightens the worst-case envelope footprint
/// (10k principals × 16 capsules × 64 slots stays under the half-gig
/// ceiling called out in the design's risk register).
const CAPSULE_EVENT_QUEUE_CAPACITY: usize = 64;

/// Maximum number of per-(capsule, principal) dispatcher queues to
/// hold simultaneously **per capsule**. Beyond this cap, new principals
/// for that capsule fall back to a single shared `PrincipalKey::None`
/// queue (with an audit-logged degrade) so the queue map can never grow
/// unboundedly even under a pathological N-principal storm.
const MAX_DISPATCHER_QUEUES_PER_CAPSULE: usize = 10_000;

/// Default idle grace before a per-(capsule, principal) consumer task exits.
///
/// Each consumer awaits `recv()` under this timeout; on timeout the task
/// cleans up its sender from the queue map and exits. The next event for
/// that principal re-spawns the consumer through `or_insert_with`. This
/// mirrors the demand-allocation invariant on the bus's `RouteEntry`
/// fanout and bounds steady-state dispatcher memory at the working set.
const DEFAULT_IDLE_CONSUMER_GRACE_MS: u64 = 60_000;

/// Live override of [`DEFAULT_IDLE_CONSUMER_GRACE_MS`] in milliseconds.
/// Tests collapse the grace to a sub-second value to exercise the
/// idle-eviction path without sleeping in real time. Production uses the
/// 60-second default; the override is `cfg(test)`-only mutated through
/// [`set_idle_consumer_grace_for_test`].
static IDLE_CONSUMER_GRACE_MS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(DEFAULT_IDLE_CONSUMER_GRACE_MS);

/// Current idle-eviction grace, honouring any test override.
fn idle_consumer_grace() -> Duration {
    Duration::from_millis(IDLE_CONSUMER_GRACE_MS.load(std::sync::atomic::Ordering::Relaxed))
}

/// Test hook: collapse the idle-eviction grace to a short interval so
/// the eviction path can be exercised in unit tests without sleeping
/// for a full minute. Public-in-crate; not exposed to consumers.
#[cfg(test)]
pub(crate) fn set_idle_consumer_grace_for_test(ms: u64) {
    IDLE_CONSUMER_GRACE_MS.store(ms, std::sync::atomic::Ordering::Relaxed);
}

/// Shared map of per-(capsule, principal) dispatcher mpsc senders.
/// Wrapped in `parking_lot::Mutex` so the consumer task can remove its
/// own entry under the same lock that admits new principals — this
/// closes the race where an idle-evicting consumer exits between the
/// dispatcher's `entry().or_insert_with(...)` and the subsequent
/// `try_send`.
type CapsuleQueues =
    Arc<parking_lot::Mutex<HashMap<(CapsuleId, PrincipalKey), mpsc::Sender<InterceptorWork>>>>;

/// Work item sent to a per-capsule ordered queue.
struct InterceptorWork {
    action: String,
    payload: Arc<Vec<u8>>,
    topic: Arc<String>,
    /// The originating IPC message, if this event came from IPC.
    /// `None` for lifecycle events. Carried through to
    /// `invoke_interceptor` so the kernel can set per-invocation
    /// principal context on `HostState`.
    ipc_message: Option<Arc<astrid_events::ipc::IpcMessage>>,
}

/// Routes events from the `EventBus` to capsule interceptors.
///
/// Both IPC events (by topic) and lifecycle events (by `event_type()`) are
/// dispatched fire-and-forget. Capsules needing response collection use
/// `hooks::trigger` (the kernel fan-out syscall).
pub struct EventDispatcher {
    registry: Arc<RwLock<CapsuleRegistry>>,
    event_bus: Arc<EventBus>,
    /// Pre-created receiver so the subscription is counted before `run()` is spawned.
    receiver: EventReceiver,
    /// Identity store for validating principals before auto-provisioning.
    /// When set, only principals with a matching identity record get
    /// home directories created. When `None`, provisioning is ungated
    /// (pre-production behavior).
    identity_store: Option<Arc<dyn astrid_storage::IdentityStore>>,
    /// Per-(capsule, principal) chain serialization mutexes.
    /// Chains for the same `(CapsuleId, PrincipalKey)` are mutually
    /// exclusive (FIFO via `tokio::sync::Mutex`) but distinct
    /// principals — even within the same class — run concurrently.
    /// Closes the cross-principal SET/CALL race at the dispatcher
    /// layer in addition to the bus-side routing demux (#813).
    chain_locks: ChainLocks,
    /// Per-principal capsule-access resolver. When set, dispatch of the
    /// **user-invocable surface** (`tool.v1.execute.*`,
    /// `cli.v1.command.run.*`) is filtered to capsules the caller is
    /// granted; admins (`*`) bypass. When `None` (e.g. legacy tests),
    /// the surface is ungated — the kernel always wires the resolver in
    /// production so the security boundary is present at runtime.
    access_resolver: Option<CapsuleAccessResolver>,
    /// The Astrid home under which new principals' home directories are
    /// auto-provisioned. The kernel injects its already-booted home; tests
    /// inject a tempdir home. When `None`, auto-provisioning is disabled
    /// entirely (fail-closed): the dispatcher never resolves a home from
    /// the process environment and never writes to the filesystem —
    /// library dispatch code deciding filesystem roots from ambient env
    /// is how `cargo test` once scaffolded a thousand fixture principals
    /// into a developer's real `~/.astrid` (#1145).
    home: Option<astrid_core::dirs::AstridHome>,
}

impl EventDispatcher {
    /// Create a new event dispatcher.
    ///
    /// Subscribes to the event bus immediately so the subscriber count is
    /// accurate before `run()` is spawned on a background task.
    #[must_use]
    pub fn new(registry: Arc<RwLock<CapsuleRegistry>>, event_bus: Arc<EventBus>) -> Self {
        let receiver = event_bus.subscribe_as("capsule_dispatcher");
        Self {
            registry,
            event_bus,
            receiver,
            identity_store: None,
            chain_locks: Arc::new(parking_lot::RwLock::new(HashMap::new())),
            access_resolver: None,
            home: None,
        }
    }

    /// Set the identity store for principal validation during auto-provisioning.
    #[must_use]
    pub fn with_identity_store(mut self, store: Arc<dyn astrid_storage::IdentityStore>) -> Self {
        self.identity_store = Some(store);
        self
    }

    /// Set the Astrid home under which new principals' home directories
    /// are auto-provisioned.
    ///
    /// The kernel passes its already-booted home at construction; tests
    /// pass a tempdir home and get filesystem isolation for free. Without
    /// this call, auto-provisioning is disabled entirely — the dispatcher
    /// never consults the process environment and never writes to the
    /// filesystem (fail-closed, #1145).
    #[must_use]
    pub fn with_home(mut self, home: astrid_core::dirs::AstridHome) -> Self {
        self.home = Some(home);
        self
    }

    /// Set the per-principal capsule-access resolver.
    ///
    /// Once set, dispatch of the user-invocable surface
    /// (`tool.v1.execute.*`, `cli.v1.command.run.*`) is filtered to the
    /// caller's granted capsules; describe fan-outs are narrowed to the
    /// caller's capsule view. Admins bypass; unknown callers fail closed.
    /// Wired by the kernel at boot, mirroring how the fuel and memory ledgers
    /// are cloned in from the kernel.
    #[must_use]
    pub fn with_access_resolver(mut self, resolver: CapsuleAccessResolver) -> Self {
        self.access_resolver = Some(resolver);
        self
    }

    /// Run the dispatch loop. Blocks until the event bus is closed.
    ///
    /// Subscribes to all events on the bus and routes both IPC events (by topic)
    /// and lifecycle events (by `event_type()`). Should be spawned as a
    /// background tokio task.
    ///
    /// Monitors broadcast channel lag and publishes `astrid.v1.event_bus.lagged`
    /// IPC events when messages are dropped, rate-limited to at most once per
    /// 10 seconds to avoid feedback loops.
    pub async fn run(mut self) {
        let mut last_lag_notification = astrid_runtime::time::Instant::now()
            .checked_sub(std::time::Duration::from_secs(10))
            .unwrap_or_else(astrid_runtime::time::Instant::now);
        // Per-(capsule, principal) ordered queue. Per-principal keying
        // means the dispatcher's worst case at N distinct principals
        // is N independent FIFO consumers, not a single class-keyed
        // queue collapsing the load (#813 Layer 3).
        let capsule_queues: CapsuleQueues = Arc::new(parking_lot::Mutex::new(HashMap::new()));
        // Auto-provisions home directories for newly seen principals under
        // the injected home. With no injected home, provisioning is disabled
        // entirely — no env resolution, no filesystem writes (#1145).
        let mut provisioner =
            provision::PrincipalProvisioner::new(self.home.clone(), self.identity_store.is_some());
        debug!("Event dispatcher started");

        while let Some(event) = self.receiver.recv().await {
            // Check for broadcast channel overflow (lost messages).
            let lagged = self.receiver.drain_lagged();
            if lagged > 0 && last_lag_notification.elapsed() >= std::time::Duration::from_secs(10) {
                warn!(
                    lagged_count = lagged,
                    "Event bus broadcast channel lagged - {lagged} messages dropped"
                );
                last_lag_notification = astrid_runtime::time::Instant::now();

                // Publish a lag notification so capsules can react.
                // Note: This notification is published onto the same bus that just
                // overflowed, so it may itself be dropped under sustained load. This
                // is acceptable - the watchdog timeout is the actual recovery mechanism.
                // The 10s rate limit prevents amplification feedback loops.
                let msg = astrid_events::ipc::IpcMessage::new(
                    astrid_events::ipc::Topic::from_raw("astrid.v1.event_bus.lagged"),
                    astrid_events::ipc::IpcPayload::Custom {
                        data: serde_json::json!({ "lagged_count": lagged }),
                    },
                    uuid::Uuid::new_v4(),
                );
                self.event_bus.publish(AstridEvent::Ipc {
                    metadata: astrid_events::EventMetadata::new("dispatcher"),
                    message: msg,
                });
            }

            let (topic, payload_bytes, ipc_message) = match &*event {
                AstridEvent::Ipc { message, .. } => {
                    // Dispatch-internal topic representation is `Arc<String>`;
                    // the wire `Topic` is rendered to its string here.
                    let topic = Arc::new(message.topic.to_string());
                    match message.payload.to_guest_bytes() {
                        Ok(bytes) => (topic, Arc::new(bytes), Some(Arc::new(message.clone()))),
                        Err(e) => {
                            warn!(topic = %message.topic, error = %e, "Failed to serialize IPC payload");
                            continue;
                        },
                    }
                },
                other => {
                    let topic = Arc::new(other.event_type().to_string());
                    match serde_json::to_vec(other) {
                        Ok(bytes) => (topic, Arc::new(bytes), None),
                        Err(e) => {
                            warn!(event_type = %topic, error = %e, "Failed to serialize lifecycle event");
                            continue;
                        },
                    }
                },
            };

            // Auto-provision home directories for new principals under the
            // injected home (see `dispatcher::provision`).
            provisioner.observe(ipc_message.as_deref().and_then(|m| m.principal.as_deref()));

            // Caller principal (kernel-stamped on the IPC message; `None`
            // for lifecycle events). Threaded into matching so the
            // user-invocable surface can be filtered to the caller's
            // granted capsules — never a caller-supplied claim.
            let caller_principal: Option<&str> =
                ipc_message.as_deref().and_then(|m| m.principal.as_deref());
            let matches = find_matching_interceptors(
                &self.registry,
                &topic,
                caller_principal,
                self.access_resolver.as_ref(),
                &self.event_bus,
            )
            .await;
            dispatch_to_capsule_queues(
                &capsule_queues,
                &self.chain_locks,
                matches,
                topic,
                payload_bytes,
                ipc_message,
            );
        }

        debug!("Event dispatcher stopped (event bus closed)");
    }
}

/// Dispatch matching interceptors for an event.
///
/// Matches at DISTINCT priorities form an ordered middleware chain: called
/// sequentially in priority order (lower fires first), each returning an
/// [`crate::capsule::InterceptResult`] that controls the chain:
/// - `Continue` — pass (possibly modified) payload to the next interceptor
/// - `Final` — short-circuit with a response, no further interceptors fire
/// - `Deny` — short-circuit with denial, audit-logged, no further interceptors fire
///
/// Matches that all share ONE priority have no defined order, so they are an
/// independent fan-out (N capsules each reacting to the same event): each is
/// dispatched on its own per-(capsule, principal) consumer and runs
/// concurrently, with no cross-subscriber short-circuit — one responder's
/// `Final`/`Deny`/error/slowness cannot suppress or stall the others.
///
/// Within a single capsule, events are still delivered in publish order via
/// per-(capsule, principal) mpsc queues (preserving IPC `seq` ordering and
/// isolating principals from one another).
fn dispatch_to_capsule_queues(
    queues: &CapsuleQueues,
    chain_locks: &ChainLocks,
    matches: Vec<(Arc<dyn Capsule>, String, u32)>,
    topic: Arc<String>,
    payload_bytes: Arc<Vec<u8>>,
    ipc_message: Option<Arc<astrid_events::ipc::IpcMessage>>,
) {
    if matches.is_empty() {
        return;
    }

    let principal_key: PrincipalKey = ipc_message.as_deref().and_then(|m| m.principal.clone());

    // For single-interceptor events (common case), skip chain overhead.
    if matches.len() == 1 {
        let (capsule, action, _priority) = matches.into_iter().next().unwrap();
        dispatch_single(
            queues,
            capsule,
            action,
            topic,
            payload_bytes,
            ipc_message,
            principal_key,
        );
        return;
    }

    // Multiple matches at the SAME priority have no defined order between them
    // (the priority sort is arbitrary among equal keys), so they are an
    // independent fan-out — N capsules each reacting to one event — NOT an
    // ordered middleware chain. Dispatch each on its OWN per-(capsule,
    // principal) consumer so they run CONCURRENTLY and no subscriber's outcome
    // (`Final`/`Deny`, an error, or a slow/throttled invocation) can suppress or
    // stall the others. The previous single serial chain task let a slow leading
    // member starve later ones — a 6-way `tool.v1.request.describe` fan-out
    // reached only ~3 of 6 responders before the requester's window elapsed —
    // and its per-(capsule, principal) chain lock made re-firing serialize
    // instead of parallelize. Only a genuinely ORDERED set (members at DISTINCT
    // priorities — an explicit "fire me before you" signal) keeps the
    // sequential, short-circuiting chain below.
    let lead_priority = matches[0].2;
    if matches
        .iter()
        .all(|(_, _, priority)| *priority == lead_priority)
    {
        for (capsule, action, _priority) in matches {
            dispatch_single(
                queues,
                capsule,
                action,
                Arc::clone(&topic),
                Arc::clone(&payload_bytes),
                ipc_message.clone(),
                principal_key.clone(),
            );
        }
        return;
    }

    // Distinct priorities → ordered middleware chain: run sequentially in
    // priority order. Spawned as a task so the dispatcher loop doesn't block.
    let matches_owned: Vec<(Arc<dyn Capsule>, String)> =
        matches.into_iter().map(|(c, a, _)| (c, a)).collect();
    let topic_clone = Arc::clone(&topic);
    let ipc_clone = ipc_message.clone();
    let chain_locks_clone = Arc::clone(chain_locks);
    astrid_runtime::spawn(async move {
        let mut current_payload = (*payload_bytes).clone();

        for (capsule, action) in &matches_owned {
            debug!(
                capsule_id = %capsule.id(),
                action = %action,
                topic = %topic_clone,
                "Dispatching interceptor (chain)"
            );

            // Per-(capsule, principal) chain serialization. Two
            // events with the same principal targeting this capsule
            // execute one-at-a-time (FIFO via tokio::Mutex) so the
            // SET/CALL/CLEAR window in wasm/mod.rs can never race a
            // sibling chain. Distinct principals on the same capsule
            // run concurrently — the orchestration cliff fix is
            // per-principal, not per-class (#813 Layer 3). The guard
            // prunes its map entry on drop so the lock map stays bounded
            // under high principal churn (#828).
            let chain_key = (capsule.id().clone(), principal_key.clone());
            let _chain_guard = acquire_chain_lock(&chain_locks_clone, chain_key).await;

            let caller = ipc_clone.as_deref();
            match capsule
                .invoke_interceptor(action, &current_payload, caller)
                .await
            {
                Ok(crate::capsule::InterceptResult::Continue(modified_payload)) => {
                    debug!(
                        capsule_id = %capsule.id(),
                        action = %action,
                        "Interceptor: Continue"
                    );
                    // If the interceptor returned payload bytes, use them
                    // for the next interceptor in the chain.
                    if !modified_payload.is_empty() {
                        current_payload = modified_payload;
                    }
                },
                Ok(crate::capsule::InterceptResult::Final(response)) => {
                    debug!(
                        capsule_id = %capsule.id(),
                        action = %action,
                        topic = %topic_clone,
                        response_len = response.len(),
                        "Interceptor: Final — chain halted"
                    );
                    return; // Short-circuit — no further interceptors
                },
                Ok(crate::capsule::InterceptResult::Deny { reason }) => {
                    warn!(
                        capsule_id = %capsule.id(),
                        action = %action,
                        topic = %topic_clone,
                        reason = %reason,
                        "Interceptor: Deny — chain halted"
                    );
                    return; // Short-circuit — no further interceptors
                },
                Err(crate::error::CapsuleError::NotSupported(ref msg)) => {
                    debug!(
                        capsule_id = %capsule.id(),
                        action = %action,
                        reason = %msg,
                        "Interceptor skipped (NotSupported)"
                    );
                    // Continue chain — this capsule doesn't participate
                },
                Err(e) => {
                    warn!(
                        capsule_id = %capsule.id(),
                        action = %action,
                        topic = %topic_clone,
                        error = %e,
                        "Interceptor invocation failed — continuing chain"
                    );
                    // Continue chain on error — don't let a broken capsule
                    // block the entire pipeline
                },
            }
        }
    });
}

/// Count how many entries in `queues` have the given `capsule_id` —
/// used to enforce `MAX_DISPATCHER_QUEUES_PER_CAPSULE`. Linear in the
/// number of dispatcher queues, called only on the cold-miss path.
fn queues_per_capsule(
    queues: &HashMap<(CapsuleId, PrincipalKey), mpsc::Sender<InterceptorWork>>,
    capsule_id: &CapsuleId,
) -> usize {
    queues.keys().filter(|(cid, _)| cid == capsule_id).count()
}

/// Get or spawn the per-(capsule, principal) consumer task and return
/// its sender. On the cold-miss path this spawns a new consumer that
/// will idle-evict itself after [`IDLE_CONSUMER_GRACE`] of inactivity.
/// Enforces [`MAX_DISPATCHER_QUEUES_PER_CAPSULE`] by falling back to a
/// single shared `PrincipalKey::None` queue when the cap is exceeded
/// (audit-logged degrade).
fn get_or_spawn_consumer(
    queues: &CapsuleQueues,
    capsule: &Arc<dyn Capsule>,
    key: (CapsuleId, PrincipalKey),
) -> mpsc::Sender<InterceptorWork> {
    let mut guard = queues.lock();
    // Never hand back a CLOSED sender. The mapped entry can be stale: an
    // idle-evicting consumer that exited (or, defensively, a consumer task that
    // ended abnormally) leaves its `Sender` in the map with the receiver gone.
    // Returning it would make every `try_send` fail `Closed` and silently drop
    // events forever — the burst-induced `user.v1.prompt` stall. If the entry
    // is dead, REMOVE it and fall through to re-spawn. The explicit remove
    // matters for the degrade-to-shared path below: that re-keys the insert to
    // `(capsule, None)`, so it would never overwrite a stale
    // `(capsule, Some(principal))` entry — the dead `Sender` and its
    // `PrincipalKey` string would leak and slow `queues_per_capsule`'s scan.
    match guard.get(&key) {
        Some(s) if !s.is_closed() => return s.clone(),
        Some(_) => {
            guard.remove(&key);
        },
        None => {},
    }

    // Cap enforcement — if exceeded, degrade this insert to the
    // shared `(capsule, None)` slot so the queue map can't grow
    // unboundedly under a pathological principal-fanout. The
    // shared slot itself counts toward the cap but is allowed to
    // exist once per capsule.
    let mut effective_key = key.clone();
    if effective_key.1.is_some()
        && queues_per_capsule(&guard, &effective_key.0) >= MAX_DISPATCHER_QUEUES_PER_CAPSULE
    {
        tracing::error!(
            target: "astrid.audit.ipc",
            security_event = true,
            capsule = %effective_key.0,
            principal_key_count = MAX_DISPATCHER_QUEUES_PER_CAPSULE,
            "dispatcher: per-principal queue cap exceeded; degrading to shared queue"
        );
        effective_key.1 = None;
        match guard.get(&effective_key) {
            Some(s) if !s.is_closed() => return s.clone(),
            // A closed shared sender is removed too. The insert below would
            // overwrite it anyway, but removing keeps the handling uniform with
            // the per-principal path and avoids a transient dead entry.
            Some(_) => {
                guard.remove(&effective_key);
            },
            None => {},
        }
    }

    let (tx, rx) = mpsc::channel::<InterceptorWork>(CAPSULE_EVENT_QUEUE_CAPACITY);
    guard.insert(effective_key.clone(), tx.clone());
    drop(guard);

    let capsule_arc = Arc::clone(capsule);
    let queues_arc = Arc::clone(queues);
    let cleanup_key = effective_key.clone();
    astrid_runtime::spawn(async move {
        run_consumer(rx, capsule_arc, queues_arc, cleanup_key).await;
    });
    tx
}

/// Consumer loop for one `(capsule, principal_key)` queue. Idle-evicts
/// itself after [`IDLE_CONSUMER_GRACE`] of inactivity, atomically
/// removing its sender from the queue map under the same lock that
/// `get_or_spawn_consumer` takes — closes the race where an event
/// arrives between timeout and unmap.
async fn run_consumer(
    mut rx: mpsc::Receiver<InterceptorWork>,
    capsule: Arc<dyn Capsule>,
    queues: CapsuleQueues,
    key: (CapsuleId, PrincipalKey),
) {
    loop {
        match astrid_runtime::time::timeout(idle_consumer_grace(), rx.recv()).await {
            Ok(Some(work)) => {
                debug!(
                    capsule_id = %capsule.id(),
                    action = %work.action,
                    topic = %work.topic,
                    "Dispatching interceptor (ordered)"
                );

                let caller = work.ipc_message.as_deref();
                match capsule
                    .invoke_interceptor(&work.action, &work.payload, caller)
                    .await
                {
                    Ok(crate::capsule::InterceptResult::Continue(_)) => {
                        debug!(
                            capsule_id = %capsule.id(),
                            action = %work.action,
                            "Interceptor completed (Continue)"
                        );
                    },
                    Ok(crate::capsule::InterceptResult::Final(_)) => {
                        debug!(
                            capsule_id = %capsule.id(),
                            action = %work.action,
                            "Interceptor completed (Final)"
                        );
                    },
                    Ok(crate::capsule::InterceptResult::Deny { reason }) => {
                        warn!(
                            capsule_id = %capsule.id(),
                            action = %work.action,
                            topic = %work.topic,
                            reason = %reason,
                            "Interceptor: Deny"
                        );
                    },
                    Err(crate::error::CapsuleError::NotSupported(ref msg)) => {
                        debug!(
                            capsule_id = %capsule.id(),
                            action = %work.action,
                            reason = %msg,
                            "Interceptor skipped (NotSupported)"
                        );
                    },
                    Err(e) => {
                        warn!(
                            capsule_id = %capsule.id(),
                            action = %work.action,
                            topic = %work.topic,
                            error = %e,
                            "Interceptor invocation failed"
                        );
                    },
                }
            },
            Ok(None) => {
                // Sender side hung up (capsule unloaded). Drain
                // anything queued and exit. Don't bother cleaning
                // the map entry — the sender is already gone.
                debug!(
                    capsule_id = %capsule.id(),
                    "Per-principal consumer exiting: sender dropped"
                );
                return;
            },
            Err(_elapsed) => {
                // Idle-evict — but only when it is provably safe to drop
                // `rx`, i.e. no queued item AND no other live `Sender`.
                //
                // Holding the `queues` lock across the check stops a NEW
                // `get_or_spawn_consumer` from cloning our sender, but it
                // does NOT stop a `dispatch_single` that already cloned the
                // sender (under an earlier lock acquisition) from calling
                // `try_send` after we remove the entry and drop `rx`: that
                // send would fail and the event would be lost silently
                // (TOCTOU). `sender_strong_count` closes it — the map holds
                // exactly one `Sender` for this key, so a count of 1 means
                // the map's copy is the ONLY sender and no in-flight
                // dispatch can still send. Any in-flight clone bumps the
                // count to ≥2 and we keep running, so the racing `try_send`
                // lands in `rx` and is drained next iteration. The clone's
                // count drops back when that dispatch finishes, so a stale
                // sender can delay eviction by at most one grace window —
                // bounded, and it always errs toward NOT dropping events.
                let mut guard = queues.lock();
                if rx.try_recv().is_err() && rx.sender_strong_count() == 1 {
                    // KNOWN RESIDUAL (bounded, non-correctness): this `remove` is
                    // identity-blind — unlike `ChainLockGuard::drop`'s
                    // `Arc::ptr_eq` guard above, it removes whatever sits at
                    // `key` even if a *newer* consumer generation was cold-spawned
                    // (and re-`insert`ed) for this key in the gap between the
                    // grace timeout firing and this lock acquisition. The
                    // `sender_strong_count()==1` check reads THIS consumer's own
                    // channel, decoupled from the map entry, so it cannot catch
                    // the cross-generation case. Consequence is bounded churn (a
                    // transient orphaned consumer + a re-spawn), NOT event loss:
                    // `get_or_spawn_consumer` skips `is_closed()` senders and
                    // re-spawns, so no dispatch is ever dropped to a reclaimed
                    // generation. A complete root fix would tag each generation
                    // (e.g. an `Arc<()>` stored beside the sender) and only
                    // remove when it matches, mirroring the chain-lock identity
                    // discipline. Tracked separately; left here so the
                    // already-shipped, live-verified detect-and-replace fix is
                    // not entangled with a deeper map-shape change.
                    guard.remove(&key);
                    drop(guard);
                    debug!(
                        capsule_id = %capsule.id(),
                        "Per-principal consumer idle-evicted after grace"
                    );
                    return;
                }
                // Either a racing dispatch landed between the timeout and
                // the map-lock acquisition, or an in-flight dispatch still
                // holds a sender clone that may `try_send` — keep running.
                // The map entry stays valid.
                drop(guard);
            },
        }
    }
}

/// Fast path for single-interceptor dispatch — uses per-(capsule,
/// principal) queue for ordered delivery without chain overhead.
/// Keying on the full `PrincipalKey` (Option<String>) means alice's
/// events don't head-of-line block bob's on the same capsule, even
/// when both fall in the same `PrincipalClass` (#813 Layer 3).
fn dispatch_single(
    queues: &CapsuleQueues,
    capsule: Arc<dyn Capsule>,
    action: String,
    topic: Arc<String>,
    payload_bytes: Arc<Vec<u8>>,
    ipc_message: Option<Arc<astrid_events::ipc::IpcMessage>>,
    principal_key: PrincipalKey,
) {
    let key = (capsule.id().clone(), principal_key);
    let sender = get_or_spawn_consumer(queues, &capsule, key.clone());

    let work = InterceptorWork {
        action,
        payload: Arc::clone(&payload_bytes),
        topic: Arc::clone(&topic),
        ipc_message: ipc_message.clone(),
    };
    match sender.try_send(work) {
        Ok(()) => {},
        Err(mpsc::error::TrySendError::Closed(work)) => {
            // The consumer idle-evicted in the window between
            // `get_or_spawn_consumer` cloning its sender and this send. The
            // `sender_strong_count` guard in `run_consumer` narrows that TOCTOU
            // but cannot fully close it under a concurrent burst: a stale clone
            // can outlive the count==1 check, so a send can still land on a
            // just-closed channel. Eviction is benign (the queue was idle), so
            // re-spawn a fresh consumer and retry ONCE — the event must not be
            // lost to a race against reclamation. (Symptom: a `user.v1.prompt`
            // stall under a 100-wide prompt burst — the route's consumer closed
            // and every later prompt was dropped.) The re-spawn just spawned its
            // consumer, so the retry cannot hit the same race.
            let sender = get_or_spawn_consumer(queues, &capsule, key);
            match sender.try_send(work) {
                Ok(()) => {},
                // `Full` after a fresh re-spawn is the same intended shed-load
                // drop as the steady-state arm below: the new consumer is alive
                // but its bounded queue saturated under the ongoing burst.
                // Recoverable via the requester's IPC/SSE timeout.
                Err(e @ mpsc::error::TrySendError::Full(_)) => {
                    warn!(
                        capsule_id = %capsule.id(),
                        topic = %topic,
                        "Capsule dispatch queue full after re-spawn, dropping event (backpressure): {e}"
                    );
                },
                // `Closed` immediately after we spawned a fresh consumer is a
                // BUG, not backpressure — it would break the "Closed is never
                // dropped" invariant. Flag it as a security/correctness event
                // rather than folding it into the benign backpressure log.
                Err(e @ mpsc::error::TrySendError::Closed(_)) => {
                    warn!(
                        capsule_id = %capsule.id(),
                        topic = %topic,
                        security_event = true,
                        "BUG: capsule dispatch sender closed immediately after re-spawn; event dropped: {e}"
                    );
                },
            }
        },
        Err(e @ mpsc::error::TrySendError::Full(_)) => {
            // Genuine backpressure: the consumer is alive but its bounded queue
            // is saturated. Dropping is the intended shed-load behaviour (a
            // slow/looping consumer must not let the queue grow without bound).
            warn!(
                capsule_id = %capsule.id(),
                topic = %topic,
                "Capsule dispatch queue full, dropping event (backpressure): {e}"
            );
        },
    }
}

/// Find all capsules with interceptors matching the given topic.
///
/// Takes a brief read lock on the registry. Only `Ready` capsules are
/// considered. Returns `(capsule, action, priority)` tuples sorted by
/// interceptor priority (lower values fire first, default 100). The priority is
/// returned so the caller can distinguish an ordered chain (distinct
/// priorities) from an independent fan-out (all equal).
///
/// # Per-principal capsule-access filter
///
/// When an `access_resolver` is wired, principal-stamped non-admin dispatch is
/// first narrowed to the caller's capsule view. When `topic` is also in the
/// **user-invocable surface** (`tool.v1.execute.*`, `cli.v1.command.run.*`),
/// a matched capsule is kept only if `caller_principal` is granted it (or is an
/// admin holding `*`). The grant-on-use filter is keyed on the **topic**, so a
/// dual-role capsule's orchestration interceptors (on non-tool topics) are
/// view-scoped but not grant-gated.
///
/// The gate engages **only for capsules whose subscription actually matches the
/// dispatched topic**. The cheap, manifest-local interceptor match is evaluated
/// first (using the same [`crate::topic::topic_matches`] delivery uses), and a
/// capsule that provides no interceptor for `topic` never reaches the access
/// gate — so a single tool call cannot storm `GrantRequired` across every
/// ungranted capsule in the view (#1113). Only a capsule that *would* be
/// delivered the call is gated.
///
/// For an **authenticated, non-admin** caller a denied match is no longer a
/// pure silent drop: before dropping, a [`IpcPayload::GrantRequired`] signal is
/// published on `astrid.v1.approval` (grant-on-first-use, #998) so a broker/shim
/// can elicit consent and, on approve, the kernel grants the capsule. The match
/// is still dropped for THIS call (the capsule never sees the ungranted call);
/// the caller's request simply finds no tool, exactly as if the capsule were not
/// installed. A `None`/empty/`anonymous` caller (no authenticated principal to
/// grant to) is still a pure silent drop with no signal.
async fn find_matching_interceptors(
    registry: &RwLock<CapsuleRegistry>,
    topic: &str,
    caller_principal: Option<&str>,
    access_resolver: Option<&CapsuleAccessResolver>,
    event_bus: &EventBus,
) -> Vec<(Arc<dyn crate::capsule::Capsule>, String, u32)> {
    // Compute the gate once per event, not per capsule. Principal-stamped
    // dispatch is view-scoped when a resolver is present; grant-on-use only
    // engages for the narrower user-invocable surface.
    let gate_surface = crate::access::is_user_invocable_surface(topic);
    let view_scoped_surface = access_resolver.is_some()
        && (gate_surface
            || topic == "tool.v1.request.describe"
            || topic == "llm.v1.request.describe");
    let registry = registry.read().await;
    let mut matches: Vec<(Arc<dyn crate::capsule::Capsule>, String, u32)> = Vec::new();
    // Dedup grant-on-use signals within a single dispatch pass. This stays
    // tiny in practice, so a Vec keeps the gate path simple.
    let mut grant_signalled: Vec<String> = Vec::new();
    let caller_pid = caller_principal.and_then(|p| astrid_core::PrincipalId::new(p).ok());
    let view_scoped_admin = view_scoped_surface
        && access_resolver.is_some_and(|resolver| resolver.is_admin(caller_principal));
    let candidate_capsules = candidate_capsules_for_dispatch(
        &registry,
        caller_pid.as_ref(),
        access_resolver.is_some(),
        view_scoped_surface,
        view_scoped_admin,
    );

    for capsule in candidate_capsules {
        if !matches!(capsule.state(), crate::capsule::CapsuleState::Ready) {
            continue;
        }
        // Resolve the capsule's matching interceptors FIRST (#1113). The
        // subscription match is cheap and manifest-local; evaluating it before
        // the access gate means the grant-on-use gate — and its
        // `GrantRequired` emit — engages only for a capsule that actually
        // provides an interceptor for THIS topic. Without this ordering a
        // single tool call storms `GrantRequired` across every ungranted
        // capsule in the caller's view, regardless of what the call touched.
        //
        // RFC cargo-like-manifest: `effective_interceptors()` reads the
        // `[subscribe].handler` bindings (new-form entries get the default
        // priority, 100). The matcher is the SAME `crate::topic::topic_matches`
        // the delivery push below uses — the gate and delivery must never
        // diverge, or a matching capsule could be gated by one matcher and
        // delivered by another.
        let mut capsule_matches: Vec<(String, u32)> = Vec::new();
        for interceptor in capsule.manifest().effective_interceptors() {
            if crate::topic::topic_matches(topic, &interceptor.event) {
                capsule_matches.push((interceptor.action, interceptor.priority));
            }
        }
        // A capsule that provides no interceptor for this topic never reaches
        // the gate: it simply does not match, exactly as before.
        if capsule_matches.is_empty() {
            continue;
        }
        // Per-principal access gate for the user-invocable surface, now scoped
        // to capsules that DO match the topic. Fail-closed: with the gate
        // engaged and a resolver wired, an ungranted (or unknown/anonymous)
        // caller drops this capsule's matching interceptors entirely — the
        // capsule never sees the ungranted call.
        if gate_surface
            && let Some(resolver) = access_resolver
            && !resolver.is_capsule_allowed(caller_principal, capsule.id())
        {
            // Grant-on-first-use (#998): for an authenticated non-admin
            // caller, emit a `GrantRequired` signal before dropping. The
            // grant TARGET is the kernel-stamped caller + this capsule —
            // never any caller-supplied claim. Skip a `None`/empty/
            // `anonymous` principal (no authenticated principal to grant).
            if let Some(principal) = caller_principal
                && !principal.is_empty()
                && principal != "anonymous"
            {
                let capsule_key = capsule.id().to_string();
                if !grant_signalled.contains(&capsule_key) {
                    grant_signalled.push(capsule_key.clone());
                    crate::access::emit_grant_required(event_bus, principal, capsule_key);
                }
            }
            continue;
        }
        for (action, priority) in capsule_matches {
            matches.push((Arc::clone(&capsule), action, priority));
        }
    }
    // Sort by priority (lower fires first), then by capsule id and action as a
    // STABLE tiebreak so equal-priority members have a deterministic order.
    // `registry.list()` iterates a HashMap (arbitrary per run), so a
    // priority-only sort left ties (e.g. a mixed chain `[10, 20, 20]`) in
    // non-deterministic order — which matters in the ordered-chain path, where a
    // tied member's `Final`/`Deny` short-circuits its sibling. (An all-equal set
    // dispatches concurrently, so order is irrelevant there, but a stable order
    // keeps dispatch reproducible everywhere.) Priority rides along in the
    // returned tuple so dispatch can distinguish an ordered chain (distinct
    // priorities) from an independent fan-out (all equal).
    matches.sort_by(|(a_cap, a_act, a_pri), (b_cap, b_act, b_pri)| {
        a_pri
            .cmp(b_pri)
            .then_with(|| a_cap.id().as_str().cmp(b_cap.id().as_str()))
            .then_with(|| a_act.cmp(b_act))
    });
    matches
}

fn candidate_capsules_for_dispatch(
    registry: &CapsuleRegistry,
    caller_pid: Option<&astrid_core::PrincipalId>,
    has_access_resolver: bool,
    view_scoped_surface: bool,
    view_scoped_admin: bool,
) -> Vec<Arc<dyn crate::capsule::Capsule>> {
    if view_scoped_surface && !view_scoped_admin {
        return caller_pid.map_or_else(Vec::new, |principal| registry.cloned_values_for(principal));
    }

    if has_access_resolver
        && !view_scoped_admin
        && let Some(principal) = caller_pid
    {
        return registry.cloned_values_for(principal);
    }

    registry
        .list_any()
        .into_iter()
        .filter_map(|id| registry.get_any(id))
        .collect()
}

#[cfg(test)]
#[path = "dispatcher_tests.rs"]
mod tests;
