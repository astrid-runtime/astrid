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

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use tokio::sync::{RwLock, mpsc};
use tracing::{debug, warn};

use crate::capsule::{Capsule, CapsuleId};
use crate::registry::CapsuleRegistry;
use astrid_events::{AstridEvent, EventBus, EventReceiver};

/// Capacity of each per-capsule event dispatch queue.
///
/// If a capsule's queue fills up (i.e. it is processing events slower than
/// they arrive), new events are dropped with a warning rather than blocking
/// the dispatcher. 256 is generous for typical usage.
const CAPSULE_EVENT_QUEUE_CAPACITY: usize = 256;

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
        }
    }

    /// Set the identity store for principal validation during auto-provisioning.
    #[must_use]
    pub fn with_identity_store(mut self, store: Arc<dyn astrid_storage::IdentityStore>) -> Self {
        self.identity_store = Some(store);
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
        let mut last_lag_notification = std::time::Instant::now()
            .checked_sub(std::time::Duration::from_secs(10))
            .unwrap_or_else(std::time::Instant::now);
        let mut capsule_queues: HashMap<CapsuleId, mpsc::Sender<InterceptorWork>> = HashMap::new();
        let mut known_principals: HashSet<String> = HashSet::new();
        // The "default" principal is always provisioned by the kernel boot sequence.
        known_principals.insert("default".to_string());
        /// Maximum number of principals tracked before the set stops growing.
        /// 10K principals = ~640KB of memory (64-byte strings). Beyond this,
        /// new principals are still dispatched but not cached — they'll hit
        /// the filesystem check on every event instead of the O(1) HashSet.
        const MAX_KNOWN_PRINCIPALS: usize = 10_000;
        debug!("Event dispatcher started");

        while let Some(event) = self.receiver.recv().await {
            // Check for broadcast channel overflow (lost messages).
            let lagged = self.receiver.drain_lagged();
            if lagged > 0 && last_lag_notification.elapsed() >= std::time::Duration::from_secs(10) {
                warn!(
                    lagged_count = lagged,
                    "Event bus broadcast channel lagged - {lagged} messages dropped"
                );
                last_lag_notification = std::time::Instant::now();

                // Publish a lag notification so capsules can react.
                // Note: This notification is published onto the same bus that just
                // overflowed, so it may itself be dropped under sustained load. This
                // is acceptable - the watchdog timeout is the actual recovery mechanism.
                // The 10s rate limit prevents amplification feedback loops.
                let msg = astrid_events::ipc::IpcMessage::new(
                    "astrid.v1.event_bus.lagged",
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
                    let topic = Arc::new(message.topic.clone());
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

            // Auto-provision home directories for new principals.
            // When an identity store is configured, only the "default"
            // principal is auto-provisioned. Other principals must be
            // explicitly created via the identity flow (uplink calls
            // create_user → AstridUserId with principal → uplink sets
            // principal on IPC). This prevents unauthenticated directory
            // creation from arbitrary IPC principal strings.
            if let Some(ref msg) = ipc_message
                && let Some(ref principal_str) = msg.principal
                && !known_principals.contains(principal_str)
            {
                if let Ok(pid) = astrid_core::PrincipalId::new(principal_str) {
                    // Gate: if identity store is wired, only auto-provision
                    // "default". Other principals are created by uplinks
                    // which handle home provisioning after create_user.
                    let should_provision =
                        self.identity_store.is_none() || pid == astrid_core::PrincipalId::default();

                    if should_provision && let Ok(home) = astrid_core::dirs::AstridHome::resolve() {
                        let ph = home.principal_home(&pid);
                        if let Err(e) = ph.ensure() {
                            // Don't cache — allow retry on next event (#544).
                            warn!(
                                principal = %pid,
                                error = %e,
                                "Failed to auto-provision principal home"
                            );
                        } else {
                            debug!(
                                principal = %pid,
                                "Auto-provisioned principal home directory"
                            );
                            // Only cache on success so transient failures
                            // can retry on the next event (#544).
                            if known_principals.len() < MAX_KNOWN_PRINCIPALS {
                                known_principals.insert(principal_str.clone());
                            }
                        }
                    }
                    // If AstridHome::resolve() failed, don't cache — allow
                    // retry when the home directory becomes available.
                } else {
                    warn!(
                        principal = %principal_str,
                        "IPC message has invalid principal string, ignoring"
                    );
                }
            }

            let matches = find_matching_interceptors(&self.registry, &topic).await;
            dispatch_to_capsule_queues(
                &mut capsule_queues,
                matches,
                topic,
                payload_bytes,
                ipc_message,
            );
        }

        debug!("Event dispatcher stopped (event bus closed)");
    }
}

/// Dispatch matching interceptors as a middleware chain.
///
/// Interceptors are called sequentially in priority order (lower fires first).
/// Each interceptor returns an [`InterceptResult`] that controls the chain:
/// - `Continue` — pass (possibly modified) payload to the next interceptor
/// - `Final` — short-circuit with a response, no further interceptors fire
/// - `Deny` — short-circuit with denial, audit-logged, no further interceptors fire
///
/// Within a single capsule, events are still delivered in publish order via
/// per-capsule mpsc queues (preserving IPC `seq` ordering). The chain semantics
/// apply across capsules for the same event.
fn dispatch_to_capsule_queues(
    queues: &mut HashMap<CapsuleId, mpsc::Sender<InterceptorWork>>,
    matches: Vec<(Arc<dyn Capsule>, String)>,
    topic: Arc<String>,
    payload_bytes: Arc<Vec<u8>>,
    ipc_message: Option<Arc<astrid_events::ipc::IpcMessage>>,
) {
    if matches.is_empty() {
        return;
    }

    // Clone what we need for the spawned chain task.
    let matches_owned: Vec<_> = matches
        .into_iter()
        .map(|(c, a)| (Arc::clone(&c), a))
        .collect();

    // For single-interceptor events (common case), skip chain overhead.
    if matches_owned.len() == 1 {
        let (capsule, action) = matches_owned.into_iter().next().unwrap();
        dispatch_single(queues, capsule, action, topic, payload_bytes, ipc_message);
        return;
    }

    // Multi-interceptor chain: run sequentially in priority order.
    // Spawned as a task so the dispatcher loop doesn't block.
    let topic_clone = Arc::clone(&topic);
    let ipc_clone = ipc_message.clone();
    tokio::task::spawn(async move {
        let mut current_payload = (*payload_bytes).clone();

        for (capsule, action) in &matches_owned {
            debug!(
                capsule_id = %capsule.id(),
                action = %action,
                topic = %topic_clone,
                "Dispatching interceptor (chain)"
            );
            // Bound concurrent invokes of THIS capsule. The permit is
            // re-acquired per chain step because each step is a separate
            // `invoke_interceptor` call and Wasmtime Store contention is
            // per-call; chains across distinct capsules don't share a
            // permit pool. `acquire_owned()` only fails when the
            // semaphore is closed (capsule unloaded); treat as benign
            // and tear down the chain.
            let wait_start = std::time::Instant::now();
            let _permit = match capsule
                .interceptor_semaphore()
                .clone()
                .acquire_owned()
                .await
            {
                Ok(p) => p,
                Err(_) => {
                    debug!(
                        capsule_id = %capsule.id(),
                        "interceptor permit acquire failed (semaphore closed); \
                         capsule likely unloading"
                    );
                    return;
                },
            };
            metrics::histogram!(
                "astrid_capsule_interceptor_permit_wait_seconds_total",
                "capsule" => capsule.id().to_string(),
            )
            .record(wait_start.elapsed().as_secs_f64());

            let caller = ipc_clone.as_deref();
            match capsule.invoke_interceptor(action, &current_payload, caller) {
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

/// Fast path for single-interceptor dispatch — uses per-capsule queue
/// for ordered delivery without chain overhead.
fn dispatch_single(
    queues: &mut HashMap<CapsuleId, mpsc::Sender<InterceptorWork>>,
    capsule: Arc<dyn Capsule>,
    action: String,
    topic: Arc<String>,
    payload_bytes: Arc<Vec<u8>>,
    ipc_message: Option<Arc<astrid_events::ipc::IpcMessage>>,
) {
    let sender = queues.entry(capsule.id().clone()).or_insert_with(|| {
        let (tx, mut rx) = mpsc::channel::<InterceptorWork>(CAPSULE_EVENT_QUEUE_CAPACITY);
        let capsule = Arc::clone(&capsule);
        tokio::task::spawn(async move {
            while let Some(work) = rx.recv().await {
                debug!(
                    capsule_id = %capsule.id(),
                    action = %work.action,
                    topic = %work.topic,
                    "Dispatching interceptor (ordered)"
                );
                // Bound concurrent invokes of THIS capsule. `continue`
                // (not `return`) on a closed semaphore so a transient
                // closure during hot-reload doesn't tear down the
                // consumer loop for the replacement capsule.
                let wait_start = std::time::Instant::now();
                let _permit = match capsule
                    .interceptor_semaphore()
                    .clone()
                    .acquire_owned()
                    .await
                {
                    Ok(p) => p,
                    Err(_) => {
                        debug!(
                            capsule_id = %capsule.id(),
                            "interceptor permit acquire failed (semaphore closed); \
                             capsule likely unloading"
                        );
                        continue;
                    },
                };
                metrics::histogram!(
                    "astrid_capsule_interceptor_permit_wait_seconds_total",
                    "capsule" => capsule.id().to_string(),
                )
                .record(wait_start.elapsed().as_secs_f64());

                let caller = work.ipc_message.as_deref();
                match capsule.invoke_interceptor(&work.action, &work.payload, caller) {
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
            }
        });
        tx
    });

    let work = InterceptorWork {
        action,
        payload: Arc::clone(&payload_bytes),
        topic: Arc::clone(&topic),
        ipc_message: ipc_message.clone(),
    };
    if let Err(e) = sender.try_send(work) {
        warn!(
            capsule_id = %capsule.id(),
            topic = %topic,
            "Capsule dispatch queue full or closed, dropping event: {e}"
        );
    }
}

/// Find all capsules with interceptors matching the given topic.
///
/// Takes a brief read lock on the registry. Only `Ready` capsules are
/// considered. Returns `(capsule, action)` pairs sorted by interceptor
/// priority (lower values fire first, default 100).
async fn find_matching_interceptors(
    registry: &RwLock<CapsuleRegistry>,
    topic: &str,
) -> Vec<(Arc<dyn crate::capsule::Capsule>, String)> {
    let registry = registry.read().await;
    let mut matches: Vec<(Arc<dyn crate::capsule::Capsule>, String, u32)> = Vec::new();
    for capsule_id in registry.list() {
        if let Some(capsule) = registry.get(capsule_id) {
            if !matches!(capsule.state(), crate::capsule::CapsuleState::Ready) {
                continue;
            }
            // RFC cargo-like-manifest: read effective interceptors
            // — [subscribe].handler entries merged with legacy
            // [[interceptor]] blocks. Legacy entries keep their declared
            // priority; new-form entries get the default (100).
            for interceptor in capsule.manifest().effective_interceptors() {
                if crate::topic::topic_matches(topic, &interceptor.event) {
                    matches.push((
                        Arc::clone(&capsule),
                        interceptor.action,
                        interceptor.priority,
                    ));
                }
            }
        }
    }
    // Sort by priority — lower values fire first.
    matches.sort_by_key(|(_, _, priority)| *priority);
    matches
        .into_iter()
        .map(|(capsule, action, _)| (capsule, action))
        .collect()
}

#[cfg(test)]
#[path = "dispatcher_tests.rs"]
mod tests;
