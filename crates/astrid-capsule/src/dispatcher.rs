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
//!
//! # Per-principal view scoping (issue #1069)
//!
//! Matching ([`find_matching_interceptors`]) chooses the candidate capsule set
//! by topic class:
//!
//! - On the **view-scoped surface** (`is_view_scoped_surface` — tool execute,
//!   CLI command execute, and tool-describe) with a real authenticated caller,
//!   matching iterates ONLY that caller's per-principal registry view. A
//!   capsule absent from the caller's view is invisible, full stop — the
//!   fail-closed floor. An unknown/unprovisioned/invalid/`anonymous` caller
//!   resolves to an EMPTY view, so nothing matches; there is **no fallback to
//!   any other principal's view** (a silent default fallback would be the
//!   cross-tenant break this whole change closes).
//! - On every other topic — the internal orchestration mesh and tool-result
//!   delivery — matching iterates the GLOBAL instance set (`all_instances`),
//!   so the mesh stays global and routing never wedges.
//!
//! The existing per-principal grant gate ([`CapsuleAccessResolver`]) applies
//! **on top** of the view, and only for the narrower grant-gated surface
//! ([`crate::access::is_user_invocable_surface`] — execute/CLI, not describe):
//! view FIRST (a capsule outside the view is never even considered), grant
//! SECOND (an in-view-but-ungranted capsule is dropped, with a
//! grant-on-first-use signal for an authenticated non-admin caller).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{RwLock, mpsc};
use tracing::{debug, warn};

use crate::access::CapsuleAccessResolver;
use crate::capsule::{Capsule, CapsuleId};
use crate::registry::CapsuleRegistry;
use astrid_events::PrincipalKey;
use astrid_events::{AstridEvent, EventBus, EventReceiver};

#[path = "dispatcher_queues.rs"]
mod queues;
use queues::{CapsuleQueues, ChainLocks, dispatch_to_capsule_queues};

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
    /// **grant-gated surface** (`tool.v1.execute.*`,
    /// `cli.v1.command.execute`) is filtered to capsules the caller is
    /// granted; admins (`*`) bypass. When `None` (e.g. legacy tests),
    /// the grant gate is off — the kernel always wires the resolver in
    /// production so the security boundary is present at runtime. Note
    /// the per-principal VIEW floor (#1069) applies independently of the
    /// resolver: even with `None`, view-scoped topics only reach the
    /// caller's view.
    access_resolver: Option<CapsuleAccessResolver>,
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
        }
    }

    /// Set the identity store for principal validation during auto-provisioning.
    #[must_use]
    pub fn with_identity_store(mut self, store: Arc<dyn astrid_storage::IdentityStore>) -> Self {
        self.identity_store = Some(store);
        self
    }

    /// Set the per-principal capsule-access resolver.
    ///
    /// Once set, dispatch of the grant-gated surface
    /// (`tool.v1.execute.*`, `cli.v1.command.execute`) is filtered to the
    /// caller's granted capsules (admins bypass; fail-closed for unknown
    /// callers). Wired by the kernel at boot, mirroring how the fuel and
    /// memory ledgers are cloned in from the kernel. The per-principal view
    /// floor (#1069) is enforced regardless of the resolver.
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
        let mut last_lag_notification = std::time::Instant::now()
            .checked_sub(std::time::Duration::from_secs(10))
            .unwrap_or_else(std::time::Instant::now);
        // Per-(capsule, principal) ordered queue. Per-principal keying
        // means the dispatcher's worst case at N distinct principals
        // is N independent FIFO consumers, not a single class-keyed
        // queue collapsing the load (#813 Layer 3).
        let capsule_queues: CapsuleQueues = Arc::new(parking_lot::Mutex::new(HashMap::new()));
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

            // Caller principal (kernel-stamped on the IPC message; `None`
            // for lifecycle events). Threaded into matching so the
            // view-scoped surface can be scoped to the caller's per-principal
            // view and the grant-gated surface filtered to the caller's
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

/// Resolve the candidate capsule set for an event, applying the per-principal
/// VIEW floor (#1069) BEFORE any grant gate.
///
/// - **View-scoped surface** (`is_view_scoped_surface`): a real authenticated
///   caller scopes to ONLY its per-principal view (`cloned_values(caller)`). An
///   absent / empty / `anonymous` / syntactically-invalid principal yields an
///   EMPTY set — fail-closed, with **no fallback to any other principal's
///   view**. This is the cross-tenant floor: a capsule outside the caller's
///   view is never even a candidate, so it can never be matched, described, or
///   dispatched, and the grant gate downstream never even sees it (so it cannot
///   leak a capsule's existence via a `GrantRequired`).
/// - **Everything else** (the orchestration mesh, tool-result delivery,
///   lifecycle): the GLOBAL instance set (`all_instances`). The mesh stays
///   global or routing wedges.
fn candidate_capsules(
    registry: &CapsuleRegistry,
    topic: &str,
    caller_principal: Option<&str>,
) -> Vec<Arc<dyn Capsule>> {
    if !crate::access::is_view_scoped_surface(topic) {
        // Mesh / lifecycle / result-delivery: global, unchanged.
        return registry.all_instances();
    }

    // View-scoped surface: fail-closed to the caller's own view. An absent,
    // empty, or `anonymous` caller has no authenticated principal to scope to,
    // so the candidate set is EMPTY — never default's view.
    let Some(principal_str) = caller_principal else {
        return Vec::new();
    };
    if principal_str.is_empty() || principal_str == "anonymous" {
        return Vec::new();
    }
    // A syntactically invalid principal likewise resolves to an empty view —
    // fail-closed, never a fallback. (The dispatcher already logged the invalid
    // string when it skipped auto-provisioning; no second warn needed here.)
    let Ok(pid) = astrid_core::PrincipalId::new(principal_str) else {
        return Vec::new();
    };
    // The view floor: ONLY the capsules this principal can see. An unknown /
    // unprovisioned principal has no view entry, so `cloned_values` returns an
    // empty Vec — no match, no default fallback.
    registry.cloned_values(&pid)
}

/// Find all capsules with interceptors matching the given topic.
///
/// Takes a brief read lock on the registry. Only `Ready` capsules are
/// considered. Returns `(capsule, action, priority)` tuples sorted by
/// interceptor priority (lower values fire first, default 100). The priority is
/// returned so the caller can distinguish an ordered chain (distinct
/// priorities) from an independent fan-out (all equal).
///
/// # Per-principal view floor + grant gate
///
/// The candidate set is chosen by [`candidate_capsules`]: the view-scoped
/// surface scopes to the caller's per-principal view (fail-closed, no default
/// fallback); every other topic uses the global instance set (the mesh stays
/// global). View FIRST.
///
/// Then, on the **grant-gated surface**
/// ([`crate::access::is_user_invocable_surface`] — tool execute / CLI command
/// execute, NOT describe) **and** with an `access_resolver` wired, a candidate
/// capsule is kept only if `caller_principal` is granted it (or is an admin
/// holding `*`). Grant SECOND. The gate is keyed on the **topic**, so a
/// dual-role capsule's orchestration interceptors are never filtered.
///
/// For an **authenticated, non-admin** caller a grant-denied (but in-view)
/// match is not a pure silent drop: before dropping, a
/// [`astrid_events::ipc::IpcPayload::GrantRequired`] signal is published on
/// `astrid.v1.approval` (grant-on-first-use, #998) so a broker/shim can elicit
/// consent. A `None`/empty/`anonymous` caller (no authenticated principal to
/// grant to) is a pure silent drop with no signal. A capsule that was never in
/// the caller's view is dropped by the view floor BEFORE this, so it never
/// triggers a `GrantRequired` (its existence is not disclosed).
async fn find_matching_interceptors(
    registry: &RwLock<CapsuleRegistry>,
    topic: &str,
    caller_principal: Option<&str>,
    access_resolver: Option<&CapsuleAccessResolver>,
    event_bus: &EventBus,
) -> Vec<(Arc<dyn crate::capsule::Capsule>, String, u32)> {
    // The grant gate engages only for the grant-gated surface (execute / CLI)
    // with a resolver present. Describe is view-scoped but NOT grant-gated; the
    // mesh is neither. Compute once per event, not per capsule.
    let gate_surface = crate::access::is_user_invocable_surface(topic);
    let registry = registry.read().await;
    // View FIRST: resolve the candidate set under the per-principal view floor
    // (#1069). For the view-scoped surface this is ONLY the caller's view —
    // fail-closed, no default fallback. For the mesh it is the global set.
    let candidates = candidate_capsules(&registry, topic, caller_principal);
    let mut matches: Vec<(Arc<dyn crate::capsule::Capsule>, String, u32)> = Vec::new();
    // Dedup grant-on-use signals within one dispatch pass (principal is fixed
    // per call, so key on `capsule_id`). Owned strings — the candidates are
    // cloned `Arc`s, not registry-borrowed.
    let mut grant_signalled: Vec<String> = Vec::new();
    for capsule in candidates {
        if !matches!(capsule.state(), crate::capsule::CapsuleState::Ready) {
            continue;
        }
        // Grant SECOND: per-principal access gate for the grant-gated surface.
        // Fail-closed: with the gate engaged and a resolver wired, an ungranted
        // (or unknown/anonymous) caller drops this capsule's tool interceptors
        // entirely. (A capsule outside the caller's view was already excluded by
        // the view floor above, so this only ever sees in-view candidates.)
        if gate_surface
            && let Some(resolver) = access_resolver
            && !resolver.is_capsule_allowed(caller_principal, capsule.id())
        {
            // Grant-on-first-use (#998): for an authenticated non-admin caller,
            // emit a `GrantRequired` signal before dropping. The grant TARGET is
            // the kernel-stamped caller + this capsule — never any
            // caller-supplied claim. Skip a `None`/empty/`anonymous` principal
            // (no authenticated principal to grant).
            if let Some(principal) = caller_principal
                && !principal.is_empty()
                && principal != "anonymous"
            {
                let capsule_key = capsule.id().as_str().to_string();
                if !grant_signalled.contains(&capsule_key) {
                    crate::access::emit_grant_required(event_bus, principal, capsule_key.clone());
                    grant_signalled.push(capsule_key);
                }
            }
            continue;
        }
        // RFC cargo-like-manifest: read effective interceptors — [subscribe]
        // .handler entries merged with legacy [[interceptor]] blocks. Legacy
        // entries keep their declared priority; new-form entries get default
        // (100).
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
    // Sort by priority (lower fires first), then by capsule id and action as a
    // STABLE tiebreak so equal-priority members have a deterministic order. The
    // candidate set iterates a HashMap (arbitrary per run), so a priority-only
    // sort left ties (e.g. a mixed chain `[10, 20, 20]`) in non-deterministic
    // order — which matters in the ordered-chain path, where a tied member's
    // `Final`/`Deny` short-circuits its sibling. (An all-equal set dispatches
    // concurrently, so order is irrelevant there, but a stable order keeps
    // dispatch reproducible everywhere.) Priority rides along in the returned
    // tuple so dispatch can distinguish an ordered chain (distinct priorities)
    // from an independent fan-out (all equal).
    matches.sort_by(|(a_cap, a_act, a_pri), (b_cap, b_act, b_pri)| {
        a_pri
            .cmp(b_pri)
            .then_with(|| a_cap.id().as_str().cmp(b_cap.id().as_str()))
            .then_with(|| a_act.cmp(b_act))
    });
    matches
}

#[cfg(test)]
#[path = "dispatcher_tests.rs"]
mod tests;
