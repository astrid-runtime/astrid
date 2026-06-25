//! Per-(capsule, principal) ordered dispatch queues and chain serialization.
//!
//! Split out of [`crate::dispatcher`] (referenced via `#[path]`) so the
//! dispatcher's enforcement core (`find_matching_interceptors`, the view-scope
//! gate) and this queue/consumer machinery each stay under the per-file CI line
//! cap as both surfaces grow (#1069 added per-principal view scoping to the
//! core, pushing the combined file over the ceiling).
//!
//! This module owns:
//! - the per-(capsule, principal) chain-serialization mutex map
//!   ([`ChainLocks`], [`ChainLockGuard`], [`acquire_chain_lock`]),
//! - the per-(capsule, principal) ordered mpsc queue map ([`CapsuleQueues`],
//!   [`InterceptorWork`]),
//! - the dispatch entry points ([`dispatch_to_capsule_queues`],
//!   [`dispatch_single`]) and the consumer lifecycle
//!   ([`get_or_spawn_consumer`], [`run_consumer`]).
//!
//! It shares the parent module's `use` scope through `use super::*`. The
//! matching/enforcement decision (which capsules an event reaches) lives in
//! the parent; this module only routes already-matched work to ordered,
//! per-principal-isolated consumers.

use super::*;

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

/// Shared map of per-(capsule, principal) chain mutexes. One
/// `Arc<tokio::sync::Mutex<()>>` per `(CapsuleId, PrincipalKey)` so
/// chain dispatches for the same key serialize FIFO while distinct
/// keys (including distinct principals within the same class) run
/// concurrently. Held across the chain task's lifetime in
/// `dispatch_to_capsule_queues`.
pub(crate) type ChainLocks =
    Arc<parking_lot::RwLock<HashMap<(CapsuleId, PrincipalKey), Arc<tokio::sync::Mutex<()>>>>>;

/// RAII chain-lock lease that prunes its `ChainLocks` map entry on drop
/// when it was the last referrer.
///
/// Without this, the map gains an entry per `(capsule, principal)` on first
/// use and never sheds it — ephemeral recursive sub-agents (high principal
/// churn) would grow it unboundedly, unlike `capsule_queues` which idle-evicts
/// (Gemini #828). The acquire path stays race-safe: a concurrent acquirer that
/// raced the removal simply re-inserts via `or_insert_with`, so a pruned-then-
/// reused key costs one extra allocation, never a correctness loss.
struct ChainLockGuard {
    /// The held mutex guard. Dropped FIRST in [`Drop`] so the mutex is free
    /// before we inspect the Arc's strong count.
    ///
    /// `Option` so `drop` can take it and release the lock explicitly before
    /// taking the map's write lock.
    guard: Option<tokio::sync::OwnedMutexGuard<()>>,
    /// Our own clone of the per-key mutex `Arc`. With `guard` dropped, this is
    /// the only referrer outside the map, so `strong_count == 2` (map + this)
    /// proves no other chain task holds the lock and the entry can be pruned.
    mutex: Arc<tokio::sync::Mutex<()>>,
    chain_locks: ChainLocks,
    key: (CapsuleId, PrincipalKey),
}

impl Drop for ChainLockGuard {
    fn drop(&mut self) {
        // Release the lock first so the strong-count check below sees only
        // map + `self.mutex` referrers (the `OwnedMutexGuard` holds its own
        // internal `Arc` clone, which must be gone before we count).
        self.guard.take();
        let mut write = self.chain_locks.write();
        // Re-fetch under the write lock: a concurrent acquirer may have
        // replaced the entry after a previous prune, so only remove the
        // exact Arc we hold, and only when we are its last non-map referrer.
        if let Some(entry) = write.get(&self.key)
            && Arc::ptr_eq(entry, &self.mutex)
            && Arc::strong_count(entry) == 2
        {
            write.remove(&self.key);
        }
    }
}

/// Acquire the per-(capsule, principal) chain lock, returning a guard that
/// prunes the map entry on drop. Read-fast / write-on-miss: the common case
/// is a hit on an existing lock.
async fn acquire_chain_lock(
    chain_locks: &ChainLocks,
    key: (CapsuleId, PrincipalKey),
) -> ChainLockGuard {
    let mutex = {
        let read = chain_locks.read();
        if let Some(m) = read.get(&key) {
            Arc::clone(m)
        } else {
            drop(read);
            let mut write = chain_locks.write();
            Arc::clone(
                write
                    .entry(key.clone())
                    .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))),
            )
        }
    };
    let guard = Arc::clone(&mutex).lock_owned().await;
    ChainLockGuard {
        guard: Some(guard),
        mutex,
        chain_locks: Arc::clone(chain_locks),
        key,
    }
}

/// Shared map of per-(capsule, principal) dispatcher mpsc senders.
/// Wrapped in `parking_lot::Mutex` so the consumer task can remove its
/// own entry under the same lock that admits new principals — this
/// closes the race where an idle-evicting consumer exits between the
/// dispatcher's `entry().or_insert_with(...)` and the subsequent
/// `try_send`.
pub(crate) type CapsuleQueues =
    Arc<parking_lot::Mutex<HashMap<(CapsuleId, PrincipalKey), mpsc::Sender<InterceptorWork>>>>;

/// Work item sent to a per-capsule ordered queue.
///
/// `pub(crate)` because it appears in [`CapsuleQueues`]'s type (which the parent
/// `dispatcher` module names), but its fields stay private to this module — only
/// the dispatch path here constructs one.
pub(crate) struct InterceptorWork {
    action: String,
    payload: Arc<Vec<u8>>,
    topic: Arc<String>,
    /// The originating IPC message, if this event came from IPC.
    /// `None` for lifecycle events. Carried through to
    /// `invoke_interceptor` so the kernel can set per-invocation
    /// principal context on `HostState`.
    ipc_message: Option<Arc<astrid_events::ipc::IpcMessage>>,
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
pub(crate) fn dispatch_to_capsule_queues(
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
    tokio::task::spawn(async move {
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
/// will idle-evict itself after [`IDLE_CONSUMER_GRACE_MS`] of inactivity.
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
    tokio::task::spawn(async move {
        run_consumer(rx, capsule_arc, queues_arc, cleanup_key).await;
    });
    tx
}

/// Consumer loop for one `(capsule, principal_key)` queue. Idle-evicts
/// itself after [`IDLE_CONSUMER_GRACE_MS`] of inactivity, atomically
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
        match tokio::time::timeout(idle_consumer_grace(), rx.recv()).await {
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

#[cfg(test)]
#[path = "dispatcher_queues_tests.rs"]
mod tests;
