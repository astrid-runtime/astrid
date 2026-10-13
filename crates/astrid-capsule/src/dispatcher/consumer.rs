//! Per-principal invocation and idle-consumer cleanup.

use super::*;

/// Consumer loop for one `(capsule, principal_key)` queue. Idle-evicts
/// itself after the configured grace of inactivity, atomically removing its
/// sender under the same map lock that `get_or_spawn_consumer` takes.
pub(super) async fn run_consumer(
    mut rx: mpsc::Receiver<InterceptorWork>,
    capsule: Arc<dyn Capsule>,
    queues: CapsuleQueues,
    key: (RuntimeId, PrincipalKey),
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
                match wait_graph::ACTIVE_CONSUMER
                    .scope(
                        key.clone(),
                        capsule.invoke_interceptor(&work.action, &work.payload, caller),
                    )
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
                        if let Some(failure) = &work.failure {
                            failure.report(&reason);
                        }
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
                        if let Some(failure) = &work.failure {
                            failure.report(&e.to_string());
                        }
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
