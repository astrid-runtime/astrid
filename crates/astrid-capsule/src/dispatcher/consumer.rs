//! Per-principal invocation and idle-consumer cleanup.

use super::*;

/// Consumer loop for one `(capsule, principal_key)` queue. Idle-evicts
/// itself after [`IDLE_CONSUMER_GRACE`] of inactivity, atomically
/// removing its sender from the queue map under the same lock that
/// `get_or_spawn_consumer` takes — closes the race where an event
/// arrives between timeout and unmap.
pub(super) async fn run_consumer(
    mut rx: mpsc::Receiver<InterceptorWork>,
    capsule: Arc<dyn Capsule>,
    queues: CapsuleQueues,
    key: (RuntimeId, PrincipalKey),
    generation: mpsc::WeakSender<InterceptorWork>,
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
                if try_evict_idle_consumer(&mut rx, &queues, &key, &generation) {
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
            },
        }
    }
}

/// Probe without consuming work or removing a replacement channel generation.
fn try_evict_idle_consumer(
    rx: &mut mpsc::Receiver<InterceptorWork>,
    queues: &CapsuleQueues,
    key: &(RuntimeId, PrincipalKey),
    generation: &mpsc::WeakSender<InterceptorWork>,
) -> bool {
    let mut guard = queues.lock();
    let owns_entry = generation.upgrade().is_some_and(|own| {
        guard
            .get(key)
            .is_some_and(|mapped| mapped.same_channel(&own))
    });
    // The temporary identity-check Sender is dropped before counting. With
    // the map locked and holding this channel's only Sender, no producer or
    // owned permit can still enqueue. Check that FIRST: checking emptiness
    // first lets an existing sender enqueue and drop before the count read.
    if owns_entry && rx.sender_strong_count() == 1 && rx.is_empty() {
        guard.remove(key);
        return true;
    }
    false
}

#[cfg(test)]
mod tests;
