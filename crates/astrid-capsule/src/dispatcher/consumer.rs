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
    identity: mpsc::WeakSender<InterceptorWork>,
) {
    let gate = capsule.delivery_admission_gate();
    let mut draining = false;
    loop {
        let next = if draining {
            Ok(rx.recv().await)
        } else {
            tokio::select! {
                next = astrid_runtime::time::timeout(idle_consumer_grace(), rx.recv()) => next,
                () = queues.stopping().wait_until_retired() => {
                    rx.close();
                    draining = true;
                    continue;
                }
                () = async {
                    match &gate {
                        Some(gate) => gate.wait_until_retired().await,
                        None => std::future::pending::<()>().await,
                    }
                } => {
                    // Close admission, then finish queued work through normal
                    // invocation/error reporting. Never drop an active invoke
                    // future or an outstanding reserved channel permit.
                    rx.close();
                    draining = true;
                    continue;
                }
            }
        };
        match next {
            Ok(Some(work)) => {
                invoke_work(capsule.as_ref(), &key, work).await;
            },
            Ok(None) => {
                // No queued work or outstanding permits remain. A replacement
                // generation may already occupy this key; never remove it.
                let mut guard = queues.lock();
                if guard.get(&key).is_some_and(|sender| {
                    identity
                        .upgrade()
                        .is_some_and(|original| original.same_channel(sender))
                }) {
                    guard.remove(&key);
                }
                drop(guard);
                debug!(
                    capsule_id = %capsule.id(),
                    "Per-principal consumer exiting: sender dropped"
                );
                return;
            },
            Err(_elapsed) => {
                if evict_idle(&rx, &queues, &key, &identity) {
                    return;
                }
            },
        }
    }
}

/// Under the admission lock, an empty queue with only its mapped sender has
/// no in-flight publication. Inspect without consuming: work can race the
/// timeout before this lock is acquired and must remain available to recv.
pub(super) fn evict_idle(
    rx: &mpsc::Receiver<InterceptorWork>,
    queues: &CapsuleQueues,
    key: &(RuntimeId, PrincipalKey),
    identity: &mpsc::WeakSender<InterceptorWork>,
) -> bool {
    let mut guard = queues.lock();
    if rx.is_empty()
        && rx.sender_strong_count() == 1
        && guard.get(key).is_some_and(|sender| {
            identity
                .upgrade()
                .is_some_and(|original| original.same_channel(sender))
        })
    {
        guard.remove(key);
        return true;
    }
    false
}

async fn invoke_work(
    capsule: &dyn Capsule,
    key: &(RuntimeId, PrincipalKey),
    work: InterceptorWork,
) {
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
}
