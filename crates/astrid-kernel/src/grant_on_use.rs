//! Grant-on-first-use consent handler (issue #998).
//!
//! Per-principal capsule access (#992/#993) gates the user-invocable tool
//! surface at dispatch. An ungranted call used to be silently dropped; with
//! #998 the dispatcher instead publishes an [`IpcPayload::GrantRequired`] on
//! `astrid.v1.approval`. This module is the kernel's half of the consent loop:
//! it observes those signals, lets an external broker/shim elicit consent, and
//! — on an APPROVE response delivered on the per-request response topic — grants
//! the capsule to the *correlated* principal, reusing the #993 grant machinery.
//!
//! # Security model
//!
//! - **The grant target is never response-supplied.** `(principal, capsule_id)`
//!   comes only from the kernel-observed `GrantRequired` (which the dispatcher
//!   built from the kernel-stamped authenticated caller). It is captured by
//!   value into the per-request awaiter; the response message conveys only a
//!   `decision` for an already-fixed `request_id → target` correlation. The
//!   response payload's fields are never read for the target.
//! - **Authenticity rides on the publish-ACL.** Only the uplink and broker may
//!   publish `astrid.v1.approval.response.*`; a tool capsule cannot forge an
//!   approve. The handler consumes the response without a separate provenance
//!   check, exactly as `host/approval.rs` does — it reacts only to a correctly
//!   topic'd [`IpcPayload::ApprovalResponse`].
//! - **Fail-closed everywhere.** Every error path on the grant (invalid
//!   principal, missing profile, load/validate/save error, timeout, deny,
//!   unknown decision) is a `warn!(security_event = true)` no-op — never a
//!   panic, unwrap, or default-allow.
//! - **Bounded resource use.** Each correlation is a short-lived per-request
//!   task that self-expires at [`GRANT_RESPONSE_TIMEOUT`]; concurrent in-flight
//!   requests are capped by a [`tokio::sync::Semaphore`] ([`MAX_INFLIGHT_GRANTS`]),
//!   fail-closed dropping at cap. There is no unbounded shared correlation table.

use std::sync::Arc;
use std::time::Duration;

use astrid_core::principal::PrincipalId;
use astrid_core::profile::PrincipalProfile;
use astrid_events::AstridEvent;
use astrid_events::ipc::{IpcPayload, Topic};
use tracing::{info, warn};

use crate::Kernel;

/// Maximum time the per-request awaiter waits for a consent response before it
/// drops fail-closed, in milliseconds. Mirrors `host/approval.rs`'s
/// `MAX_APPROVAL_TIMEOUT_MS` (60s) so grant-on-use and plain approval share one
/// human-facing budget.
const GRANT_RESPONSE_TIMEOUT_MS: u64 = 60_000;

/// [`GRANT_RESPONSE_TIMEOUT_MS`] as a [`Duration`].
const GRANT_RESPONSE_TIMEOUT: Duration = Duration::from_millis(GRANT_RESPONSE_TIMEOUT_MS);

/// Hard cap on concurrent in-flight grant-on-use requests. A flood of
/// gate-misses cannot spawn unbounded awaiter tasks: at cap, a new
/// `GrantRequired` is dropped fail-closed.
const MAX_INFLIGHT_GRANTS: usize = 1024;

/// Stable lag label for the permanent `astrid.v1.approval` observer.
const OBSERVER_SUBSCRIBER: &str = "grant_on_use_observer";

/// Stable lag label for the short-lived per-request response awaiters. Kept
/// distinct from [`OBSERVER_SUBSCRIBER`] so the many transient awaiter
/// subscriptions are attributed to their own bucket and never skew the
/// permanent observer's lag metric.
const AWAITER_SUBSCRIBER: &str = "grant_on_use_awaiter";

/// The approve set, replicated from `host/approval.rs::decision_from_str`.
/// Anything else — explicit deny, unknown string, or empty — is NOT an approve.
fn is_approved(decision: &str) -> bool {
    matches!(decision, "approve" | "approve_session" | "approve_always")
}

/// Spawn the permanent grant-on-first-use consent handler.
///
/// Subscribes ONCE (a permanent broadcast subscriber — counts toward
/// `INTERNAL_SUBSCRIBER_COUNT`) to the literal topic `astrid.v1.approval`. For
/// each observed [`IpcPayload::GrantRequired`], it captures the correlated
/// `(principal, capsule_id)` by value and spawns a short-lived awaiter that
/// subscribes to the per-request response topic, waits (bounded) for an
/// [`IpcPayload::ApprovalResponse`], and grants on approve. The response's own
/// fields are never read for the target.
pub(crate) fn spawn_grant_on_use_handler(kernel: Arc<Kernel>) -> tokio::task::JoinHandle<()> {
    // Subscribe to the exact topic synchronously, BEFORE returning, so this
    // counts as the one permanent boot subscriber and never misses a signal
    // published right after boot. The literal (non-wildcard) topic matches only
    // `astrid.v1.approval`; per-request `astrid.v1.approval.response.<id>` is a
    // different topic, caught only by the per-request subscription below.
    let mut observer = kernel
        .event_bus
        .subscribe_topic_as(Topic::approval_request().as_str(), OBSERVER_SUBSCRIBER);

    // Bound concurrent in-flight grants. Cheap to clone (Arc inside).
    let inflight = Arc::new(tokio::sync::Semaphore::new(MAX_INFLIGHT_GRANTS));

    tokio::spawn(async move {
        while let Some(event) = observer.recv().await {
            let AstridEvent::Ipc { message, .. } = &*event else {
                continue;
            };
            let IpcPayload::GrantRequired {
                request_id,
                principal,
                capsule_id,
            } = &message.payload
            else {
                continue;
            };

            // SECURITY: only honour a GrantRequired the KERNEL emitted. The
            // dispatcher publishes it with a nil `source_id`; the host stamps
            // every CAPSULE publish with the capsule's own (non-nil v5) UUID,
            // which a capsule cannot override. Without this, a capsule holding
            // `astrid.v1.approval` publish-ACL could craft a typed
            // `GrantRequired` (`IpcPayload::from_json_value` parses a
            // `{"type":"grant_required",...}` body into the typed variant) with
            // an attacker-chosen `(principal, capsule_id)` grant target. Reject
            // anything not kernel-originated.
            if message.source_id != uuid::Uuid::nil() {
                warn!(
                    security_event = true,
                    source = %message.source_id,
                    request_id = %request_id,
                    principal = %principal,
                    capsule = %capsule_id,
                    "grant-on-use: GrantRequired from non-kernel source; ignoring (fail-closed)"
                );
                continue;
            }

            // SECURITY: capture the grant target from THIS observed signal
            // (kernel-built from the authenticated caller). The awaiter reads
            // only `decision` from the response — never a target.
            let request_id = request_id.clone();
            let principal = principal.clone();
            let capsule_id = capsule_id.clone();

            // Fail-closed flood control: acquire a permit BEFORE subscribing /
            // spawning. At cap, drop the signal — never spawn unbounded tasks.
            let Ok(permit) = Arc::clone(&inflight).try_acquire_owned() else {
                warn!(
                    security_event = true,
                    %request_id,
                    principal = %principal,
                    capsule = %capsule_id,
                    "grant-on-use inflight cap reached; dropping"
                );
                continue;
            };

            // Subscribe to the response topic BEFORE the await (and before the
            // next observe-loop iteration) to avoid a publish/subscribe race.
            let response_topic = Topic::approval_response(&request_id);
            let receiver = kernel
                .event_bus
                .subscribe_topic_as(response_topic.as_str(), AWAITER_SUBSCRIBER);

            let kernel = Arc::clone(&kernel);
            tokio::spawn(async move {
                // The permit lives for the awaiter's whole lifetime, releasing
                // the in-flight slot on drop (response, timeout, or panic).
                let _permit = permit;
                await_and_grant(&kernel, receiver, &principal, &capsule_id).await;
            });
        }
    })
}

/// Await a single consent response (bounded by [`GRANT_RESPONSE_TIMEOUT`]) and,
/// on an approve, grant the *correlated* capsule. Every non-approve outcome
/// (deny, unknown decision, timeout, channel closed) is a fail-closed no-op.
async fn await_and_grant(
    kernel: &Arc<Kernel>,
    mut receiver: astrid_events::EventReceiver,
    principal: &str,
    capsule_id: &str,
) {
    // Timed out (`Err`) or the bus closed (`Ok(None)`) → no consent, no grant.
    let Ok(Some(event)) = tokio::time::timeout(GRANT_RESPONSE_TIMEOUT, receiver.recv()).await
    else {
        warn!(
            security_event = true,
            principal = %principal,
            capsule = %capsule_id,
            "grant-on-use: no consent response before timeout; no grant (fail-closed)"
        );
        return;
    };

    let AstridEvent::Ipc { message, .. } = &*event else {
        return;
    };
    // SECURITY: read ONLY `decision`. The target is the already-captured
    // (principal, capsule_id); the response carries no target to honour.
    let IpcPayload::ApprovalResponse { decision, .. } = &message.payload else {
        return;
    };

    if !is_approved(decision) {
        warn!(
            security_event = true,
            principal = %principal,
            capsule = %capsule_id,
            decision = %decision,
            "grant-on-use: consent not approved; no grant (fail-closed)"
        );
        return;
    }

    grant_capsule(kernel, principal, capsule_id).await;
}

/// Grant `capsule_id` to `principal`, reusing the #993 admin grant machinery
/// (load → set-delta → validate → save → cache-invalidate) under the kernel's
/// `admin_write_lock` so a concurrent `agent modify` cannot race the
/// load-modify-save on the same profile. Fail-closed on every error.
async fn grant_capsule(kernel: &Arc<Kernel>, principal: &str, capsule_id: &str) {
    use crate::kernel_router::admin::handlers::{
        apply_set_delta, principal_profile_path, require_principal_exists,
    };

    let Ok(pid) = PrincipalId::new(principal) else {
        warn!(
            security_event = true,
            principal = %principal,
            capsule = %capsule_id,
            "grant-on-use: invalid principal string; no grant (fail-closed)"
        );
        return;
    };

    // Serialize with `agent modify` (#993) so the load-modify-save is atomic.
    let _guard = kernel.admin_write_lock.lock().await;

    let path = principal_profile_path(kernel, &pid);
    // A grant for a principal with no profile on disk is a fail-closed no-op,
    // NOT a create — never materialize a phantom principal with a grant.
    if let Err(msg) = require_principal_exists(&pid, &path) {
        warn!(
            security_event = true,
            principal = %pid,
            capsule = %capsule_id,
            error = %msg,
            "grant-on-use: principal has no profile; no grant (fail-closed)"
        );
        return;
    }

    let mut profile = match PrincipalProfile::load_from_path(&path) {
        Ok(p) => p,
        Err(e) => {
            warn!(
                security_event = true,
                principal = %pid,
                capsule = %capsule_id,
                error = %e,
                "grant-on-use: profile load failed; no grant (fail-closed)"
            );
            return;
        },
    };

    let changed = match apply_set_delta::<astrid_core::CapsuleGrant>(
        &mut profile.capsules,
        &[capsule_id.to_string()],
        &[],
    ) {
        Ok(changed) => changed,
        Err(e) => {
            warn!(
                security_event = true,
                principal = %pid,
                capsule = %capsule_id,
                error = %e,
                "grant-on-use: capsule grant rejected; no grant (fail-closed)"
            );
            return;
        },
    };
    if !changed {
        // Already granted — idempotent. Invalidate to be safe; no save needed.
        kernel.profile_cache.invalidate(&pid);
        return;
    }

    // Validate before saving: re-run the profile invariants (#993). On reject,
    // do NOT save — a malformed grant must never reach disk.
    if let Err(e) = profile.validate() {
        warn!(
            security_event = true,
            principal = %pid,
            capsule = %capsule_id,
            error = %e,
            "grant-on-use: profile rejected by validation; no grant (fail-closed)"
        );
        return;
    }
    if let Err(e) = profile.save_to_path(&path) {
        warn!(
            security_event = true,
            principal = %pid,
            capsule = %capsule_id,
            error = %e,
            "grant-on-use: profile save failed; no grant (fail-closed)"
        );
        return;
    }
    kernel.profile_cache.invalidate(&pid);

    info!(
        security_event = true,
        principal = %pid,
        capsule = %capsule_id,
        "grant-on-first-use: capsule granted via elicited consent"
    );
}

#[cfg(test)]
#[path = "grant_on_use_tests.rs"]
mod tests;
