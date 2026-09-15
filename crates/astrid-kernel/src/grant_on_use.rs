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

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use astrid_core::principal::PrincipalId;
use astrid_core::profile::PrincipalProfile;
use astrid_events::ipc::{IpcMessage, IpcPayload, Topic};
use astrid_events::{AstridEvent, EventMetadata};
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

/// Stable lag label for the permanent ordered approval observer.
const OBSERVER_SUBSCRIBER: &str = "grant_on_use_observer";

/// The approve set, replicated from `host/approval.rs::decision_from_str`.
/// Anything else — explicit deny, unknown string, or empty — is NOT an approve.
fn is_approved(decision: &str) -> bool {
    matches!(decision, "approve" | "approve_session" | "approve_always")
}

/// Spawn the permanent grant-on-first-use consent handler.
///
/// Subscribes once to the ordered event stream (counting toward
/// `INTERNAL_SUBSCRIBER_COUNT`) and keeps a bounded correlation map. Recording
/// both requests and responses from one receiver is important: a fast native
/// responder can never publish before a per-request waiter exists, because the
/// request event is necessarily consumed first from the same ordered stream.
pub(crate) fn spawn_grant_on_use_handler(kernel: Arc<Kernel>) -> astrid_runtime::JoinHandle<()> {
    // Subscribe synchronously before returning so no request published after
    // kernel construction can precede observer registration. EventReceiver's
    // topic filters still consume the same broadcast stream, so a single
    // unfiltered receiver is both cheaper and strictly ordered across the
    // request and per-request response topics we correlate here.
    let mut observer = kernel.event_bus.subscribe_as(OBSERVER_SUBSCRIBER);
    let inflight = Arc::new(tokio::sync::Semaphore::new(MAX_INFLIGHT_GRANTS));

    astrid_runtime::spawn(async move {
        let mut pending = HashMap::<String, PendingGrant>::new();
        loop {
            let until_expiry = pending
                .values()
                .map(|entry| {
                    entry
                        .deadline
                        .saturating_duration_since(astrid_runtime::time::Instant::now())
                })
                .min()
                .unwrap_or(GRANT_RESPONSE_TIMEOUT);

            tokio::select! {
                event = observer.recv() => {
                    let Some(event) = event else {
                        break;
                    };
                    process_event(&kernel, &inflight, &mut pending, &event);
                }
                () = astrid_runtime::time::sleep(until_expiry), if !pending.is_empty() => {
                    expire_pending(&mut pending);
                }
            }
        }
    })
}

struct PendingGrant {
    principal: String,
    request_owner: astrid_events::ipc::RequestOwnerId,
    capsule_id: String,
    deadline: astrid_runtime::time::Instant,
    /// Keeps the flood-control slot through durable grant completion.
    _permit: tokio::sync::OwnedSemaphorePermit,
}

fn process_event(
    kernel: &Arc<Kernel>,
    inflight: &Arc<tokio::sync::Semaphore>,
    pending: &mut HashMap<String, PendingGrant>,
    event: &AstridEvent,
) {
    let AstridEvent::Ipc { message, .. } = event else {
        return;
    };

    match &message.payload {
        IpcPayload::GrantRequired {
            request_id,
            request_owner,
            principal,
            capsule_id,
        } if message.topic == Topic::approval_request() => record_grant_request(
            inflight,
            pending,
            message,
            request_id,
            request_owner,
            principal,
            capsule_id,
        ),
        IpcPayload::ApprovalResponse {
            request_id,
            decision,
            ..
        } if message.topic == Topic::approval_response(request_id) => {
            handle_grant_response(kernel, pending, message, request_id, decision);
        },
        _ => {},
    }
}

fn record_grant_request(
    inflight: &Arc<tokio::sync::Semaphore>,
    pending: &mut HashMap<String, PendingGrant>,
    message: &IpcMessage,
    request_id: &str,
    request_owner: &str,
    principal: &str,
    capsule_id: &str,
) {
    if message.source_id != uuid::Uuid::nil() {
        warn!(
            security_event = true,
            source = %message.source_id,
            %request_id,
            %principal,
            capsule = %capsule_id,
            "grant-on-use: GrantRequired from non-kernel source; ignoring (fail-closed)"
        );
        return;
    }
    let Some(stamped_owner) = message.request_owner else {
        warn!(
            security_event = true,
            %request_id,
            %principal,
            capsule = %capsule_id,
            "grant-on-use: unattributed request; ignoring (fail-closed)"
        );
        return;
    };
    if request_owner != stamped_owner.to_string() {
        warn!(
            security_event = true,
            %request_id,
            %principal,
            capsule = %capsule_id,
            "grant-on-use: payload owner differs from host metadata; ignoring"
        );
        return;
    }
    if pending.contains_key(request_id) {
        warn!(
            security_event = true,
            %request_id,
            %principal,
            capsule = %capsule_id,
            "grant-on-use duplicate request id; dropping"
        );
        return;
    }
    let Ok(permit) = Arc::clone(inflight).try_acquire_owned() else {
        warn!(
            security_event = true,
            %request_id,
            %principal,
            capsule = %capsule_id,
            "grant-on-use inflight cap reached; dropping"
        );
        return;
    };
    let deadline = astrid_runtime::time::Instant::now()
        .checked_add(GRANT_RESPONSE_TIMEOUT)
        .unwrap_or_else(astrid_runtime::time::Instant::now);
    pending.insert(
        request_id.to_owned(),
        PendingGrant {
            principal: principal.to_owned(),
            request_owner: stamped_owner,
            capsule_id: capsule_id.to_owned(),
            deadline,
            _permit: permit,
        },
    );
}

fn handle_grant_response(
    kernel: &Arc<Kernel>,
    pending: &mut HashMap<String, PendingGrant>,
    message: &IpcMessage,
    request_id: &str,
    decision: &str,
) {
    let Some(entry) = pending.get(request_id) else {
        return;
    };
    if message.principal.as_deref() != Some(entry.principal.as_str()) {
        warn!(
            security_event = true,
            expected_principal = %entry.principal,
            got_principal = message.principal.as_deref().unwrap_or("<none>"),
            capsule = %entry.capsule_id,
            "grant-on-use: rejected cross-principal approval response"
        );
        return;
    }
    if message.request_owner != Some(entry.request_owner) {
        let got_request_owner = message.request_owner.map(|owner| owner.to_string());
        warn!(
            security_event = true,
            principal = %entry.principal,
            expected_request_owner = %entry.request_owner,
            got_request_owner = got_request_owner.as_deref().unwrap_or("<none>"),
            capsule = %entry.capsule_id,
            "grant-on-use: rejected response from the wrong authenticated request owner"
        );
        return;
    }

    let entry = pending
        .remove(request_id)
        .expect("pending grant disappeared after immutable lookup");
    if !is_approved(decision) {
        warn!(
            security_event = true,
            principal = %entry.principal,
            capsule = %entry.capsule_id,
            %decision,
            "grant-on-use: consent not approved; no grant (fail-closed)"
        );
        return;
    }

    let kernel = Arc::clone(kernel);
    let request_id = request_id.to_owned();
    astrid_runtime::spawn(async move {
        complete_grant(&kernel, &request_id, entry).await;
    });
}

fn expire_pending(pending: &mut HashMap<String, PendingGrant>) {
    let now = astrid_runtime::time::Instant::now();
    pending.retain(|_, entry| {
        let keep = entry.deadline > now;
        if !keep {
            warn!(
                security_event = true,
                principal = %entry.principal,
                capsule = %entry.capsule_id,
                "grant-on-use: no consent response before timeout; no grant (fail-closed)"
            );
        }
        keep
    });
}

async fn complete_grant(kernel: &Arc<Kernel>, request_id: &str, entry: PendingGrant) {
    let granted = grant_capsule(kernel, &entry.principal, &entry.capsule_id).await;
    let payload = IpcPayload::GrantResult {
        request_id: request_id.to_owned(),
        request_owner: entry.request_owner.to_string(),
        principal: entry.principal.clone(),
        capsule_id: entry.capsule_id,
        granted,
    };
    let message = IpcMessage::new(Topic::grant_result(request_id), payload, uuid::Uuid::nil())
        .with_principal(entry.principal)
        .with_request_owner(entry.request_owner);
    let _ = kernel.event_bus.publish(AstridEvent::Ipc {
        message,
        metadata: EventMetadata::new("grant-on-use"),
    });
}

/// Grant `capsule_id` to `principal`, reusing the #993 admin grant machinery
/// (load → set-delta → validate → save → cache-invalidate) under the kernel's
/// `admin_write_lock` so a concurrent `agent modify` cannot race the
/// load-modify-save on the same profile. Fail-closed on every error.
async fn grant_capsule(kernel: &Arc<Kernel>, principal: &str, capsule_id: &str) -> bool {
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
        return false;
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
        return false;
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
            return false;
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
            return false;
        },
    };
    if !changed {
        // Already granted — idempotent. Invalidate to be safe; no save needed.
        kernel.profile_cache.invalidate(&pid);
        return true;
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
        return false;
    }
    if let Err(e) = profile.save_to_path(&path) {
        warn!(
            security_event = true,
            principal = %pid,
            capsule = %capsule_id,
            error = %e,
            "grant-on-use: profile save failed; no grant (fail-closed)"
        );
        return false;
    }
    kernel.profile_cache.invalidate(&pid);

    info!(
        security_event = true,
        principal = %pid,
        capsule = %capsule_id,
        "grant-on-first-use: capsule granted via elicited consent"
    );
    true
}

#[cfg(test)]
#[path = "grant_on_use_tests.rs"]
mod tests;
