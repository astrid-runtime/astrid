//! Layer 6 admin dispatcher (issue #672).
//!
//! Subscribes to `astrid.v1.admin.*` and routes every variant of
//! [`AdminRequestKind`] through the same capability-enforcement
//! preamble introduced in issue #670 (Layer 5). On allow, the mutating
//! handlers in [`handlers`] acquire
//! [`Kernel::admin_write_lock`](crate::Kernel::admin_write_lock) before
//! touching `profile.toml` / `groups.toml`, then atomically replace the
//! resolved config on the [`ArcSwap`](arc_swap::ArcSwap) backing
//! [`Kernel::groups`](crate::Kernel::groups) and/or invalidate the
//! matching [`PrincipalProfileCache`](astrid_capsule::profile_cache::PrincipalProfileCache)
//! entry.
//!
//! # Audit trail
//!
//! Every admin topic — allow or deny — appends an
//! [`AuditAction::AdminRequest`] entry. `method` is the wire name
//! (`"admin.agent.create"`, etc.); `target_principal` is `Some` for
//! variants that operate on another principal and `None` otherwise.
//! `params` captures the full request payload (capabilities granted,
//! quotas set, group definition) for forensic replay without diffing
//! `profile.toml` snapshots.

#[cfg(test)]
mod enforcement_tests;
mod handlers;
#[cfg(test)]
mod state_tests;
#[cfg(test)]
mod state_tests_agent_modify;
#[cfg(test)]
mod tests;

use std::sync::Arc;

use astrid_audit::{AuditOutcome, AuthorizationProof};
use astrid_core::principal::PrincipalId;
use astrid_events::ipc::IpcPayload;
use astrid_events::kernel_api::{
    AdminKernelRequest, AdminKernelResponse, AdminRequestKind, AdminResponseBody,
};
use tracing::warn;

use super::{
    AdminAuditEntry, AuthorityScope, authorize_request, publish_response, record_admin_audit,
    resolve_caller,
};

/// Admin IPC input topic prefix.
const ADMIN_TOPIC_PREFIX: &str = "astrid.v1.admin.";
/// Admin IPC response topic prefix (paired with [`ADMIN_TOPIC_PREFIX`]).
const ADMIN_RESPONSE_PREFIX: &str = "astrid.v1.admin.response.";

/// Spawn the admin dispatcher task. Mirrors [`super::spawn_kernel_router`]
/// but listens on `astrid.v1.admin.*` and parses
/// [`AdminKernelRequest`] payloads.
pub(crate) fn spawn_admin_router(kernel: Arc<crate::Kernel>) -> tokio::task::JoinHandle<()> {
    let mut receiver = kernel.event_bus.subscribe_topic("astrid.v1.admin.*");

    tokio::spawn(async move {
        while let Some(event) = receiver.recv().await {
            let astrid_events::AstridEvent::Ipc { message, .. } = &*event else {
                continue;
            };

            // Never loop back on our own response topic.
            if message.topic.starts_with(ADMIN_RESPONSE_PREFIX) {
                continue;
            }

            let IpcPayload::RawJson(val) = &message.payload else {
                continue;
            };

            match serde_json::from_value::<AdminKernelRequest>(val.clone()) {
                Ok(req) => {
                    let caller = resolve_caller(message);
                    handle_admin_request(&kernel, message.topic.clone(), caller, req).await;
                },
                Err(e) => {
                    warn!(
                        error = %e,
                        topic = %message.topic,
                        "Failed to parse AdminKernelRequest from IPC"
                    );
                },
            }
        }
    })
}

/// Compute the response topic for an incoming admin request topic.
fn admin_response_topic(input_topic: &str) -> String {
    input_topic.strip_prefix(ADMIN_TOPIC_PREFIX).map_or_else(
        || input_topic.to_string(),
        |suffix| format!("{ADMIN_RESPONSE_PREFIX}{suffix}"),
    )
}

/// Return the authority scope `req` exercises for `caller`.
///
/// Self-scoped when the target principal equals the caller
/// ([`AdminRequestKind::QuotaGet`] / [`AdminRequestKind::QuotaSet`]
/// / [`AdminRequestKind::AgentList`] — the last scoped as "self" so
/// agents can see their own row). Everything else is cross-tenant,
/// including creation / group operations that are intrinsically global.
#[must_use]
pub fn resolve_admin_scope(req: &AdminRequestKind, caller: &PrincipalId) -> AuthorityScope {
    match req {
        AdminRequestKind::QuotaGet { principal } | AdminRequestKind::QuotaSet { principal, .. } => {
            if principal == caller {
                AuthorityScope::Self_
            } else {
                AuthorityScope::Global
            }
        },
        AdminRequestKind::AgentList => AuthorityScope::Self_,
        AdminRequestKind::AgentCreate { .. }
        | AdminRequestKind::AgentDelete { .. }
        | AdminRequestKind::AgentEnable { .. }
        | AdminRequestKind::AgentDisable { .. }
        | AdminRequestKind::AgentModify { .. }
        | AdminRequestKind::GroupCreate { .. }
        | AdminRequestKind::GroupDelete { .. }
        | AdminRequestKind::GroupModify { .. }
        | AdminRequestKind::GroupList
        | AdminRequestKind::CapsGrant { .. }
        | AdminRequestKind::CapsRevoke { .. } => AuthorityScope::Global,
    }
}

/// Static capability string required to satisfy `req` under `scope`.
///
/// Pure function — the mapping can be unit-tested in isolation.
/// Every variant has an entry; there is no default-allow arm.
///
/// `self:*` forms apply when the target principal is the caller
/// themselves; admins operating on another principal need the
/// unscoped `quota:set` / `caps:grant` forms. Group admin is always
/// global — there is no "self" variant of `group:create`.
#[must_use]
pub fn required_capability_for_admin_request(
    req: &AdminRequestKind,
    scope: AuthorityScope,
) -> &'static str {
    match (req, scope) {
        (AdminRequestKind::AgentCreate { .. }, _) => "agent:create",
        (AdminRequestKind::AgentDelete { .. }, _) => "agent:delete",
        (AdminRequestKind::AgentEnable { .. }, _) => "agent:enable",
        (AdminRequestKind::AgentDisable { .. }, _) => "agent:disable",
        (AdminRequestKind::AgentModify { .. }, _) => "agent:modify",
        (AdminRequestKind::AgentList, AuthorityScope::Self_) => "self:agent:list",
        (AdminRequestKind::AgentList, AuthorityScope::Global) => "agent:list",
        (AdminRequestKind::QuotaSet { .. }, AuthorityScope::Self_) => "self:quota:set",
        (AdminRequestKind::QuotaSet { .. }, AuthorityScope::Global) => "quota:set",
        (AdminRequestKind::QuotaGet { .. }, AuthorityScope::Self_) => "self:quota:get",
        (AdminRequestKind::QuotaGet { .. }, AuthorityScope::Global) => "quota:get",
        (AdminRequestKind::GroupCreate { .. }, _) => "group:create",
        (AdminRequestKind::GroupDelete { .. }, _) => "group:delete",
        (AdminRequestKind::GroupModify { .. }, _) => "group:modify",
        (AdminRequestKind::GroupList, _) => "group:list",
        (AdminRequestKind::CapsGrant { .. }, _) => "caps:grant",
        (AdminRequestKind::CapsRevoke { .. }, _) => "caps:revoke",
    }
}

/// Stable wire-name identifier for an [`AdminRequestKind`] — used as
/// the `method` field on every [`AuditAction::AdminRequest`] entry.
#[must_use]
pub fn admin_request_method(req: &AdminRequestKind) -> &'static str {
    match req {
        AdminRequestKind::AgentCreate { .. } => "admin.agent.create",
        AdminRequestKind::AgentDelete { .. } => "admin.agent.delete",
        AdminRequestKind::AgentEnable { .. } => "admin.agent.enable",
        AdminRequestKind::AgentDisable { .. } => "admin.agent.disable",
        AdminRequestKind::AgentModify { .. } => "admin.agent.modify",
        AdminRequestKind::AgentList => "admin.agent.list",
        AdminRequestKind::QuotaSet { .. } => "admin.quota.set",
        AdminRequestKind::QuotaGet { .. } => "admin.quota.get",
        AdminRequestKind::GroupCreate { .. } => "admin.group.create",
        AdminRequestKind::GroupDelete { .. } => "admin.group.delete",
        AdminRequestKind::GroupModify { .. } => "admin.group.modify",
        AdminRequestKind::GroupList => "admin.group.list",
        AdminRequestKind::CapsGrant { .. } => "admin.caps.grant",
        AdminRequestKind::CapsRevoke { .. } => "admin.caps.revoke",
    }
}

/// Borrow the target principal for audit purposes — `Some` only when the
/// request operates on a principal distinct from the caller.
#[must_use]
pub fn admin_target_principal(req: &AdminRequestKind) -> Option<&PrincipalId> {
    match req {
        AdminRequestKind::AgentDelete { principal }
        | AdminRequestKind::AgentEnable { principal }
        | AdminRequestKind::AgentDisable { principal }
        | AdminRequestKind::AgentModify { principal, .. }
        | AdminRequestKind::QuotaSet { principal, .. }
        | AdminRequestKind::QuotaGet { principal }
        | AdminRequestKind::CapsGrant { principal, .. }
        | AdminRequestKind::CapsRevoke { principal, .. } => Some(principal),
        AdminRequestKind::AgentCreate { .. }
        | AdminRequestKind::AgentList
        | AdminRequestKind::GroupCreate { .. }
        | AdminRequestKind::GroupDelete { .. }
        | AdminRequestKind::GroupModify { .. }
        | AdminRequestKind::GroupList => None,
    }
}

async fn handle_admin_request(
    kernel: &Arc<crate::Kernel>,
    topic: String,
    caller: PrincipalId,
    req: AdminKernelRequest,
) {
    let response_topic = admin_response_topic(&topic);
    let request_id = req.request_id.clone();
    let method = admin_request_method(&req.kind);
    let scope = resolve_admin_scope(&req.kind, &caller);
    let required_cap = required_capability_for_admin_request(&req.kind, scope);
    let target = admin_target_principal(&req.kind).cloned();
    // Capture the params field for the audit entry — clients submitting
    // malformed JSON never reach this point, so serialization is
    // infallible for shapes we accept.
    let audit_params = serde_json::to_value(&req.kind).ok();

    match authorize_request(kernel, &caller, required_cap) {
        Ok(()) => {
            record_admin_audit(
                kernel,
                AdminAuditEntry {
                    caller: &caller,
                    method,
                    required_cap,
                    target_principal: target.clone(),
                    params: audit_params.clone(),
                    authorization: AuthorizationProof::System {
                        reason: format!("policy allow: {caller} holds {required_cap}"),
                    },
                    outcome: AuditOutcome::success(),
                },
            );
        },
        Err(e) => {
            warn!(
                security_event = true,
                method = method,
                principal = %caller,
                required = required_cap,
                error = %e,
                "Permission check denied admin request"
            );
            record_admin_audit(
                kernel,
                AdminAuditEntry {
                    caller: &caller,
                    method,
                    required_cap,
                    target_principal: target,
                    params: audit_params,
                    authorization: AuthorizationProof::Denied {
                        reason: e.to_string(),
                    },
                    outcome: AuditOutcome::failure(e.to_string()),
                },
            );
            publish_response(
                kernel,
                response_topic,
                AdminKernelResponse::for_request(
                    request_id,
                    AdminResponseBody::Error(e.to_string()),
                ),
            );
            return;
        },
    }

    let body = handlers::dispatch(kernel, req.kind).await;
    publish_response(
        kernel,
        response_topic,
        AdminKernelResponse::for_request(request_id, body),
    );
}
