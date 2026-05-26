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
mod invite_handlers;
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
        // `GroupList` is read-only over system config and carries no
        // target principal; every agent legitimately needs to read it
        // to enumerate their own group-inherited capabilities (e.g.
        // `caps check <self>` follows AgentList with GroupList to
        // resolve `(group: agent)` → `self:agent:list`). Self-scoping
        // makes the request match against `self:group:list`, which
        // the `self:*` grant on the `agent` builtin already satisfies
        // — without handing out the admin-tier `group:list` capability.
        // The mutating group operations (`group create / delete /
        // modify`) keep their own dedicated caps (`group:create`,
        // `group:delete`, `group:modify`) and remain
        // `AuthorityScope::Global` below, so this widening is read-only.
        AdminRequestKind::AgentList | AdminRequestKind::GroupList => AuthorityScope::Self_,
        AdminRequestKind::AgentCreate { .. }
        | AdminRequestKind::AgentDelete { .. }
        | AdminRequestKind::AgentEnable { .. }
        | AdminRequestKind::AgentDisable { .. }
        | AdminRequestKind::AgentModify { .. }
        | AdminRequestKind::GroupCreate { .. }
        | AdminRequestKind::GroupDelete { .. }
        | AdminRequestKind::GroupModify { .. }
        | AdminRequestKind::CapsGrant { .. }
        | AdminRequestKind::CapsRevoke { .. }
        | AdminRequestKind::InviteIssue { .. }
        | AdminRequestKind::InviteRedeem { .. }
        | AdminRequestKind::InviteList
        | AdminRequestKind::InviteRevoke { .. } => AuthorityScope::Global,
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
        (AdminRequestKind::GroupList, AuthorityScope::Self_) => "self:group:list",
        (AdminRequestKind::GroupList, AuthorityScope::Global) => "group:list",
        (AdminRequestKind::CapsGrant { .. }, _) => "caps:grant",
        (AdminRequestKind::CapsRevoke { .. }, _) => "caps:revoke",
        (AdminRequestKind::InviteIssue { .. }, _) => "invite:issue",
        // `InviteRedeem` is special-cased in `handle_admin_request`
        // below — the dispatcher bypasses the capability preamble
        // because the caller principal does not exist yet (the token
        // IS the auth). The string returned here is unused for that
        // variant but kept for completeness so audit records still
        // carry a stable name. We pick `invite:redeem` rather than
        // leaving it blank so the audit log reads cleanly.
        (AdminRequestKind::InviteRedeem { .. }, _) => "invite:redeem",
        (AdminRequestKind::InviteList, _) => "invite:list",
        (AdminRequestKind::InviteRevoke { .. }, _) => "invite:revoke",
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
        AdminRequestKind::InviteIssue { .. } => "admin.invite.issue",
        AdminRequestKind::InviteRedeem { .. } => "admin.invite.redeem",
        AdminRequestKind::InviteList => "admin.invite.list",
        AdminRequestKind::InviteRevoke { .. } => "admin.invite.revoke",
    }
}

/// Serialise an [`AdminRequestKind`] for audit storage with sensitive
/// fields redacted. Keeps the wire-name shape so audit consumers can
/// still discriminate variants — only the secret-bearing fields are
/// dropped or hashed.
///
/// Redactions:
///
/// * `InviteRedeem.public_key` → `public_key_fingerprint` (SHA-256 of
///   the supplied key). Storing the raw ed25519 key in the audit log
///   would double the system of record for authorization, which Layer
///   5/6 treat as `AuthConfig.public_keys` alone.
/// * `InviteRedeem.token` → `token_fingerprint` (`hex(sha256(token))`).
///   The raw invite token is a secret that grants the right to mint a
///   principal; persisting it in the audit log would let anyone with
///   read access replay it on a multi-use invite. The fingerprint
///   matches the on-disk hash in `invites.toml`, so an auditor can
///   still correlate a redeem to the issued invite.
/// * `InviteRevoke.token` → `token_fingerprint`. Same hazard as
///   `InviteRedeem.token`: the caller can pass either the raw token or
///   the already-fingerprinted form. Hash unconditionally when the
///   input doesn't already look like a fingerprint (64 hex chars).
fn sanitize_admin_audit_params(req: &AdminRequestKind) -> Option<serde_json::Value> {
    let mut val = serde_json::to_value(req).ok()?;
    let params = val
        .as_object_mut()
        .and_then(|m| m.get_mut("params"))
        .and_then(|p| p.as_object_mut())?;
    match req {
        AdminRequestKind::InviteRedeem {
            public_key, token, ..
        } => {
            let fp = invite_handlers::fingerprint_public_key(public_key);
            params.remove("public_key");
            params.insert(
                "public_key_fingerprint".to_string(),
                serde_json::Value::String(fp),
            );
            params.remove("token");
            params.insert(
                "token_fingerprint".to_string(),
                serde_json::Value::String(crate::invite::hash_token(token)),
            );
        },
        AdminRequestKind::InviteRevoke { token } => {
            params.remove("token");
            params.insert(
                "token_fingerprint".to_string(),
                serde_json::Value::String(fingerprint_revoke_input(token)),
            );
        },
        _ => {},
    }
    Some(val)
}

/// Fingerprint helper for `InviteRevoke.token`, which can be supplied
/// either as the raw token *or* as an already-fingerprinted 64-hex
/// identifier (from `astrid invite list`). The audit row stores the
/// fingerprint form unconditionally so an auditor can correlate
/// against `invites.toml` without seeing the secret.
fn fingerprint_revoke_input(token: &str) -> String {
    if token.len() == 64 && token.chars().all(|c| c.is_ascii_hexdigit()) {
        token.to_ascii_lowercase()
    } else {
        crate::invite::hash_token(token)
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
        | AdminRequestKind::GroupList
        | AdminRequestKind::InviteIssue { .. }
        | AdminRequestKind::InviteRedeem { .. }
        | AdminRequestKind::InviteList
        | AdminRequestKind::InviteRevoke { .. } => None,
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
    // infallible for shapes we accept. We strip the `public_key` field
    // out of `InviteRedeem` payloads before storing because the audit
    // shouldn't permanently embed an ed25519 key that a verifier might
    // later mistake for a system-of-record entry — the canonical copy
    // lives on `AuthConfig.public_keys`.
    let audit_params = sanitize_admin_audit_params(&req.kind);

    // `InviteRedeem` is the one variant that bypasses the capability
    // preamble: the redeemer's principal does not exist yet at the
    // moment the request arrives — the token IS the auth. The handler
    // verifies the token internally and either mints a principal or
    // rejects the request. Every redeem still produces an audit row
    // (allow OR deny) below.
    if matches!(req.kind, AdminRequestKind::InviteRedeem { .. }) {
        record_admin_audit(
            kernel,
            AdminAuditEntry {
                caller: &caller,
                method,
                required_cap,
                target_principal: None,
                params: audit_params.clone(),
                authorization: AuthorizationProof::System {
                    reason: "invite-redeem: token is the auth".to_string(),
                },
                outcome: AuditOutcome::success(),
            },
        );
        let body = handlers::dispatch(kernel, req.kind).await;
        publish_response(
            kernel,
            response_topic,
            AdminKernelResponse::for_request(request_id, body),
        );
        return;
    }

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
