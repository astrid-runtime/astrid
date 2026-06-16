//! Capability-token lifecycle admin handlers (issue #929).
//!
//! Split out of [`super::handlers`] to keep that file under the repo's
//! per-file line cap and to mirror the sibling layout (see
//! [`super::quota`]). These three handlers let an operator pre-grant tool
//! access by minting a signed [`CapabilityToken`] for a principal, list a
//! principal's tokens, and revoke a token by id — so an agent never has to
//! hit a per-use approval elicitation for a pre-authorized resource.
//!
//! # Trust model
//!
//! Minted tokens are signed by [`Kernel::runtime_key`](crate::Kernel) — the
//! exact key the approval interceptor's `CapabilityValidator` trusts as
//! issuer — so a minted token authorizes immediately on the secure path.
//! The token carries `principal` in its signed payload (issue #668), so a
//! token minted for Alice can never authorize Bob even if copied forward.
//! Revocation is global and final. Every call is gated by an admin-tier
//! capability (`caps:token:{mint,revoke,list}`) and audited automatically by
//! [`record_admin_audit`](super::record_admin_audit) — these handlers add no
//! audit calls of their own.

use std::sync::Arc;

use astrid_capabilities::{AuditEntryId, CapabilityToken, ResourcePattern, TokenScope};
use astrid_core::principal::PrincipalId;
use astrid_core::types::{Permission, TokenId};
use astrid_events::kernel_api::{AdminRequestKind, AdminResponseBody};

use super::handlers::{
    err_bad_input, err_internal, principal_profile_path, require_principal_exists, success_json,
};

/// Route the three capability-token admin variants to their handlers.
///
/// `req` is guaranteed by the caller ([`super::handlers::dispatch`]) to be one
/// of the `CapsToken*` variants; the unreachable arm keeps the match total.
pub(super) async fn dispatch(
    kernel: &Arc<crate::Kernel>,
    req: AdminRequestKind,
) -> AdminResponseBody {
    match req {
        AdminRequestKind::CapsTokenMint {
            principal,
            resource,
            permission,
            ttl_secs,
        } => caps_token_mint(kernel, principal, resource, permission, ttl_secs).await,
        AdminRequestKind::CapsTokenRevoke { token_id } => caps_token_revoke(kernel, &token_id),
        AdminRequestKind::CapsTokenList { principal } => caps_token_list(kernel, &principal),
        other => err_internal(format!(
            "caps_tokens::dispatch received a non-token variant: {other:?}"
        )),
    }
}

/// Parse an optional permission string, defaulting to [`Permission::Invoke`].
///
/// `mcp://` tool grants are invocations, so `invoke` is the natural default
/// when the operator does not name a permission. An unrecognized string is a
/// hard bad-input error rather than a silent fallback — a typo'd permission
/// must not mint a token granting the wrong (or no) access.
fn parse_permission(permission: Option<&str>) -> Result<Permission, AdminResponseBody> {
    let Some(raw) = permission else {
        return Ok(Permission::Invoke);
    };
    match raw.trim().to_ascii_lowercase().as_str() {
        "read" => Ok(Permission::Read),
        "write" => Ok(Permission::Write),
        "execute" => Ok(Permission::Execute),
        "delete" => Ok(Permission::Delete),
        "invoke" => Ok(Permission::Invoke),
        "list" => Ok(Permission::List),
        "create" => Ok(Permission::Create),
        other => Err(err_bad_input(format!(
            "unknown permission {other:?} (expected one of: read, write, execute, delete, \
             invoke, list, create)"
        ))),
    }
}

/// Mint a signed capability token for `principal`.
pub(super) async fn caps_token_mint(
    kernel: &Arc<crate::Kernel>,
    principal: PrincipalId,
    resource: String,
    permission: Option<String>,
    ttl_secs: Option<u64>,
) -> AdminResponseBody {
    let permission = match parse_permission(permission.as_deref()) {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let resource_pattern = match ResourcePattern::new(resource.clone()) {
        Ok(r) => r,
        Err(e) => return err_bad_input(format!("invalid resource pattern {resource:?}: {e}")),
    };

    // Take the admin write lock and verify the target principal exists, so a
    // typo'd name cannot mint a token nobody can use (and so the mint is
    // serialized against concurrent agent.delete of the same principal).
    let _guard = kernel.admin_write_lock.lock().await;
    let path = principal_profile_path(kernel, &principal);
    if let Err(msg) = require_principal_exists(&principal, &path) {
        return err_bad_input(msg);
    }

    // The token API takes a `chrono::Duration` (signed). Convert the
    // operator-supplied seconds via the non-panicking `try_seconds`:
    // `Duration::seconds` PANICS for a value beyond chrono's internal bound
    // (~9.2e15 s, far below `i64::MAX`), so guarding only the `u64`→`i64` cast
    // would still let a large `ttl_secs` crash the handler. An out-of-range
    // value must be a clean bad-input error, not a panic.
    let ttl = match ttl_secs {
        None => None,
        Some(secs) => {
            let Some(d) = i64::try_from(secs)
                .ok()
                .and_then(chrono::Duration::try_seconds)
            else {
                return err_bad_input(format!("ttl_secs {secs} is out of range"));
            };
            Some(d)
        },
    };
    // A fresh audit id: the admin action's own provenance is captured by
    // `record_admin_audit`; the token's `approval_audit_id` just needs a
    // non-approval provenance marker (there was no human approval).
    let token = CapabilityToken::create(
        resource_pattern,
        vec![permission],
        TokenScope::Persistent,
        kernel.runtime_key.key_id(),
        AuditEntryId::new(),
        &kernel.runtime_key,
        ttl,
        principal.clone(),
    );
    let token_id = token.id.0.to_string();
    let expires_at = token.expires_at.map(|t| t.to_string());

    if let Err(e) = kernel.capabilities.add(token) {
        return err_internal(format!("failed to store capability token: {e}"));
    }

    success_json(serde_json::json!({
        "token_id": token_id,
        "resource": resource,
        "permission": permission.to_string(),
        "expires_at": expires_at,
        "principal": principal.as_str(),
    }))
}

/// Revoke a capability token by id. Global and final.
pub(super) fn caps_token_revoke(kernel: &Arc<crate::Kernel>, token_id: &str) -> AdminResponseBody {
    let parsed = match uuid::Uuid::parse_str(token_id.trim()) {
        Ok(u) => TokenId::from_uuid(u),
        Err(e) => return err_bad_input(format!("invalid token id {token_id:?}: {e}")),
    };
    // `revoke` is idempotent: it writes the global revoked marker even for an
    // id with no live token (best-effort delete of the primary row). So an
    // error here is a genuine storage failure, not "unknown token".
    if let Err(e) = kernel.capabilities.revoke(&parsed) {
        return err_internal(format!("failed to revoke token {token_id:?}: {e}"));
    }
    success_json(serde_json::json!({
        "token_id": token_id,
        "revoked": true,
    }))
}

/// List the (non-revoked, non-expired) tokens minted for `principal`.
pub(super) fn caps_token_list(
    kernel: &Arc<crate::Kernel>,
    principal: &PrincipalId,
) -> AdminResponseBody {
    let all = match kernel.capabilities.list_tokens() {
        Ok(t) => t,
        Err(e) => return err_internal(format!("failed to list tokens: {e}")),
    };
    let tokens: Vec<serde_json::Value> = all
        .into_iter()
        .filter(|t| t.principal == *principal)
        .map(|t| {
            serde_json::json!({
                "token_id": t.id.0.to_string(),
                "resource": t.resource.as_str(),
                "permissions": t.permissions.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "scope": t.scope.to_string(),
                "issued_at": t.issued_at.to_string(),
                "expires_at": t.expires_at.map(|e| e.to_string()),
            })
        })
        .collect();
    success_json(serde_json::json!({
        "principal": principal.as_str(),
        "tokens": tokens,
    }))
}
