//! Explicit operator recovery for ambiguous legacy resource attribution.

use super::super::handlers::{err_bad_input, err_internal, success_json};

#[cfg(test)]
mod tests;
use crate::kernel_router::{
    AdminAuditEntry, AuthorizedRequest, authorize_request, record_admin_audit,
};
use astrid_audit::{AuditOutcome, AuthorizationProof};
use astrid_core::{PrincipalId, UserUid};
use astrid_events::kernel_api::AdminResponseBody;
use std::sync::Arc;

pub(crate) async fn assign(
    kernel: &Arc<crate::Kernel>,
    caller: &PrincipalId,
    authorization: Option<&AuthorizedRequest>,
    device_key_id: Option<&str>,
    principal: PrincipalId,
    user: UserUid,
) -> AdminResponseBody {
    let (proof, body) = apply(
        kernel,
        caller,
        authorization,
        device_key_id,
        &principal,
        user,
    )
    .await;
    let outcome = match &body {
        AdminResponseBody::Error(reason) => AuditOutcome::failure(reason),
        _ => AuditOutcome::success(),
    };
    record_admin_audit(
        kernel,
        AdminAuditEntry {
            caller,
            method: "admin.quota.assign_user",
            required_cap: "quota:set",
            device_key_id,
            target_principal: Some(principal.clone()),
            params: super::super::sanitize_admin_audit_params(
                &astrid_core::kernel_api::AdminRequestKind::QuotaAssignUser { principal, user },
            ),
            authorization: proof,
            outcome,
        },
    )
    .await;
    body
}

async fn apply(
    kernel: &Arc<crate::Kernel>,
    caller: &PrincipalId,
    authorization: Option<&AuthorizedRequest>,
    device_key_id: Option<&str>,
    principal: &PrincipalId,
    user: UserUid,
) -> (AuthorizationProof, AdminResponseBody) {
    // Even self attribution spends another user's budget. Never attenuate this
    // to self:quota:set, and never borrow capabilities outside the pinned device.
    let resolved;
    let authority = if let Some(authority) = authorization {
        authority
    } else {
        resolved = match authorize_request(kernel, caller, device_key_id, "quota:set") {
            Ok(authority) => authority,
            Err(error) => {
                return (
                    AuthorizationProof::Denied {
                        reason: error.to_string(),
                    },
                    err_bad_input(error.to_string()),
                );
            },
        };
        &resolved
    };
    if let Err(error) = authority.capability_check().require("quota:set") {
        return (
            AuthorizationProof::Denied {
                reason: error.to_string(),
            },
            err_bad_input(error.to_string()),
        );
    }
    let proof = AuthorizationProof::System {
        reason: format!("policy allow: {caller} holds quota:set"),
    };
    (proof, persist(kernel, principal, user).await)
}

async fn persist(
    kernel: &Arc<crate::Kernel>,
    principal: &PrincipalId,
    user: UserUid,
) -> AdminResponseBody {
    let _guard = kernel.admin_write_lock.lock().await;
    let uid = match kernel.principal_directory.uid_for(principal) {
        Ok(uid) => uid,
        Err(error) => return err_bad_input(error.to_string()),
    };
    let graph = match kernel.ownership_store.load().await {
        Ok(graph) => graph,
        Err(error) => return err_internal(error.to_string()),
    };
    match graph.accountable_user(uid) {
        Some(existing) if existing == user => {},
        Some(_) => return err_bad_input(
            "principal already has an accountable user; this recovery command cannot transfer an active allocation".into()
        ),
        None => {
            if let Err(error) = kernel.ownership_store.assign_accountable_user(uid, None, user).await {
                return err_bad_input(error.to_string());
            }
        },
    }
    success_json(serde_json::json!({ "principal": principal, "accountable_user": user }))
}
