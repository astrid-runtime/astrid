//! Apply quota changes before recording their final authorization and outcome.

use super::super::handlers::{err_bad_input, success_json};
use super::{is_attenuation, principal_profile_path, require_principal_exists};
use crate::kernel_router::{
    AdminAuditEntry, AuthorizedRequest, authorize_request, record_admin_audit,
};
use astrid_audit::{AuditOutcome, AuthorizationProof};
use astrid_core::{
    PrincipalId,
    profile::{PrincipalProfile, Quotas},
};
use astrid_events::kernel_api::{AdminRequestKind, AdminResponseBody};
use std::sync::Arc;

enum SetError {
    Denied {
        required: &'static str,
        reason: String,
    },
    Failed {
        required: &'static str,
        reason: String,
    },
}

pub(in crate::kernel_router::admin) async fn quota_set(
    kernel: &Arc<crate::Kernel>,
    caller: &PrincipalId,
    authorization: Option<&AuthorizedRequest>,
    device_key_id: Option<&str>,
    principal: PrincipalId,
    quotas: Quotas,
) -> AdminResponseBody {
    let params = super::super::sanitize_admin_audit_params(&AdminRequestKind::QuotaSet {
        principal: principal.clone(),
        quotas: quotas.clone(),
    });
    let result = apply(
        kernel,
        caller,
        authorization,
        device_key_id,
        principal.clone(),
        quotas,
    )
    .await;
    let (required_cap, proof, outcome, body) = match result {
        Ok(required) => (
            required,
            AuthorizationProof::System {
                reason: format!("policy allow: {caller} holds {required}"),
            },
            AuditOutcome::success(),
            success_json(serde_json::json!({ "principal": principal.as_str() })),
        ),
        Err(SetError::Denied { required, reason }) => (
            required,
            AuthorizationProof::Denied {
                reason: reason.clone(),
            },
            AuditOutcome::failure(&reason),
            err_bad_input(reason),
        ),
        Err(SetError::Failed { required, reason }) => (
            required,
            AuthorizationProof::System {
                reason: format!("quota request failed validation or persistence for {caller}"),
            },
            AuditOutcome::failure(&reason),
            err_bad_input(reason),
        ),
    };
    record_admin_audit(
        kernel,
        AdminAuditEntry {
            caller,
            method: "admin.quota.set",
            required_cap,
            device_key_id,
            target_principal: Some(principal),
            params,
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
    principal: PrincipalId,
    quotas: Quotas,
) -> Result<&'static str, SetError> {
    let required = if caller == &principal {
        "self:quota:set"
    } else {
        "quota:set"
    };
    // Validate before taking the write lock — quick reject on bad input.
    if let Err(e) = quotas.validate() {
        return Err(SetError::Failed {
            required,
            reason: format!("quotas rejected: {e}"),
        });
    }

    let _guard = kernel.admin_write_lock.lock().await;
    let resolved;
    let authorization = if let Some(authorization) = authorization {
        authorization
    } else {
        resolved = match authorize_request(kernel, caller, device_key_id, required) {
            Ok(authorization) => authorization,
            Err(error) => {
                return Err(SetError::Denied {
                    required,
                    reason: error.to_string(),
                });
            },
        };
        &resolved
    };
    let check = authorization.capability_check();
    if let Err(error) = check.require(required) {
        return Err(SetError::Denied {
            required,
            reason: error.to_string(),
        });
    }
    let path = principal_profile_path(kernel, &principal);
    if let Err(msg) = require_principal_exists(&principal, &path) {
        return Err(SetError::Failed {
            required,
            reason: msg,
        });
    }
    let mut profile = match PrincipalProfile::load_from_path(&path) {
        Ok(p) => p,
        Err(e) => {
            return Err(SetError::Failed {
                required,
                reason: format!("profile error for {principal}: {e}"),
            });
        },
    };
    // Self authority can attenuate an allocation, not mint resources. Compare
    // against the current durable allocation under the write lock, not the
    // authorization snapshot: another request may already have lowered it.
    // Global authority remains subject to the authenticating device's scope.
    let required = if is_attenuation(&quotas, &profile.quotas) {
        required
    } else {
        "quota:set"
    };
    if let Err(error) = check.require(required) {
        return Err(SetError::Denied {
            required,
            reason: format!("increasing resource quotas requires quota:set: {error}"),
        });
    }
    profile.quotas = quotas;
    if let Err(e) = profile.save_to_path(&path) {
        return Err(SetError::Failed {
            required,
            reason: format!("profile error for {principal}: {e}"),
        });
    }
    kernel.profile_cache.invalidate(&principal);
    Ok(required)
}
