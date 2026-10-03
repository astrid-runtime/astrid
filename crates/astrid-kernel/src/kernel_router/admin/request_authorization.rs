//! Capability authorization of admin requests and the audit rows that
//! record each decision.

use std::sync::Arc;

use astrid_audit::{AuditOutcome, AuthorizationProof};
use astrid_core::principal::PrincipalId;
use astrid_events::kernel_api::AdminRequestKind;
use tracing::warn;

use super::{audit_handlers, pair_device_handlers};
use crate::kernel_router::{
    AdminAuditEntry, AuthorizedRequest, authorize_request, record_admin_audit,
};

pub(super) struct AdminAuthorizationContext<'a> {
    pub(super) caller: &'a PrincipalId,
    pub(super) device_key_id: Option<&'a str>,
    pub(super) method: &'static str,
    pub(super) required_cap: &'static str,
    pub(super) target_principal: Option<&'a PrincipalId>,
    pub(super) audit_params: Option<&'a serde_json::Value>,
}

fn allowed_admin_authorization(context: &AdminAuthorizationContext<'_>) -> AuthorizationProof {
    AuthorizationProof::System {
        reason: format!(
            "policy allow: {} holds {}",
            context.caller, context.required_cap
        ),
    }
}

async fn record_admin_authorization_failure(
    kernel: &Arc<crate::Kernel>,
    context: &AdminAuthorizationContext<'_>,
    error: &str,
) {
    warn!(
        security_event = true,
        method = context.method,
        principal = %context.caller,
        required = context.required_cap,
        error,
        "Permission check denied admin request"
    );
    record_admin_audit(
        kernel,
        AdminAuditEntry {
            caller: context.caller,
            method: context.method,
            required_cap: context.required_cap,
            device_key_id: context.device_key_id,
            target_principal: context.target_principal.cloned(),
            params: context.audit_params.cloned(),
            authorization: AuthorizationProof::Denied {
                reason: error.to_string(),
            },
            outcome: AuditOutcome::failure(error),
        },
    )
    .await;
}

/// Record an authorized request that failed on its input or in its handler.
pub(super) async fn record_admin_request_failure(
    kernel: &Arc<crate::Kernel>,
    context: &AdminAuthorizationContext<'_>,
    error: &str,
) {
    record_admin_audit(
        kernel,
        AdminAuditEntry {
            caller: context.caller,
            method: context.method,
            required_cap: context.required_cap,
            device_key_id: context.device_key_id,
            target_principal: context.target_principal.cloned(),
            params: context.audit_params.cloned(),
            authorization: allowed_admin_authorization(context),
            outcome: AuditOutcome::failure(error),
        },
    )
    .await;
}

pub(super) async fn authorize_admin_request(
    kernel: &Arc<crate::Kernel>,
    context: &AdminAuthorizationContext<'_>,
    kind: &AdminRequestKind,
) -> Result<AuthorizedRequest, String> {
    let authorization = match authorize_request(
        kernel,
        context.caller,
        context.device_key_id,
        context.required_cap,
    ) {
        Ok(authorization) => authorization,
        Err(error) => {
            let error = error.to_string();
            record_admin_authorization_failure(kernel, context, &error).await;
            return Err(error);
        },
    };

    let preflight = if let AdminRequestKind::PairDeviceIssue {
        expires_secs,
        scope,
        ..
    } = kind
    {
        pair_device_handlers::preflight_pair_device_issue(&authorization, *expires_secs, scope)
    } else {
        Ok(())
    };
    match preflight {
        Ok(()) => {},
        Err(pair_device_handlers::PairIssuePreflightError::BadInput(error)) => {
            record_admin_request_failure(kernel, context, &error).await;
            return Err(error);
        },
        Err(pair_device_handlers::PairIssuePreflightError::Unauthorized(error)) => {
            record_admin_authorization_failure(kernel, context, &error).await;
            return Err(error);
        },
    }
    // Anchoring polls read the audit log itself. Denials above stay audited,
    // and the caller records the request if its handler fails.
    // Quota changes also require a locked comparison with the current allocation.
    // Their handler records the final result after that check and persistence.
    if audit_handlers::omit_success_admin_audit(kind)
        || matches!(kind, AdminRequestKind::QuotaSet { .. })
    {
        return Ok(authorization);
    }

    record_admin_audit(
        kernel,
        AdminAuditEntry {
            caller: context.caller,
            method: context.method,
            required_cap: context.required_cap,
            device_key_id: context.device_key_id,
            target_principal: context.target_principal.cloned(),
            params: context.audit_params.cloned(),
            authorization: allowed_admin_authorization(context),
            outcome: AuditOutcome::success(),
        },
    )
    .await;
    Ok(authorization)
}
