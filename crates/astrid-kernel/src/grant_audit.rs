//! Audit entries for applied authority changes: capability tokens minted and
//! revoked, and principal grants (capability patterns, capsule grants, group
//! membership) added or removed.
//!
//! These entries record what was applied, after the change is saved. The
//! request that asked for it is recorded separately (an `AdminRequest` entry
//! for the admin API, approval entries for grant-on-use). Each entry is
//! chained under the principal whose authority changed.

use astrid_audit::{ApprovalScope, AuditAction, AuditOutcome, AuthorizationProof};
use astrid_capabilities::CapabilityToken;
use astrid_core::principal::PrincipalId;
use astrid_core::types::TokenId;
use tracing::warn;

/// Authorization reason for changes applied by an admin request.
pub(crate) const ADMIN_REQUEST_REASON: &str = "admin request";

/// Items in `after` but not in `before`, and items in `before` but not in
/// `after`, each in their original order.
pub(crate) fn set_diff(before: &[String], after: &[String]) -> (Vec<String>, Vec<String>) {
    let added = after
        .iter()
        .filter(|item| !before.contains(item))
        .cloned()
        .collect();
    let removed = before
        .iter()
        .filter(|item| !after.contains(item))
        .cloned()
        .collect();
    (added, removed)
}

/// Record an applied change to `target`'s grants of `kind` (`capability`,
/// `capsule` or `group`), applied through `via`. Nothing is recorded when
/// nothing changed.
pub(crate) async fn record_grant_change(
    kernel: &crate::Kernel,
    target: &PrincipalId,
    kind: &str,
    (granted, revoked): (Vec<String>, Vec<String>),
    via: &str,
    reason: &str,
) {
    if granted.is_empty() && revoked.is_empty() {
        return;
    }
    let action = AuditAction::CapabilityChanged {
        target_principal: target.clone(),
        kind: kind.to_owned(),
        granted,
        revoked,
        via: via.to_owned(),
    };
    append(kernel, Some(target), action, reason).await;
}

/// Record a minted capability token.
pub(crate) async fn record_token_created(kernel: &crate::Kernel, token: &CapabilityToken) {
    let action = AuditAction::CapabilityCreated {
        token_id: token.id.clone(),
        resource: token.resource.to_string(),
        permissions: token.permissions.clone(),
        scope: match token.scope {
            astrid_capabilities::TokenScope::Session => ApprovalScope::Session,
            astrid_capabilities::TokenScope::Persistent => ApprovalScope::Always,
        },
    };
    append(kernel, Some(&token.principal), action, ADMIN_REQUEST_REASON).await;
}

/// Record a revoked capability token. `principal` is the token's subject
/// when the token was still known.
pub(crate) async fn record_token_revoked(
    kernel: &crate::Kernel,
    principal: Option<&PrincipalId>,
    token_id: &TokenId,
    reason: &str,
) {
    let action = AuditAction::CapabilityRevoked {
        token_id: token_id.clone(),
        reason: reason.to_owned(),
    };
    append(kernel, principal, action, ADMIN_REQUEST_REASON).await;
}

/// Append a successful authority-change entry. A failed append is logged and
/// does not undo the change, matching the admin audit's continue-and-alert
/// behaviour.
async fn append(
    kernel: &crate::Kernel,
    principal: Option<&PrincipalId>,
    action: AuditAction,
    reason: &str,
) {
    let authorization = AuthorizationProof::System {
        reason: reason.to_owned(),
    };
    let session = kernel.session_id.clone();
    // Boxed so the admin handlers that await this do not carry the append's
    // state machine inline.
    let result = match principal {
        Some(principal) => {
            Box::pin(kernel.audit_log.append_with_principal(
                session,
                principal.clone(),
                action,
                authorization,
                AuditOutcome::success(),
            ))
            .await
        },
        None => {
            Box::pin(kernel.audit_log.append(
                session,
                action,
                authorization,
                AuditOutcome::success(),
            ))
            .await
        },
    };
    if let Err(error) = result {
        warn!(
            security_event = true,
            %error,
            "Failed to persist authority-change audit entry; continuing"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::set_diff;

    #[test]
    fn set_diff_reports_additions_and_removals_in_order() {
        let before = ["a".to_owned(), "b".to_owned(), "c".to_owned()];
        let after = ["c".to_owned(), "d".to_owned(), "a".to_owned()];
        assert_eq!(
            set_diff(&before, &after),
            (vec!["d".to_owned()], vec!["b".to_owned()])
        );
        assert_eq!(set_diff(&before, &before), (Vec::new(), Vec::new()));
    }
}
