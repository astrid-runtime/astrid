//! Audit records for approval checks (command approvals and local-egress
//! consent).
//!
//! Each check records exactly one decision. When the host has to ask the
//! user, it first appends the request durably (and waits for it), then
//! publishes the prompt; the decision is appended durably too and carries the
//! request id and the request entry's id, so the two are linked on the log. A
//! check answered by an existing grant records only the decision, through the
//! host-audit queue, with how it was reached.

use std::sync::Arc;

use astrid_core::principal::PrincipalId;
use tokio::sync::Semaphore;

use crate::audit_sink::{
    HostApprovalDecision, HostApprovalScope, HostAuditEvent, HostAuditOutcome, HostAuditReceipt,
    HostAuditSink,
};
use crate::engine::wasm::host::util;
use crate::engine::wasm::host_state::HostState;

/// The audit trail of one approval check. Dropping it after a prompt was
/// issued but before a decision was recorded records a denial, so every
/// prompt on the log has a decision.
pub(crate) struct ApprovalAudit {
    sink: Option<Arc<dyn HostAuditSink>>,
    principal: PrincipalId,
    action: String,
    resource: String,
    request_id: Option<String>,
    request: Option<HostAuditReceipt>,
    decided: bool,
    runtime_handle: tokio::runtime::Handle,
    blocking_semaphore: Arc<Semaphore>,
}

impl ApprovalAudit {
    /// Start the audit trail of a check of `action` on `resource`.
    pub(crate) fn new(
        state: &HostState,
        principal: &PrincipalId,
        action: &str,
        resource: &str,
    ) -> Self {
        Self {
            sink: state.audit_sink.clone(),
            principal: principal.clone(),
            action: action.to_owned(),
            resource: resource.to_owned(),
            request_id: None,
            request: None,
            decided: false,
            runtime_handle: state.runtime_handle.clone(),
            blocking_semaphore: Arc::clone(&state.blocking_semaphore),
        }
    }

    /// Record the prompt `request_id` and wait until the entry is durable.
    /// Call before the prompt is published.
    pub(crate) fn requested(&mut self, request_id: &str) {
        self.request_id = Some(request_id.to_owned());
        let Some(sink) = self.sink.as_ref() else {
            return;
        };
        let event = HostAuditEvent::ApprovalRequested {
            request_id,
            action: &self.action,
            resource: &self.resource,
        };
        self.request = Some(util::bounded_block_on(
            &self.runtime_handle,
            &self.blocking_semaphore,
            sink.commit(&self.principal, event, HostAuditOutcome::Allowed),
        ));
    }

    /// Record a grant of `scope`, reached `via`.
    pub(crate) fn granted(&mut self, scope: HostApprovalScope, via: &str) {
        self.decide(Some(scope), via, HostAuditOutcome::Allowed, true);
    }

    /// Record a denial, reached `via`, for `reason`.
    pub(crate) fn denied(&mut self, via: &str, reason: &str) {
        self.decide(None, via, HostAuditOutcome::Denied(reason), true);
    }

    /// Record the decision. The answer to a committed prompt is appended
    /// durably when `may_block` allows it; everything else is queued.
    fn decide(
        &mut self,
        scope: Option<HostApprovalScope>,
        via: &str,
        outcome: HostAuditOutcome<'_>,
        may_block: bool,
    ) {
        if self.decided {
            return;
        }
        self.decided = true;
        let Some(sink) = self.sink.as_ref() else {
            return;
        };
        let event = HostAuditEvent::ApprovalDecided(HostApprovalDecision {
            request_id: self.request_id.as_deref(),
            request: self.request.as_ref(),
            action: &self.action,
            resource: &self.resource,
            scope,
            via,
        });
        if may_block && self.request.is_some() {
            util::bounded_block_on(
                &self.runtime_handle,
                &self.blocking_semaphore,
                sink.commit(&self.principal, event, outcome),
            );
        } else {
            sink.record(&self.principal, event, outcome);
        }
    }
}

impl Drop for ApprovalAudit {
    fn drop(&mut self) {
        // Never block in drop: an unanswered prompt's denial is queued.
        if self.request_id.is_some() {
            self.decide(
                None,
                "error",
                HostAuditOutcome::Denied("no decision was applied"),
                false,
            );
        }
    }
}
