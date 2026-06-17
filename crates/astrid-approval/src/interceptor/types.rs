use astrid_audit::AuditEntryId;
use astrid_core::types::TokenId;

/// Budget warning info to surface to the user.
#[derive(Debug, Clone)]
pub struct BudgetWarning {
    /// The running total spent.
    pub current_spend: f64,
    /// The maximum allowed session spend.
    pub session_max: f64,
    /// Percentage of budget used (0.0 to 1.0).
    pub percent_used: f64,
}

/// The result of a successful security intercept.
#[derive(Debug)]
pub struct InterceptResult {
    /// How the action was authorized.
    pub proof: InterceptProof,
    /// The audit entry ID for this action.
    pub audit_id: AuditEntryId,
    /// Optional budget warning (e.g. nearing limit).
    pub budget_warning: Option<BudgetWarning>,
}

/// How an action was authorized through the interceptor.
#[derive(Debug)]
pub enum InterceptProof {
    /// Authorized by an existing capability token.
    Capability {
        /// Token ID that authorized the action.
        token_id: TokenId,
    },
    /// Authorized by an existing allowance.
    Allowance {
        /// ID of the allowance that matched.
        allowance_id: crate::allowance::AllowanceId,
    },
    /// Authorized by a one-time human approval.
    UserApproval {
        /// Audit entry ID of the approval event.
        approval_audit_id: AuditEntryId,
    },
    /// Authorized by a blanket session approval.
    SessionApproval {
        /// ID of the created session allowance.
        allowance_id: crate::allowance::AllowanceId,
    },
    /// Authorized by a persistent workspace approval.
    WorkspaceApproval {
        /// ID of the created workspace allowance.
        allowance_id: crate::allowance::AllowanceId,
    },
    /// A new capability token was minted ("Allow Always").
    CapabilityCreated {
        /// The new capability token ID.
        token_id: TokenId,
        /// Audit entry ID of the approval event (chain-link proof).
        approval_audit_id: AuditEntryId,
    },
    /// Policy allowed without further checks (low-risk, no approval needed).
    PolicyAllowed,
}
