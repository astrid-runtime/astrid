//! Prelude module - commonly used types for convenient import.
//!
//! Use `use astrid_approval::prelude::*;` to import all essential types.

// Action types
pub use crate::SensitiveAction;

// Request/response types
pub use crate::{ApprovalDecision, ApprovalRequest, ApprovalResponse, RequestId, RiskAssessment};

// Allowance types
pub use crate::{Allowance, AllowanceId, AllowancePattern, AllowanceStore};

// Manager types
pub use crate::{ApprovalHandler, ApprovalManager, ApprovalOutcome, ApprovalProof};

// Deferred resolution types
pub use crate::{
    ActionContext, DeferredResolution, DeferredResolutionStore, FallbackBehavior, PendingAction,
    Priority, ResolutionId,
};

// Budget types
pub use crate::{
    BudgetConfig, BudgetResult, BudgetTracker, WorkspaceBudgetSnapshot, WorkspaceBudgetTracker,
};
