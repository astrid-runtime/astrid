//! Astrid Approval - Human-in-the-loop approval system.
//!
//! This crate provides types and logic for the approval workflow that gates
//! sensitive agent operations behind explicit human confirmation.
//!
//! # Components
//!
//! - **Approval Types**: [`SensitiveAction`], [`RiskAssessment`],
//!   [`ApprovalRequest`], [`ApprovalDecision`], [`ApprovalResponse`]
//! - **Allowance System**: [`Allowance`], [`AllowancePattern`], `AllowanceStore`
//! - **Approval Manager**: Orchestrates the full approval flow
//! - **Budget Tracking**: Session and per-action spending limits
//!
//! Astrid's security is *decomposed*: these are the human-in-the-loop pieces.
//! Authorization is enforced by independent, per-area mechanisms (the WASM
//! sandbox, the manifest allowlist host gates, the IPC ACL, capability tokens,
//! and budgets) — not a single unified gate. See issue #991.
//!
//! # Relationship to Frontend Types
//!
//! The approval types in this crate are the **internal** representation used by
//! the security system. The types in [`astrid_core::types`] (`ApprovalRequest`,
//! `ApprovalDecision`, `ApprovalOption`) are the shared vocabulary. The approval
//! manager converts between them when presenting requests to users.
//!
//! # Example
//!
//! ```
//! use astrid_approval::{SensitiveAction, ApprovalRequest, ApprovalDecision, RiskAssessment};
//!
//! // Classify a risky action
//! let action = SensitiveAction::FileDelete {
//!     path: "/home/user/important.txt".to_string(),
//! };
//!
//! // Create a request with context
//! let request = ApprovalRequest::new(action, "Cleaning up temporary files");
//!
//! // Decisions
//! let approved = ApprovalDecision::Approve;
//! assert!(approved.is_approved());
//!
//! let denied = ApprovalDecision::Deny { reason: "Too risky".to_string() };
//! assert!(!denied.is_approved());
//! ```

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![deny(unreachable_pub)]
#![deny(clippy::unwrap_used)]
#![cfg_attr(test, allow(clippy::unwrap_used))]

pub mod prelude;

pub mod action;
pub mod allowance;
pub mod budget;
pub mod deferred;
/// Error types and results for the approval module.
pub mod error;
pub mod manager;
pub mod request;

pub use action::SensitiveAction;
pub use allowance::{Allowance, AllowanceId, AllowancePattern, AllowanceStore};
pub use budget::{
    BudgetConfig, BudgetResult, BudgetTracker, WorkspaceBudgetSnapshot, WorkspaceBudgetTracker,
};
pub use deferred::{
    ActionContext, DeferredResolution, DeferredResolutionStore, FallbackBehavior, PendingAction,
    Priority, ResolutionId,
};
pub use error::{ApprovalError, ApprovalResult};
pub use manager::{ApprovalHandler, ApprovalManager, ApprovalOutcome, ApprovalProof};
pub use request::{ApprovalDecision, ApprovalRequest, ApprovalResponse, RequestId, RiskAssessment};
