//! Approval request and response types.
//!
//! These types represent the internal approval system's view of approval flows.
//! They are richer than the Frontend-facing types in `astrid-core::frontend`,
//! which are simplified for UI rendering.
//!
//! The approval manager converts between internal and frontend types
//! when presenting requests to users.

use astrid_core::types::Timestamp;
use astrid_crypto::Signature;
use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

use crate::action::SensitiveAction;
use crate::allowance::Allowance;

/// Unique identifier for an approval request.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RequestId(pub Uuid);

impl RequestId {
    /// Create a new random request ID.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for RequestId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "req:{}", self.0)
    }
}

/// Assessment of the risk posed by a sensitive action.
///
/// Provides a human-readable explanation of why the action is sensitive
/// and any available mitigations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    /// Human-readable explanation of why this action requires approval.
    pub reason: String,
    /// Available mitigations that could reduce the risk.
    pub mitigations: Vec<String>,
}

impl RiskAssessment {
    /// Create a new risk assessment.
    #[must_use]
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            mitigations: Vec::new(),
        }
    }

    /// Add a mitigation.
    #[must_use]
    pub fn with_mitigation(mut self, mitigation: impl Into<String>) -> Self {
        self.mitigations.push(mitigation.into());
        self
    }

    /// Add multiple mitigations.
    #[must_use]
    pub fn with_mitigations(mut self, mitigations: impl IntoIterator<Item = String>) -> Self {
        self.mitigations.extend(mitigations);
        self
    }
}

impl fmt::Display for RiskAssessment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.reason)
    }
}

/// A request for human approval of a sensitive action.
///
/// Created when an action requires explicit human confirmation. Contains all
/// context needed for an informed decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    /// Unique request identifier.
    pub id: RequestId,
    /// The sensitive action requiring approval.
    pub action: SensitiveAction,
    /// Risk assessment for this action.
    pub assessment: RiskAssessment,
    /// Why the agent wants to perform this action.
    pub context: String,
    /// When the request was created.
    pub timestamp: Timestamp,
}

impl ApprovalRequest {
    /// Create a new approval request.
    #[must_use]
    pub fn new(action: SensitiveAction, context: impl Into<String>) -> Self {
        let reason = format!("{} operation", action.action_type());
        Self {
            id: RequestId::new(),
            action,
            assessment: RiskAssessment::new(reason),
            context: context.into(),
            timestamp: Timestamp::now(),
        }
    }

    /// Set a custom risk assessment.
    #[must_use]
    pub fn with_assessment(mut self, assessment: RiskAssessment) -> Self {
        self.assessment = assessment;
        self
    }
}

impl fmt::Display for ApprovalRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} - {}", self.action, self.context)
    }
}

/// The decision made on an approval request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "decision")]
pub enum ApprovalDecision {
    /// One-time approval — action executes, no allowance stored.
    Approve,
    /// Approved for the rest of the session — creates a session-scoped allowance.
    ApproveSession,
    /// Approved for the current workspace — creates a workspace-scoped allowance.
    ///
    /// Workspace allowances persist beyond session end but are scoped to the
    /// workspace directory. Full persistence (state.db) comes in Step 4;
    /// for now they live in `AllowanceStore` as non-session entries.
    ApproveWorkspace,
    /// Allow always — creates a persistent, permanent `CapabilityToken`
    /// (no TTL; valid until explicitly revoked).
    ///
    /// Unlike session allowances (in-memory), this creates a cryptographically
    /// signed capability token with an `approval_audit_id` chain-link.
    ApproveAlways,
    /// Create a reusable allowance (session or persistent).
    ///
    /// Boxed to keep [`ApprovalDecision`] compact — [`Allowance`] gained a
    /// [`PrincipalId`](astrid_core::principal::PrincipalId) field in Layer 4
    /// (issue #668) which pushed the unboxed variant past clippy's
    /// `large_enum_variant` threshold.
    ApproveWithAllowance(Box<Allowance>),
    /// Deny the action.
    Deny {
        /// Reason for denial.
        reason: String,
    },
}

impl ApprovalDecision {
    /// Check if this decision approves the action.
    #[must_use]
    pub fn is_approved(&self) -> bool {
        !matches!(self, Self::Deny { .. })
    }

    /// Check if this decision creates a persistent grant (allowance or capability token).
    #[must_use]
    pub fn creates_grant(&self) -> bool {
        matches!(
            self,
            Self::ApproveSession
                | Self::ApproveWorkspace
                | Self::ApproveAlways
                | Self::ApproveWithAllowance(_)
        )
    }

    /// Check if this decision creates a persistent capability token.
    #[must_use]
    pub fn creates_capability(&self) -> bool {
        matches!(self, Self::ApproveAlways)
    }

    /// Get the denial reason, if this is a denial.
    #[must_use]
    pub fn denial_reason(&self) -> Option<&str> {
        match self {
            Self::Deny { reason } => Some(reason),
            _ => None,
        }
    }
}

impl fmt::Display for ApprovalDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Approve => write!(f, "Approve (once)"),
            Self::ApproveSession => write!(f, "Approve (session)"),
            Self::ApproveWorkspace => write!(f, "Approve (workspace)"),
            Self::ApproveAlways => write!(f, "Approve (always)"),
            Self::ApproveWithAllowance(a) => write!(f, "Approve (allowance: {})", a.id),
            Self::Deny { reason } => write!(f, "Deny: {reason}"),
        }
    }
}

/// Response to an approval request, including the decision and optional signature.
///
/// The signature field allows the user to cryptographically sign their approval
/// for non-repudiation in the audit trail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalResponse {
    /// The request this response addresses.
    pub request_id: RequestId,
    /// The decision made.
    pub decision: ApprovalDecision,
    /// When the decision was made.
    pub timestamp: Timestamp,
    /// Optional cryptographic signature from the user.
    pub signature: Option<Signature>,
}

impl ApprovalResponse {
    /// Create a new approval response.
    #[must_use]
    pub fn new(request_id: RequestId, decision: ApprovalDecision) -> Self {
        Self {
            request_id,
            decision,
            timestamp: Timestamp::now(),
            signature: None,
        }
    }

    /// Attach a user signature.
    #[must_use]
    pub fn with_signature(mut self, signature: Signature) -> Self {
        self.signature = Some(signature);
        self
    }

    /// Check if this response is an approval.
    #[must_use]
    pub fn is_approved(&self) -> bool {
        self.decision.is_approved()
    }

    /// Check if the response is signed.
    #[must_use]
    pub fn is_signed(&self) -> bool {
        self.signature.is_some()
    }
}

impl fmt::Display for ApprovalResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} -> {}", self.request_id, self.decision)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::SensitiveAction;

    #[test]
    fn test_request_id() {
        let id1 = RequestId::new();
        let id2 = RequestId::new();
        assert_ne!(id1, id2);
        assert!(id1.to_string().starts_with("req:"));
    }

    #[test]
    fn test_risk_assessment() {
        let assessment = RiskAssessment::new("File deletion is irreversible")
            .with_mitigation("Check file is not in use".to_string())
            .with_mitigation("Verify backup exists".to_string());

        assert_eq!(assessment.mitigations.len(), 2);
        assert!(
            assessment
                .to_string()
                .contains("File deletion is irreversible")
        );
    }

    #[test]
    fn test_approval_request_creation() {
        let action = SensitiveAction::FileDelete {
            path: "/home/user/important.txt".to_string(),
        };
        let request = ApprovalRequest::new(action, "Cleaning up temporary files");

        assert_eq!(request.context, "Cleaning up temporary files");
        assert!(!request.timestamp.is_future());
    }

    #[test]
    fn test_approval_request_custom_assessment() {
        let action = SensitiveAction::McpToolCall {
            server: "filesystem".to_string(),
            tool: "read_file".to_string(),
        };
        let assessment = RiskAssessment::new("Reading a known safe file");
        let request =
            ApprovalRequest::new(action, "Need file contents").with_assessment(assessment);

        assert_eq!(request.assessment.reason, "Reading a known safe file");
    }

    #[test]
    fn test_approval_decision_approve() {
        let decision = ApprovalDecision::Approve;
        assert!(decision.is_approved());
        assert!(!decision.creates_grant());
        assert!(decision.denial_reason().is_none());
    }

    #[test]
    fn test_approval_decision_session() {
        let decision = ApprovalDecision::ApproveSession;
        assert!(decision.is_approved());
        assert!(decision.creates_grant());
    }

    #[test]
    fn test_approval_decision_deny() {
        let decision = ApprovalDecision::Deny {
            reason: "Too risky".to_string(),
        };
        assert!(!decision.is_approved());
        assert!(!decision.creates_grant());
        assert_eq!(decision.denial_reason(), Some("Too risky"));
    }

    #[test]
    fn test_approval_response() {
        let request_id = RequestId::new();
        let response = ApprovalResponse::new(request_id.clone(), ApprovalDecision::Approve);

        assert!(response.is_approved());
        assert!(!response.is_signed());
        assert_eq!(response.request_id, request_id);
    }

    #[test]
    fn test_approval_response_display() {
        let request_id = RequestId::new();
        let response = ApprovalResponse::new(
            request_id,
            ApprovalDecision::Deny {
                reason: "Not allowed".to_string(),
            },
        );

        let display = response.to_string();
        assert!(display.contains("Deny"));
        assert!(display.contains("Not allowed"));
    }

    #[test]
    fn test_approval_request_serialization() {
        let action = SensitiveAction::NetworkRequest {
            capsule_id: "react".to_string(),
            host: "api.example.com".to_string(),
            port: 443,
        };
        let request = ApprovalRequest::new(action, "Fetching API data");
        let json = serde_json::to_string(&request).unwrap();
        let deserialized: ApprovalRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(request.id, deserialized.id);
        assert_eq!(request.context, deserialized.context);
    }

    #[test]
    fn test_approval_decision_serialization() {
        let decision = ApprovalDecision::Deny {
            reason: "test".to_string(),
        };
        let json = serde_json::to_string(&decision).unwrap();
        let deserialized: ApprovalDecision = serde_json::from_str(&json).unwrap();
        assert!(!deserialized.is_approved());
    }

    #[test]
    fn test_approval_decision_with_allowance_serialization() {
        use crate::allowance::{AllowanceId, AllowancePattern};
        use astrid_crypto::KeyPair;

        let keypair = KeyPair::generate();
        let allowance = Allowance {
            id: AllowanceId::new(),
            principal: astrid_core::principal::PrincipalId::default(),
            action_pattern: AllowancePattern::ExactTool {
                server: "filesystem".to_string(),
                tool: "read_file".to_string(),
            },
            created_at: Timestamp::now(),
            expires_at: None,
            max_uses: None,
            uses_remaining: None,
            session_only: true,
            workspace_root: None,
            signature: keypair.sign(b"test-allowance"),
        };
        let decision = ApprovalDecision::ApproveWithAllowance(Box::new(allowance));

        let json = serde_json::to_string(&decision).unwrap();
        let deserialized: ApprovalDecision = serde_json::from_str(&json).unwrap();
        assert!(deserialized.is_approved());
        assert!(deserialized.creates_grant());
    }

    #[test]
    fn test_all_decision_variants_serialize() {
        // Verify unit variants roundtrip correctly with internal tagging
        let approve_json = serde_json::to_string(&ApprovalDecision::Approve).unwrap();
        let approve: ApprovalDecision = serde_json::from_str(&approve_json).unwrap();
        assert!(approve.is_approved());
        assert!(!approve.creates_grant());

        let session_json = serde_json::to_string(&ApprovalDecision::ApproveSession).unwrap();
        let session: ApprovalDecision = serde_json::from_str(&session_json).unwrap();
        assert!(session.is_approved());
        assert!(session.creates_grant());
    }
}
