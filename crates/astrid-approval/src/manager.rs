//! Approval manager — orchestrates the full approval flow.
//!
//! The [`ApprovalManager`] coordinates between:
//! - The [`AllowanceStore`] (pre-approved patterns)
//! - The [`ApprovalHandler`] trait (UI implementations)
//! - The [`DeferredResolutionStore`] (queued actions for absent users)
//!
//! # Approval Flow
//!
//! 1. Check if an existing allowance covers the action
//! 2. If yes, consume a use and return `ApprovalOutcome::Allowed`
//! 3. If no, send an `ApprovalRequest` to the handler
//! 4. Wait for response (with configurable timeout)
//! 5. If timeout and handler unavailable, queue for deferred resolution
//! 6. If approved with allowance, store the allowance
//! 7. Return the outcome

use astrid_core::principal::PrincipalId;
use async_trait::async_trait;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

use crate::action::SensitiveAction;
use crate::allowance::AllowanceStore;
use crate::deferred::{
    ActionContext, DeferredResolution, DeferredResolutionStore, FallbackBehavior, PendingAction,
    Priority, ResolutionId,
};
use crate::request::{ApprovalDecision, ApprovalRequest, ApprovalResponse};

/// Default approval timeout (5 minutes).
const DEFAULT_TIMEOUT: Duration = Duration::from_mins(5);

/// Trait for UI implementations that present approval requests to users.
///
/// Different frontends (CLI, Discord, Web) implement this trait to provide
/// their own approval UX.
///
/// # Example
///
/// ```rust,ignore
/// use astrid_approval::manager::ApprovalHandler;
/// use astrid_approval::request::{ApprovalRequest, ApprovalResponse};
///
/// struct CliHandler;
///
/// #[async_trait::async_trait]
/// impl ApprovalHandler for CliHandler {
///     async fn request_approval(&self, request: ApprovalRequest) -> Option<ApprovalResponse> {
///         // Present to user via terminal...
///         None // User didn't respond
///     }
///
///     fn is_available(&self) -> bool {
///         true // CLI is always available when running
///     }
/// }
/// ```
#[async_trait]
pub trait ApprovalHandler: Send + Sync {
    /// Present an approval request to the user and wait for a response.
    ///
    /// Returns `None` if the user did not respond (timeout, unavailable, etc.).
    async fn request_approval(&self, request: ApprovalRequest) -> Option<ApprovalResponse>;

    /// Check if the handler is currently available to receive requests.
    ///
    /// Returns `false` if the user is offline, the frontend is disconnected, etc.
    fn is_available(&self) -> bool;
}

/// The outcome of an approval check.
#[derive(Debug)]
pub enum ApprovalOutcome {
    /// Action is allowed — proceed.
    Allowed {
        /// How the action was authorized.
        proof: ApprovalProof,
    },
    /// Action was denied by the user.
    Denied {
        /// Reason for denial.
        reason: String,
    },
    /// Action was deferred — queued for later resolution.
    Deferred {
        /// Resolution ID for tracking.
        resolution_id: ResolutionId,
        /// What fallback was taken.
        fallback: FallbackBehavior,
    },
}

impl ApprovalOutcome {
    /// Check if this outcome allows the action to proceed.
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed { .. })
    }

    /// Check if this outcome denies the action.
    #[must_use]
    pub fn is_denied(&self) -> bool {
        matches!(self, Self::Denied { .. })
    }

    /// Check if this outcome deferred the action.
    #[must_use]
    pub fn is_deferred(&self) -> bool {
        matches!(self, Self::Deferred { .. })
    }
}

/// How an action was authorized through the approval system.
#[derive(Debug)]
pub enum ApprovalProof {
    /// Authorized by an existing allowance.
    Allowance {
        /// ID of the allowance that matched.
        allowance_id: crate::allowance::AllowanceId,
    },
    /// Authorized by a one-time user approval.
    OneTimeApproval,
    /// Authorized by a session approval (allowance was created).
    SessionApproval {
        /// ID of the newly created allowance.
        allowance_id: crate::allowance::AllowanceId,
    },
    /// Approved for the workspace scope (survives session end).
    WorkspaceApproval {
        /// ID of the newly created allowance.
        allowance_id: crate::allowance::AllowanceId,
    },
    /// Authorized by "Allow Always" — the caller (the kernel) should create a
    /// persistent `CapabilityToken` with an `approval_audit_id` chain-link.
    AlwaysAllow,
    /// Authorized with a custom allowance created by the user.
    CustomAllowance {
        /// ID of the newly created allowance.
        allowance_id: crate::allowance::AllowanceId,
    },
}

/// The approval manager — orchestrates the full approval flow.
///
/// Coordinates between allowance store, approval handler, and deferred queue
/// to determine whether an action should proceed.
pub struct ApprovalManager {
    /// Store of active allowances.
    allowance_store: Arc<AllowanceStore>,
    /// Queue for deferred resolutions.
    deferred_queue: Arc<DeferredResolutionStore>,
    /// The approval handler (UI frontend).
    handler: RwLock<Option<Arc<dyn ApprovalHandler>>>,
    /// Timeout for waiting on approval responses.
    timeout: RwLock<Duration>,
    /// Default fallback behavior when user is unavailable.
    default_fallback: RwLock<FallbackBehavior>,
}

impl ApprovalManager {
    /// Create a new approval manager.
    #[must_use]
    pub fn new(
        allowance_store: Arc<AllowanceStore>,
        deferred_queue: Arc<DeferredResolutionStore>,
    ) -> Self {
        Self {
            allowance_store,
            deferred_queue,
            handler: RwLock::new(None),
            timeout: RwLock::new(DEFAULT_TIMEOUT),
            default_fallback: RwLock::new(FallbackBehavior::Skip),
        }
    }

    /// Register an approval handler (UI frontend).
    pub async fn register_handler(&self, handler: Arc<dyn ApprovalHandler>) {
        *self.handler.write().await = Some(handler);
    }

    /// Set the approval timeout.
    pub async fn set_timeout(&self, timeout: Duration) {
        *self.timeout.write().await = timeout;
    }

    /// Set the default fallback behavior when user is unavailable.
    pub async fn set_default_fallback(&self, fallback: FallbackBehavior) {
        *self.default_fallback.write().await = fallback;
    }

    /// Check whether an action is approved.
    ///
    /// This is the main entry point for the approval flow:
    ///
    /// 1. Check if an existing allowance covers the action
    /// 2. If not, request approval from the handler
    /// 3. If handler unavailable or times out, defer the resolution
    ///
    /// # Arguments
    ///
    /// * `principal` - The invoking principal whose allowances we should scan
    /// * `action` - The sensitive action to check
    /// * `context` - Why the agent wants to perform this action
    /// * `workspace_root` - Current workspace root for scoping workspace allowances
    pub async fn check_approval(
        &self,
        principal: &PrincipalId,
        action: &SensitiveAction,
        context: impl Into<String>,
        workspace_root: Option<&Path>,
    ) -> ApprovalOutcome {
        let context = context.into();

        // Step 1: Check if an existing allowance covers this action (atomic find + consume).
        // Scoped to `principal` — Agent A's approvals never match Agent B.
        if let Some(allowance) =
            self.allowance_store
                .find_matching_and_consume(principal, action, workspace_root)
        {
            return ApprovalOutcome::Allowed {
                proof: ApprovalProof::Allowance {
                    allowance_id: allowance.id,
                },
            };
        }

        // Step 2: No allowance — we need user approval
        let request = ApprovalRequest::new(action.clone(), &context);

        // Step 3: Check if handler is available
        let handler = {
            let guard = self.handler.read().await;
            match guard.as_ref() {
                Some(h) => Arc::clone(h),
                None => {
                    return self
                        .defer_action(action, &context, "no approval handler registered")
                        .await;
                },
            }
        };

        if !handler.is_available() {
            return self
                .defer_action(action, &context, "approval handler unavailable")
                .await;
        }

        // Step 4: Send request to handler with timeout
        let timeout = *self.timeout.read().await;
        let response = tokio::time::timeout(timeout, handler.request_approval(request)).await;

        match response {
            // Timeout
            Err(_) => {
                self.defer_action(action, &context, "approval request timed out")
                    .await
            },
            // Handler returned None (user didn't respond)
            Ok(None) => {
                self.defer_action(action, &context, "user did not respond")
                    .await
            },
            // Handler returned a response
            Ok(Some(response)) => self.handle_response(response),
        }
    }

    /// Process an approval response from the handler.
    fn handle_response(&self, response: ApprovalResponse) -> ApprovalOutcome {
        match response.decision {
            ApprovalDecision::Approve => ApprovalOutcome::Allowed {
                proof: ApprovalProof::OneTimeApproval,
            },
            ApprovalDecision::ApproveSession => {
                // The caller (the kernel's approval handler) is responsible for
                // creating the session allowance based on the original action,
                // since only it knows the correct AllowancePattern to create.
                ApprovalOutcome::Allowed {
                    proof: ApprovalProof::SessionApproval {
                        // Placeholder — the caller fills this in
                        allowance_id: crate::allowance::AllowanceId::new(),
                    },
                }
            },
            ApprovalDecision::ApproveWorkspace => {
                // Workspace-scoped allowance — the caller creates a non-session
                // allowance (workspace-scoped, survives session end).
                ApprovalOutcome::Allowed {
                    proof: ApprovalProof::WorkspaceApproval {
                        allowance_id: crate::allowance::AllowanceId::new(),
                    },
                }
            },
            ApprovalDecision::ApproveAlways => {
                // The caller (the kernel) is responsible for creating the
                // CapabilityToken since it holds the runtime signing key and
                // capability store.
                ApprovalOutcome::Allowed {
                    proof: ApprovalProof::AlwaysAllow,
                }
            },
            ApprovalDecision::ApproveWithAllowance(allowance) => {
                let allowance_id = allowance.id.clone();
                // Store the allowance
                if let Err(e) = self.allowance_store.add_allowance(*allowance) {
                    // Log error but still approve (one-time)
                    tracing::warn!("failed to store allowance: {e}");
                    return ApprovalOutcome::Allowed {
                        proof: ApprovalProof::OneTimeApproval,
                    };
                }
                ApprovalOutcome::Allowed {
                    proof: ApprovalProof::CustomAllowance { allowance_id },
                }
            },
            ApprovalDecision::Deny { reason } => ApprovalOutcome::Denied { reason },
        }
    }

    /// Defer an action for later resolution.
    async fn defer_action(
        &self,
        action: &SensitiveAction,
        context: &str,
        reason: &str,
    ) -> ApprovalOutcome {
        let fallback = *self.default_fallback.read().await;
        let request = ApprovalRequest::new(action.clone(), context);

        let resolution = DeferredResolution::new(
            PendingAction::ApprovalNeeded { request },
            reason,
            Priority::Normal,
            ActionContext::new(context),
        )
        .with_fallback(format!("fallback: {fallback}"));

        match self.deferred_queue.queue(resolution) {
            Ok(resolution_id) => ApprovalOutcome::Deferred {
                resolution_id,
                fallback,
            },
            Err(e) => {
                // If we can't even queue it, deny as a safety measure
                ApprovalOutcome::Denied {
                    reason: format!("failed to defer action: {e}"),
                }
            },
        }
    }

    /// Get all pending deferred resolutions.
    #[must_use]
    pub fn get_pending_resolutions(&self) -> Vec<DeferredResolution> {
        self.deferred_queue.get_pending()
    }

    /// Resolve a deferred resolution with a user decision.
    ///
    /// This is called when the user comes back and reviews queued items.
    ///
    /// Returns the outcome that would have been returned by `check_approval`.
    ///
    /// # Errors
    ///
    /// Currently infallible, but returns `Result` for forward compatibility
    /// with future persistence-backed resolution stores.
    pub fn resolve_deferred(
        &self,
        id: &ResolutionId,
        response: ApprovalResponse,
    ) -> Result<ApprovalOutcome, crate::request::RequestId> {
        // Remove from queue
        if let Err(e) = self.deferred_queue.resolve(id) {
            tracing::warn!("failed to resolve deferred: {e}");
        }
        // Process the response as if it came from the handler
        Ok(self.handle_response(response))
    }

    /// Get a reference to the allowance store.
    #[must_use]
    pub fn allowance_store(&self) -> &AllowanceStore {
        &self.allowance_store
    }

    /// Get a reference to the deferred resolution store.
    #[must_use]
    pub fn deferred_queue(&self) -> &DeferredResolutionStore {
        &self.deferred_queue
    }
}

impl std::fmt::Debug for ApprovalManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApprovalManager")
            .field("allowance_store", &self.allowance_store)
            .field("deferred_queue", &self.deferred_queue)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::allowance::{Allowance, AllowanceId, AllowancePattern};
    use astrid_core::types::Timestamp;
    use astrid_crypto::KeyPair;

    /// A test handler that auto-approves everything.
    struct AutoApproveHandler;

    #[async_trait]
    impl ApprovalHandler for AutoApproveHandler {
        async fn request_approval(&self, request: ApprovalRequest) -> Option<ApprovalResponse> {
            Some(ApprovalResponse::new(request.id, ApprovalDecision::Approve))
        }

        fn is_available(&self) -> bool {
            true
        }
    }

    /// A test handler that auto-denies everything.
    struct AutoDenyHandler;

    #[async_trait]
    impl ApprovalHandler for AutoDenyHandler {
        async fn request_approval(&self, request: ApprovalRequest) -> Option<ApprovalResponse> {
            Some(ApprovalResponse::new(
                request.id,
                ApprovalDecision::Deny {
                    reason: "denied by test".to_string(),
                },
            ))
        }

        fn is_available(&self) -> bool {
            true
        }
    }

    /// A test handler that is unavailable.
    struct UnavailableHandler;

    #[async_trait]
    impl ApprovalHandler for UnavailableHandler {
        async fn request_approval(&self, _request: ApprovalRequest) -> Option<ApprovalResponse> {
            None
        }

        fn is_available(&self) -> bool {
            false
        }
    }

    /// A test handler that returns None (user didn't respond).
    struct NoResponseHandler;

    #[async_trait]
    impl ApprovalHandler for NoResponseHandler {
        async fn request_approval(&self, _request: ApprovalRequest) -> Option<ApprovalResponse> {
            None
        }

        fn is_available(&self) -> bool {
            true
        }
    }

    /// A test handler that approves with session scope.
    struct SessionApproveHandler;

    #[async_trait]
    impl ApprovalHandler for SessionApproveHandler {
        async fn request_approval(&self, request: ApprovalRequest) -> Option<ApprovalResponse> {
            Some(ApprovalResponse::new(
                request.id,
                ApprovalDecision::ApproveSession,
            ))
        }

        fn is_available(&self) -> bool {
            true
        }
    }

    fn make_manager() -> ApprovalManager {
        ApprovalManager::new(
            Arc::new(AllowanceStore::new()),
            Arc::new(DeferredResolutionStore::new()),
        )
    }

    fn make_test_allowance(pattern: AllowancePattern) -> Allowance {
        let keypair = KeyPair::generate();
        Allowance {
            id: AllowanceId::new(),
            principal: PrincipalId::default(),
            action_pattern: pattern,
            created_at: Timestamp::now(),
            expires_at: None,
            max_uses: None,
            uses_remaining: None,
            session_only: true,
            workspace_root: None,
            signature: keypair.sign(b"test-allowance"),
        }
    }

    // -----------------------------------------------------------------------
    // Allowance-based approval
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_allowed_by_existing_allowance() {
        let manager = make_manager();

        // Add an allowance
        let allowance = make_test_allowance(AllowancePattern::ExactTool {
            server: "filesystem".to_string(),
            tool: "read_file".to_string(),
        });
        manager.allowance_store.add_allowance(allowance).unwrap();

        // Check approval — should be allowed by allowance
        let action = SensitiveAction::McpToolCall {
            server: "filesystem".to_string(),
            tool: "read_file".to_string(),
        };
        let outcome = manager
            .check_approval(&PrincipalId::default(), &action, "need to read file", None)
            .await;
        assert!(outcome.is_allowed());
        assert!(matches!(
            outcome,
            ApprovalOutcome::Allowed {
                proof: ApprovalProof::Allowance { .. }
            }
        ));
    }

    // -----------------------------------------------------------------------
    // Handler-based approval
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_approved_by_handler() {
        let manager = make_manager();
        manager.register_handler(Arc::new(AutoApproveHandler)).await;

        let action = SensitiveAction::FileDelete {
            path: "/tmp/test.txt".to_string(),
        };
        let outcome = manager
            .check_approval(&PrincipalId::default(), &action, "cleanup", None)
            .await;
        assert!(outcome.is_allowed());
        assert!(matches!(
            outcome,
            ApprovalOutcome::Allowed {
                proof: ApprovalProof::OneTimeApproval
            }
        ));
    }

    #[tokio::test]
    async fn test_denied_by_handler() {
        let manager = make_manager();
        manager.register_handler(Arc::new(AutoDenyHandler)).await;

        let action = SensitiveAction::FileDelete {
            path: "/important.txt".to_string(),
        };
        let outcome = manager
            .check_approval(&PrincipalId::default(), &action, "cleanup", None)
            .await;
        assert!(outcome.is_denied());
    }

    #[tokio::test]
    async fn test_session_approval() {
        let manager = make_manager();
        manager
            .register_handler(Arc::new(SessionApproveHandler))
            .await;

        let action = SensitiveAction::McpToolCall {
            server: "github".to_string(),
            tool: "create_issue".to_string(),
        };
        let outcome = manager
            .check_approval(&PrincipalId::default(), &action, "filing a bug", None)
            .await;
        assert!(outcome.is_allowed());
        assert!(matches!(
            outcome,
            ApprovalOutcome::Allowed {
                proof: ApprovalProof::SessionApproval { .. }
            }
        ));
    }

    // -----------------------------------------------------------------------
    // Deferred resolution
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_deferred_no_handler() {
        let manager = make_manager();
        // No handler registered

        let action = SensitiveAction::FileDelete {
            path: "/important.txt".to_string(),
        };
        let outcome = manager
            .check_approval(&PrincipalId::default(), &action, "cleanup", None)
            .await;
        assert!(outcome.is_deferred());
        assert_eq!(manager.deferred_queue.count(), 1);
    }

    #[tokio::test]
    async fn test_deferred_handler_unavailable() {
        let manager = make_manager();
        manager.register_handler(Arc::new(UnavailableHandler)).await;

        let action = SensitiveAction::FileDelete {
            path: "/test.txt".to_string(),
        };
        let outcome = manager
            .check_approval(&PrincipalId::default(), &action, "cleanup", None)
            .await;
        assert!(outcome.is_deferred());
    }

    #[tokio::test]
    async fn test_deferred_no_response() {
        let manager = make_manager();
        manager.register_handler(Arc::new(NoResponseHandler)).await;

        let action = SensitiveAction::FileDelete {
            path: "/test.txt".to_string(),
        };
        let outcome = manager
            .check_approval(&PrincipalId::default(), &action, "cleanup", None)
            .await;
        assert!(outcome.is_deferred());
    }

    #[tokio::test]
    async fn test_resolve_deferred() {
        let manager = make_manager();
        // No handler — will be deferred

        let action = SensitiveAction::FileDelete {
            path: "/test.txt".to_string(),
        };
        let outcome = manager
            .check_approval(&PrincipalId::default(), &action, "cleanup", None)
            .await;

        // Get the resolution ID
        let ApprovalOutcome::Deferred { resolution_id, .. } = outcome else {
            panic!("expected deferred");
        };

        // Resolve it
        let pending = manager.get_pending_resolutions();
        assert_eq!(pending.len(), 1);

        let request_id = match &pending[0].action {
            PendingAction::ApprovalNeeded { request } => request.id.clone(),
            _ => panic!("expected approval needed"),
        };

        let response = ApprovalResponse::new(request_id, ApprovalDecision::Approve);
        let outcome = manager.resolve_deferred(&resolution_id, response).unwrap();
        assert!(outcome.is_allowed());
    }

    // -----------------------------------------------------------------------
    // Configuration
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_set_timeout() {
        let manager = make_manager();
        manager.set_timeout(Duration::from_secs(30)).await;
        let timeout = *manager.timeout.read().await;
        assert_eq!(timeout, Duration::from_secs(30));
    }

    #[tokio::test]
    async fn test_set_default_fallback() {
        let manager = make_manager();
        manager.set_default_fallback(FallbackBehavior::Block).await;
        let fallback = *manager.default_fallback.read().await;
        assert_eq!(fallback, FallbackBehavior::Block);
    }

    // -----------------------------------------------------------------------
    // Allowance with custom allowance from handler
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_approve_with_custom_allowance() {
        struct AllowanceHandler;

        #[async_trait]
        impl ApprovalHandler for AllowanceHandler {
            fn is_available(&self) -> bool {
                true
            }

            async fn request_approval(&self, request: ApprovalRequest) -> Option<ApprovalResponse> {
                let keypair = KeyPair::generate();
                let allowance = Allowance {
                    id: AllowanceId::new(),
                    principal: PrincipalId::default(),
                    action_pattern: AllowancePattern::ServerTools {
                        server: "filesystem".to_string(),
                    },
                    created_at: Timestamp::now(),
                    expires_at: None,
                    max_uses: None,
                    uses_remaining: None,
                    session_only: true,
                    workspace_root: None,
                    signature: keypair.sign(b"test"),
                };
                Some(ApprovalResponse::new(
                    request.id,
                    ApprovalDecision::ApproveWithAllowance(Box::new(allowance)),
                ))
            }
        }

        let allowance_store = Arc::new(AllowanceStore::new());
        let deferred_queue = Arc::new(DeferredResolutionStore::new());
        let manager = ApprovalManager::new(Arc::clone(&allowance_store), deferred_queue);

        manager.register_handler(Arc::new(AllowanceHandler)).await;

        let action = SensitiveAction::McpToolCall {
            server: "filesystem".to_string(),
            tool: "read_file".to_string(),
        };
        let outcome = manager
            .check_approval(&PrincipalId::default(), &action, "need to read", None)
            .await;
        assert!(outcome.is_allowed());
        assert!(matches!(
            outcome,
            ApprovalOutcome::Allowed {
                proof: ApprovalProof::CustomAllowance { .. }
            }
        ));

        // The allowance should now be in the store
        assert_eq!(allowance_store.count(), 1);

        // Future requests for the same server should be covered by the allowance
        let action2 = SensitiveAction::McpToolCall {
            server: "filesystem".to_string(),
            tool: "write_file".to_string(),
        };
        let outcome2 = manager
            .check_approval(&PrincipalId::default(), &action2, "need to write", None)
            .await;
        assert!(outcome2.is_allowed());
        assert!(matches!(
            outcome2,
            ApprovalOutcome::Allowed {
                proof: ApprovalProof::Allowance { .. }
            }
        ));
    }

    // -----------------------------------------------------------------------
    // Debug
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_debug() {
        let manager = make_manager();
        let debug = format!("{manager:?}");
        assert!(debug.contains("ApprovalManager"));
    }
}
