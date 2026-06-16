use astrid_capabilities::{
    CapabilityError, CapabilityStore, CapabilityToken, ResourcePattern, TokenScope,
};
use astrid_core::principal::PrincipalId;
use astrid_core::types::Permission;
use astrid_crypto::KeyPair;
use std::sync::Arc;

use super::types::InterceptProof;
use crate::action::SensitiveAction;
use crate::error::{ApprovalError, ApprovalResult};

/// Enforces that agents only execute requests they explicitly have tokens to authorize.
pub struct CapabilityValidator {
    /// Active storage matching tokens to resources.
    pub(crate) store: Arc<CapabilityStore>,
    /// Global keypair validating token authenticity.
    pub(crate) runtime_key: Arc<KeyPair>,
}

impl CapabilityValidator {
    /// Creates a new `CapabilityValidator`.
    pub fn new(store: Arc<CapabilityStore>, runtime_key: Arc<KeyPair>) -> Self {
        Self { store, runtime_key }
    }

    /// Cross-references a requested sensitive action against actively issued capability tokens.
    ///
    /// Mirrors the MCP secure path: validates signature, checks issuer trust,
    /// and consumes single-use tokens atomically. Returns `None` (fall through
    /// to approval) on any validation failure.
    ///
    /// **Principal scope:** Tokens are only considered when their
    /// `CapabilityToken::principal` matches the invoking `principal`. A token
    /// minted for Alice cannot authorise Bob's invocation even if the resource
    /// pattern and permission match — this is the fail-closed cross-principal
    /// check required by issue #668.
    ///
    /// **Design trade-off:** Single-use tokens are consumed *before* the audit
    /// write in `intercept()`. If audit subsequently fails (fail-closed), the
    /// token is gone but the action is denied. This is the correct security
    /// trade-off: consume-before-audit prevents replay attacks, and a transient
    /// audit failure is recoverable (the user re-approves), whereas a replayed
    /// single-use token is not.
    #[must_use]
    pub fn check_capability(
        &self,
        principal: &PrincipalId,
        action: &SensitiveAction,
    ) -> Option<InterceptProof> {
        let (resource, permission) = action_to_resource_permission(action)?;

        // Build a proper validator with issuer trust, matching secure.rs
        let trusted_key = self.runtime_key.export_public_key();
        let validator =
            astrid_capabilities::CapabilityValidator::new(&self.store).trust_issuer(trusted_key);

        let result = validator.check(principal, &resource, permission);
        let found_token = result.token()?;

        // Consume the token: validates signature + marks single-use as used
        // atomically. Narrows the replay window for single-use tokens to the
        // interval between find_capability and use_token. Two concurrent
        // callers can both pass validator.check(), but only one wins the
        // mark_used write lock.
        match self.store.use_token(&found_token.id) {
            Ok(token) => {
                // Re-verify issuer on the consumed token (TOCTOU defense).
                // use_token checks expiry and signature but not issuer trust.
                if token.issuer != trusted_key {
                    tracing::warn!(
                        token_id = %token.id,
                        "capability token issuer is not the trusted runtime key"
                    );
                    return None;
                }
                Some(InterceptProof::Capability { token_id: token.id })
            },
            Err(
                CapabilityError::TokenAlreadyUsed { .. }
                | CapabilityError::TokenExpired { .. }
                | CapabilityError::TokenRevoked { .. },
            ) => {
                tracing::debug!(
                    %resource,
                    "capability token found but already consumed/expired/revoked"
                );
                None
            },
            // Storage/crypto errors: log and fall through to approval.
            // Note: secure.rs propagates these as hard errors. Here we return
            // None because check_capability returns Option (not Result) and
            // falling through to user approval is safe - the user can
            // re-authorize. Changing the return type is deferred to avoid a
            // larger interface change in this batch.
            Err(e) => {
                tracing::error!(%resource, "capability validation failed: {e}");
                None
            },
        }
    }

    /// Commits an "allow always" ruling by generating a capability token and storing it for future bypasses.
    ///
    /// The token is minted for `principal` and only that principal will be
    /// able to consume it on subsequent calls. Tokens carry the principal in
    /// the signing payload (`SIGNING_DATA_VERSION` v2, issue #668), so cross-
    /// principal copy-forge attempts fail signature verification.
    ///
    /// The minted token is **permanent** (`ttl: None`): "Allow Always" means
    /// the human's decision persists until the token is explicitly revoked,
    /// not for a fixed window. An operator who wants a bounded grant instead
    /// uses the admin `caps token mint --ttl` path (issue #929).
    ///
    /// # Errors
    ///
    /// Returns an error if the action cannot be mapped to a resource, or if the resource pattern is invalid.
    pub fn handle_allow_always(
        &self,
        principal: &PrincipalId,
        action: &SensitiveAction,
        approval_audit_id: astrid_capabilities::AuditEntryId,
    ) -> ApprovalResult<InterceptProof> {
        let (resource_str, permission) =
            action_to_resource_permission(action).ok_or_else(|| ApprovalError::Denied {
                reason: format!(
                    "cannot create 'Allow Always' capability for {}: no resource mapping",
                    action.action_type()
                ),
            })?;

        let resource = ResourcePattern::new(&resource_str).map_err(|e| ApprovalError::Denied {
            reason: format!("invalid resource pattern for capability: {e}"),
        })?;

        let token = CapabilityToken::create(
            resource,
            vec![permission],
            TokenScope::Persistent,
            self.runtime_key.key_id(),
            approval_audit_id.clone(),
            &self.runtime_key,
            None,
            principal.clone(),
        );
        let token_id = token.id.clone();

        if let Err(e) = self.store.add(token) {
            tracing::error!("failed to store 'Allow Always' capability token: {e}");
            return Ok(InterceptProof::UserApproval { approval_audit_id });
        }

        tracing::info!(%token_id, %resource_str, "created 'Allow Always' capability token (permanent until revoked)");
        Ok(InterceptProof::CapabilityCreated {
            token_id,
            approval_audit_id,
        })
    }
}

/// Computes the exact pattern matching definition and intent for a generic `SensitiveAction`.
#[must_use]
pub fn action_to_resource_permission(action: &SensitiveAction) -> Option<(String, Permission)> {
    match action {
        SensitiveAction::McpToolCall { server, tool } => {
            Some((format!("mcp://{server}:{tool}"), Permission::Invoke))
        },
        SensitiveAction::FileRead { path } => Some((format!("file://{path}"), Permission::Read)),
        SensitiveAction::FileDelete { path } => {
            Some((format!("file://{path}"), Permission::Delete))
        },
        SensitiveAction::FileWriteOutsideSandbox { path } => {
            Some((format!("file://{path}"), Permission::Write))
        },
        SensitiveAction::ExecuteCommand { command, .. } => {
            Some((format!("exec://{command}"), Permission::Execute))
        },
        SensitiveAction::NetworkRequest { host, port } => {
            Some((format!("net://{host}:{port}"), Permission::Invoke))
        },
        SensitiveAction::CapsuleExecution {
            capsule_id,
            capability,
        } => Some((
            format!("capsule://{capsule_id}:{capability}"),
            Permission::Invoke,
        )),
        SensitiveAction::CapsuleHttpRequest { capsule_id, .. } => Some((
            format!("capsule://{capsule_id}:http_request"),
            Permission::Invoke,
        )),
        SensitiveAction::CapsuleFileAccess {
            capsule_id, mode, ..
        } => {
            let cap = match mode {
                Permission::Read => "file_read",
                Permission::Write => "file_write",
                Permission::Delete => "file_delete",
                _ => return None,
            };
            Some((format!("capsule://{capsule_id}:{cap}"), Permission::Invoke))
        },
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use astrid_capabilities::{AuditEntryId, ResourcePattern, TokenScope};
    use astrid_crypto::KeyPair;

    fn mcp_action(server: &str, tool: &str) -> SensitiveAction {
        SensitiveAction::McpToolCall {
            server: server.into(),
            tool: tool.into(),
        }
    }

    fn default_principal() -> PrincipalId {
        PrincipalId::default()
    }

    #[test]
    fn test_check_capability_consumes_single_use() {
        let runtime_key = Arc::new(KeyPair::generate());
        let store = Arc::new(CapabilityStore::in_memory());

        let token = CapabilityToken::create_with_options(
            ResourcePattern::exact("mcp://test:tool").unwrap(),
            vec![Permission::Invoke],
            TokenScope::Session,
            runtime_key.key_id(),
            AuditEntryId::new(),
            &runtime_key,
            None,
            true, // single_use
            default_principal(),
        );
        store.add(token).unwrap();

        let validator = CapabilityValidator::new(store, runtime_key);
        let action = mcp_action("test", "tool");

        // First call should succeed
        assert!(
            validator
                .check_capability(&default_principal(), &action)
                .is_some()
        );
        // Second call should return None (token consumed)
        assert!(
            validator
                .check_capability(&default_principal(), &action)
                .is_none()
        );
    }

    #[test]
    fn test_check_capability_rejects_untrusted_issuer() {
        let runtime_key = Arc::new(KeyPair::generate());
        let other_key = KeyPair::generate();
        let store = Arc::new(CapabilityStore::in_memory());

        // Token is validly signed, but by a different key than the runtime
        let token = CapabilityToken::create(
            ResourcePattern::exact("mcp://test:tool").unwrap(),
            vec![Permission::Invoke],
            TokenScope::Session,
            other_key.key_id(),
            AuditEntryId::new(),
            &other_key,
            None,
            default_principal(),
        );
        store.add(token).unwrap();

        let validator = CapabilityValidator::new(store, runtime_key);
        assert!(
            validator
                .check_capability(&default_principal(), &mcp_action("test", "tool"))
                .is_none()
        );
    }

    #[test]
    fn test_check_capability_allows_trusted_token() {
        let runtime_key = Arc::new(KeyPair::generate());
        let store = Arc::new(CapabilityStore::in_memory());

        let token = CapabilityToken::create(
            ResourcePattern::exact("mcp://test:tool").unwrap(),
            vec![Permission::Invoke],
            TokenScope::Session,
            runtime_key.key_id(),
            AuditEntryId::new(),
            &runtime_key,
            None,
            default_principal(),
        );
        store.add(token).unwrap();

        let validator = CapabilityValidator::new(store, runtime_key);
        let proof = validator.check_capability(&default_principal(), &mcp_action("test", "tool"));
        assert!(proof.is_some());
        assert!(matches!(proof.unwrap(), InterceptProof::Capability { .. }));
    }

    #[test]
    fn test_check_capability_rejects_cross_principal_token() {
        let runtime_key = Arc::new(KeyPair::generate());
        let store = Arc::new(CapabilityStore::in_memory());
        let alice = PrincipalId::new("alice").unwrap();
        let bob = PrincipalId::new("bob").unwrap();

        // Bob-minted token.
        let token = CapabilityToken::create(
            ResourcePattern::exact("mcp://test:tool").unwrap(),
            vec![Permission::Invoke],
            TokenScope::Session,
            runtime_key.key_id(),
            AuditEntryId::new(),
            &runtime_key,
            None,
            bob.clone(),
        );
        store.add(token).unwrap();

        let validator = CapabilityValidator::new(store, runtime_key);
        // Alice cannot use Bob's token, even though the resource matches.
        assert!(
            validator
                .check_capability(&alice, &mcp_action("test", "tool"))
                .is_none()
        );
        // Bob still can.
        assert!(
            validator
                .check_capability(&bob, &mcp_action("test", "tool"))
                .is_some()
        );
    }

    #[test]
    fn handle_allow_always_mints_permanent_token() {
        // "Allow Always" must mint a PERMANENT token (issue #929) — the
        // human's decision persists until revoked, not for a fixed window.
        let runtime_key = Arc::new(KeyPair::generate());
        let store = Arc::new(CapabilityStore::in_memory());
        let validator = CapabilityValidator::new(Arc::clone(&store), runtime_key);

        let proof = validator
            .handle_allow_always(
                &default_principal(),
                &mcp_action("test", "tool"),
                AuditEntryId::new(),
            )
            .expect("allow-always mint");
        let token_id = match proof {
            InterceptProof::CapabilityCreated { token_id, .. } => token_id,
            other => panic!("expected CapabilityCreated, got {other:?}"),
        };

        let token = store
            .get(&token_id)
            .expect("store get")
            .expect("token present");
        assert!(
            token.expires_at.is_none(),
            "Allow-Always token must be permanent (expires_at == None), got {:?}",
            token.expires_at
        );
    }
}
