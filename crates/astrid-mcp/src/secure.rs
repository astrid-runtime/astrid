//! Secure MCP client with capability-based authorization.
//!
//! Wraps the MCP client with security checks:
//! - Capability token validation
//! - Audit logging
//! - Approval flow integration

use astrid_audit::{AuditAction, AuditLog, AuditOutcome, AuthorizationProof};
use astrid_capabilities::{CapabilityError, CapabilityStore, CapabilityValidator};
use astrid_core::{Permission, SessionId};
use astrid_crypto::ContentHash;
use serde_json::Value;
use std::sync::Arc;
use tracing::{debug, warn};

use crate::client::McpClient;
use crate::config::ServerConfig;
use crate::error::{McpError, McpResult};
use crate::server::ServerManager;
use crate::types::{ToolDefinition, ToolResult};

/// Authorization result for a tool call.
#[derive(Debug, Clone)]
pub enum ToolAuthorization {
    /// Authorized by capability token.
    Authorized {
        /// The cryptographic proof from the authorizing token, ready to pass
        /// into `call_tool` for audit logging.
        proof: AuthorizationProof,
    },
    /// Requires user approval.
    RequiresApproval {
        /// Server name.
        server: String,
        /// Tool name.
        tool: String,
        /// Resource URI.
        resource: String,
    },
}

/// Secure MCP client with capability-based authorization.
pub struct SecureMcpClient {
    /// Underlying MCP client.
    client: McpClient,
    /// Capability store.
    capabilities: Arc<CapabilityStore>,
    /// Audit log.
    audit: Arc<AuditLog>,
    /// Current session ID.
    session_id: SessionId,
}

impl SecureMcpClient {
    /// Create a new secure MCP client.
    #[must_use]
    pub fn new(
        client: McpClient,
        capabilities: Arc<CapabilityStore>,
        audit: Arc<AuditLog>,
        session_id: SessionId,
    ) -> Self {
        Self {
            client,
            capabilities,
            audit,
            session_id,
        }
    }

    /// Check authorization for a tool call.
    ///
    /// This is a read-only validation - no audit entry is written. The audit
    /// record is created inside [`call_tool`] when the tool is actually invoked,
    /// so every audit entry carries the real args hash.
    ///
    /// For single-use tokens, calling this method consumes the token. A second
    /// call for the same resource will return [`ToolAuthorization::RequiresApproval`].
    ///
    /// # Errors
    ///
    /// Returns an error if a single-use token cannot be consumed.
    pub async fn check_authorization(
        &self,
        principal: &astrid_core::principal::PrincipalId,
        server: &str,
        tool: &str,
    ) -> McpResult<ToolAuthorization> {
        let resource = format!("mcp://{server}:{tool}");

        let validator = CapabilityValidator::new(&self.capabilities)
            .trust_issuer(self.audit.runtime_public_key());

        // Layer 4 (#668): tokens are filtered by principal before expiry
        // and signature checks. A token minted for Alice cannot authorize
        // Bob's tool call, even if the resource pattern matches.
        let result = validator
            .check(principal, &resource, Permission::Invoke)
            .await;

        if let Some(found_token) = result.token() {
            // Consume single-use tokens to prevent replay.
            // `use_token` validates + marks used atomically.
            match self.capabilities.use_token(&found_token.id).await {
                Ok(token) => {
                    // Re-verify issuer on the token returned by use_token.
                    // `use_token` checks expiry and signature but not issuer
                    // trust. This explicit check closes the TOCTOU window and
                    // ensures the security property does not rely on calling
                    // convention.
                    let trusted_key = self.audit.runtime_public_key();
                    if token.issuer != trusted_key {
                        warn!(
                            server = server,
                            tool = tool,
                            "Token issuer is not the trusted runtime key"
                        );
                        return Err(McpError::AuthorizationFailed {
                            reason: "token issuer is not the trusted runtime key".into(),
                        });
                    }

                    let proof = AuthorizationProof::Capability {
                        token_id: token.id.clone(),
                        token_hash: token.content_hash(),
                    };

                    debug!(
                        server = server,
                        tool = tool,
                        token_id = %token.id,
                        "Tool call authorized by capability"
                    );

                    return Ok(ToolAuthorization::Authorized { proof });
                },
                // Token was already consumed or expired since the find_capability
                // call. Fall through to RequiresApproval.
                Err(
                    CapabilityError::TokenAlreadyUsed { .. }
                    | CapabilityError::TokenExpired { .. }
                    | CapabilityError::TokenRevoked { .. },
                ) => {
                    debug!(
                        server = server,
                        tool = tool,
                        "Token found but already consumed/expired/revoked"
                    );
                },
                // Unexpected storage or crypto errors are real failures.
                Err(e) => return Err(McpError::TransportError(e.to_string())),
            }
        }

        debug!(server = server, tool = tool, "Tool call requires approval");

        Ok(ToolAuthorization::RequiresApproval {
            server: server.to_string(),
            tool: tool.to_string(),
            resource,
        })
    }

    /// Call a tool with authorization check.
    ///
    /// Returns an error if not authorized. Use `check_authorization` first
    /// to determine if approval is needed.
    ///
    /// # Errors
    ///
    /// Returns an error if the tool call fails or arguments cannot be serialized.
    pub async fn call_tool(
        &self,
        server: &str,
        tool: &str,
        args: Value,
        authorization: AuthorizationProof,
    ) -> McpResult<ToolResult> {
        // Compute args hash
        let args_json =
            serde_json::to_vec(&args).map_err(|e| McpError::SerializationError(e.to_string()))?;
        let args_hash = ContentHash::hash(&args_json);

        // Log the tool call
        let audit_result = {
            self.audit
                .append(
                    self.session_id.clone(),
                    AuditAction::McpToolCall {
                        server: server.to_string(),
                        tool: tool.to_string(),
                        args_hash,
                    },
                    authorization,
                    AuditOutcome::success_with("tool call started"),
                )
                .await
        };

        if let Err(e) = audit_result {
            warn!(error = %e, "Failed to log tool call start");
        }

        // Make the actual call
        let result = self.client.call_tool(server, tool, args).await;

        // Log the result
        {
            let outcome = match &result {
                Ok(r) if r.success => AuditOutcome::success_with(r.text_content()),
                Ok(r) => AuditOutcome::failure(r.error.as_deref().unwrap_or("unknown error")),
                Err(e) => AuditOutcome::failure(e.to_string()),
            };

            if let Err(e) = self
                .audit
                .append(
                    self.session_id.clone(),
                    AuditAction::McpToolCall {
                        server: server.to_string(),
                        tool: tool.to_string(),
                        args_hash,
                    },
                    AuthorizationProof::System {
                        reason: "result logging".to_string(),
                    },
                    outcome,
                )
                .await
            {
                warn!(error = %e, "Failed to log tool call result");
            }
        }

        result
    }

    /// Call a tool if authorized, otherwise return authorization requirement.
    ///
    /// # Errors
    ///
    /// Returns an error if the authorization check or tool call fails.
    pub async fn call_tool_if_authorized(
        &self,
        principal: &astrid_core::principal::PrincipalId,
        server: &str,
        tool: &str,
        args: Value,
    ) -> McpResult<Result<ToolResult, ToolAuthorization>> {
        match self.check_authorization(principal, server, tool).await? {
            ToolAuthorization::Authorized { proof } => {
                let result = self.call_tool(server, tool, args, proof).await?;
                Ok(Ok(result))
            },
            auth @ ToolAuthorization::RequiresApproval { .. } => Ok(Err(auth)),
        }
    }

    /// List all available tools.
    ///
    /// # Errors
    ///
    /// Returns an error if tools cannot be listed.
    pub async fn list_tools(&self) -> McpResult<Vec<ToolDefinition>> {
        self.client.list_tools().await
    }

    /// Get a specific tool definition.
    ///
    /// # Errors
    ///
    /// Returns an error if the tool cannot be retrieved.
    pub async fn get_tool(&self, server: &str, tool: &str) -> McpResult<Option<ToolDefinition>> {
        self.client.get_tool(server, tool).await
    }

    /// Connect to a server.
    ///
    /// # Errors
    ///
    /// Returns an error if the server cannot be connected.
    pub async fn connect(&self, server_name: &str) -> McpResult<()> {
        self.client.connect(server_name).await?;

        // Get the actual transport type for logging
        let transport = self
            .client
            .server_manager()
            .get_config(server_name)
            .map_or_else(|| "unknown".to_string(), |c| c.transport.to_string());

        // Log server start
        if let Err(e) = self
            .audit
            .append(
                self.session_id.clone(),
                AuditAction::ServerStarted {
                    name: server_name.to_string(),
                    transport,
                    binary_hash: None,
                },
                AuthorizationProof::System {
                    reason: "server connection".to_string(),
                },
                AuditOutcome::success(),
            )
            .await
        {
            warn!(server = server_name, error = %e, "Failed to audit server connection");
        }

        Ok(())
    }

    /// Disconnect from a server.
    ///
    /// # Errors
    ///
    /// Returns an error if the server cannot be disconnected.
    pub async fn disconnect(&self, server_name: &str) -> McpResult<()> {
        self.client.disconnect(server_name).await?;

        // Log server stop
        if let Err(e) = self
            .audit
            .append(
                self.session_id.clone(),
                AuditAction::ServerStopped {
                    name: server_name.to_string(),
                    reason: "user disconnect".to_string(),
                },
                AuthorizationProof::System {
                    reason: "server disconnection".to_string(),
                },
                AuditOutcome::success(),
            )
            .await
        {
            warn!(server = server_name, error = %e, "Failed to audit server disconnection");
        }

        Ok(())
    }

    /// List running servers.
    pub async fn list_servers(&self) -> Vec<String> {
        self.client.list_servers().await
    }

    /// Dynamically connect a new server using a provided configuration.
    ///
    /// Server lifecycle operations do not require capability checks, but they
    /// are audit-logged so the audit trail records which servers ran during
    /// the session.
    ///
    /// # Errors
    ///
    /// Returns an error if the server is already running or cannot be started.
    pub async fn connect_dynamic(&self, name: &str, config: ServerConfig) -> McpResult<()> {
        let transport = config.transport.to_string();
        self.client.connect_dynamic(name, config).await?;

        if let Err(e) = self
            .audit
            .append(
                self.session_id.clone(),
                AuditAction::ServerStarted {
                    name: name.to_string(),
                    transport,
                    binary_hash: None,
                },
                AuthorizationProof::System {
                    reason: "dynamic server connection".to_string(),
                },
                AuditOutcome::success(),
            )
            .await
        {
            warn!(server = name, error = %e, "Failed to audit dynamic server connection");
        }

        Ok(())
    }

    /// Disconnect from all servers.
    ///
    /// Snapshots running servers before teardown and emits a `ServerStopped`
    /// audit entry for each.
    ///
    /// # Errors
    ///
    /// Returns an error if servers cannot be stopped.
    pub async fn disconnect_all(&self) -> McpResult<()> {
        let running = self.client.list_servers().await;
        self.client.disconnect_all().await?;

        for name in running {
            if let Err(e) = self
                .audit
                .append(
                    self.session_id.clone(),
                    AuditAction::ServerStopped {
                        name: name.clone(),
                        reason: "disconnect_all".to_string(),
                    },
                    AuthorizationProof::System {
                        reason: "bulk disconnect".to_string(),
                    },
                    AuditOutcome::success(),
                )
                .await
            {
                warn!(server = %name, error = %e, "Failed to audit server stop during disconnect_all");
            }
        }

        Ok(())
    }

    /// Shut down the client, disconnecting from all servers.
    ///
    /// Snapshots running servers before teardown and emits a `ServerStopped`
    /// audit entry for each.
    ///
    /// # Errors
    ///
    /// Returns an error if disconnection fails.
    pub async fn shutdown(&self) -> McpResult<()> {
        let running = self.client.list_servers().await;
        self.client.shutdown().await?;

        for name in running {
            if let Err(e) = self
                .audit
                .append(
                    self.session_id.clone(),
                    AuditAction::ServerStopped {
                        name: name.clone(),
                        reason: "shutdown".to_string(),
                    },
                    AuthorizationProof::System {
                        reason: "client shutdown".to_string(),
                    },
                    AuditOutcome::success(),
                )
                .await
            {
                warn!(server = %name, error = %e, "Failed to audit server stop during shutdown");
            }
        }

        Ok(())
    }

    /// Get the server manager.
    #[must_use]
    pub fn server_manager(&self) -> &ServerManager {
        self.client.server_manager()
    }

    /// Connect to all auto-start servers.
    ///
    /// Each successfully started server is audit-logged.
    ///
    /// # Errors
    ///
    /// Returns an error only if refreshing the tools cache fails.
    pub async fn connect_auto_servers(&self) -> McpResult<usize> {
        // Snapshot before so we only audit newly started servers.
        let before: std::collections::HashSet<String> =
            self.client.list_servers().await.into_iter().collect();

        let count = self.client.connect_auto_servers().await?;

        // Log only the servers that were actually started by this call.
        for name in self.client.list_servers().await {
            if before.contains(&name) {
                continue;
            }
            let transport = self
                .client
                .server_manager()
                .get_config(&name)
                .map_or_else(|| "unknown".to_string(), |c| c.transport.to_string());

            if let Err(e) = self
                .audit
                .append(
                    self.session_id.clone(),
                    AuditAction::ServerStarted {
                        name: name.clone(),
                        transport,
                        binary_hash: None,
                    },
                    AuthorizationProof::System {
                        reason: "auto-start server".to_string(),
                    },
                    AuditOutcome::success(),
                )
                .await
            {
                warn!(server = %name, error = %e, "Failed to audit auto-start server");
            }
        }

        Ok(count)
    }

    /// Get the underlying MCP client.
    #[must_use]
    pub fn inner(&self) -> &McpClient {
        &self.client
    }

    /// Get the capability store.
    #[must_use]
    pub fn capabilities(&self) -> &Arc<CapabilityStore> {
        &self.capabilities
    }

    /// Get the audit log.
    #[must_use]
    pub fn audit(&self) -> &Arc<AuditLog> {
        &self.audit
    }

    /// Get the session ID.
    #[must_use]
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }
}

/// `SecureMcpClient` is cheaply cloneable — the underlying `McpClient` is
/// `Arc`-wrapped, and `CapabilityStore`/`AuditLog` are already behind `Arc`.
impl Clone for SecureMcpClient {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            capabilities: Arc::clone(&self.capabilities),
            audit: Arc::clone(&self.audit),
            session_id: self.session_id.clone(),
        }
    }
}

impl std::fmt::Debug for SecureMcpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureMcpClient")
            .field("client", &self.client)
            .field("session_id", &self.session_id)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use astrid_capabilities::{CapabilityToken, ResourcePattern, TokenScope};
    use astrid_crypto::KeyPair;

    /// Build a `SecureMcpClient` wired to in-memory stores, returning a
    /// reconstructed copy of the runtime keypair so tests can mint tokens
    /// signed by the trusted issuer.
    fn make_secure_client_with_key() -> (SecureMcpClient, KeyPair) {
        let config = crate::config::ServersConfig::default();
        let client = McpClient::with_config(config);
        let capabilities = Arc::new(CapabilityStore::in_memory());
        // Generate the runtime key and extract the secret bytes before
        // moving it into AuditLog (KeyPair is ZeroizeOnDrop, not Clone).
        let runtime_key = KeyPair::generate();
        let secret_bytes = runtime_key.secret_key_bytes();
        let audit = Arc::new(AuditLog::in_memory(runtime_key));
        // Reconstruct from the secret bytes for token signing in tests.
        let signing_key = KeyPair::from_secret_key(&secret_bytes)
            .expect("round-trip of freshly-generated key must succeed");
        let session_id = SessionId::new();
        let secure = SecureMcpClient::new(client, capabilities, audit, session_id);
        (secure, signing_key)
    }

    fn make_secure_client() -> SecureMcpClient {
        make_secure_client_with_key().0
    }

    /// Mint a token signed by the runtime key (the trusted issuer) and add
    /// it to the capability store.
    async fn grant_capability(
        secure: &SecureMcpClient,
        resource: &str,
        single_use: bool,
        signing_key: &KeyPair,
    ) -> CapabilityToken {
        let token = CapabilityToken::create_with_options(
            ResourcePattern::exact(resource).unwrap(),
            vec![Permission::Invoke],
            TokenScope::Session,
            signing_key.key_id(),
            astrid_capabilities::AuditEntryId::new(),
            signing_key,
            None,
            single_use,
            astrid_core::principal::PrincipalId::default(),
        );
        secure.capabilities.add(token.clone()).await.unwrap();
        token
    }

    fn default_principal() -> astrid_core::principal::PrincipalId {
        astrid_core::principal::PrincipalId::default()
    }

    #[tokio::test]
    async fn test_secure_client_creation() {
        let secure = make_secure_client();
        assert!(secure.list_tools().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_secure_client_clone_shares_state() {
        let secure = make_secure_client();
        let cloned = secure.clone();

        // Both see the same empty tool list (shared ServerManager)
        assert!(secure.list_tools().await.unwrap().is_empty());
        assert!(cloned.list_tools().await.unwrap().is_empty());

        // Same session ID
        assert_eq!(secure.session_id(), cloned.session_id());

        // Same capability store (Arc identity)
        assert!(Arc::ptr_eq(secure.capabilities(), cloned.capabilities()));

        // Same audit log (Arc identity)
        assert!(Arc::ptr_eq(secure.audit(), cloned.audit()));
    }

    #[tokio::test]
    async fn test_secure_client_inner_returns_bare_client() {
        let secure = make_secure_client();
        let inner = secure.inner();

        // Inner client should also see empty tools
        assert!(inner.list_tools().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_no_capability_returns_requires_approval() {
        let secure = make_secure_client();

        // No tokens in the store, so any tool check should require approval
        let auth = secure
            .check_authorization(&default_principal(), "test-server", "test-tool")
            .await
            .unwrap();
        assert!(
            matches!(auth, ToolAuthorization::RequiresApproval { .. }),
            "Empty capability store should deny by default"
        );
    }

    #[tokio::test]
    async fn test_authorized_token_produces_correct_proof() {
        let (secure, runtime_key) = make_secure_client_with_key();
        let token = grant_capability(&secure, "mcp://my-server:my-tool", false, &runtime_key).await;

        let auth = secure
            .check_authorization(&default_principal(), "my-server", "my-tool")
            .await
            .unwrap();

        match auth {
            ToolAuthorization::Authorized { proof } => match proof {
                AuthorizationProof::Capability {
                    token_id,
                    token_hash,
                } => {
                    assert_eq!(token_id, token.id, "Proof must carry the actual token ID");
                    assert_eq!(
                        token_hash,
                        token.content_hash(),
                        "Proof must carry the actual token hash"
                    );
                },
                other => panic!("Expected Capability proof, got {other:?}"),
            },
            ToolAuthorization::RequiresApproval { .. } => {
                panic!("Expected Authorized, got RequiresApproval")
            },
        }
    }

    #[tokio::test]
    async fn test_single_use_token_cannot_be_replayed() {
        let (secure, runtime_key) = make_secure_client_with_key();
        grant_capability(&secure, "mcp://replay-server:tool", true, &runtime_key).await;

        // First check consumes the token
        let first = secure
            .check_authorization(&default_principal(), "replay-server", "tool")
            .await
            .unwrap();
        assert!(
            matches!(first, ToolAuthorization::Authorized { .. }),
            "First use of single-use token should be authorized"
        );

        // Second check must fail - token was consumed
        let second = secure
            .check_authorization(&default_principal(), "replay-server", "tool")
            .await
            .unwrap();
        assert!(
            matches!(second, ToolAuthorization::RequiresApproval { .. }),
            "Single-use token must not be reusable"
        );
    }

    #[tokio::test]
    async fn test_token_from_untrusted_issuer_requires_approval() {
        let (secure, _runtime_key) = make_secure_client_with_key();

        // Mint a token signed by a DIFFERENT key (not the runtime key)
        let untrusted_key = KeyPair::generate();
        grant_capability(&secure, "mcp://server:tool", false, &untrusted_key).await;

        let auth = secure
            .check_authorization(&default_principal(), "server", "tool")
            .await
            .unwrap();
        assert!(
            matches!(auth, ToolAuthorization::RequiresApproval { .. }),
            "Token signed by untrusted issuer must not authorize"
        );
    }

    #[tokio::test]
    async fn test_delegation_methods() {
        let secure = make_secure_client();

        // list_servers delegates correctly
        assert!(secure.list_servers().await.is_empty());

        // disconnect_all on empty client succeeds
        assert!(secure.disconnect_all().await.is_ok());

        // shutdown on empty client succeeds
        assert!(secure.shutdown().await.is_ok());
    }
}
