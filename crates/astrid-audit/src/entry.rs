//! Audit entry types and actions.
//!
//! Every security-relevant operation is recorded as an audit entry.
//! Entries are chain-linked (each contains the hash of the previous)
//! and signed by the runtime.

use astrid_capabilities::AuditEntryId;
use astrid_core::{Permission, SessionId, Timestamp, TokenId};
use astrid_crypto::{ContentHash, KeyPair, PublicKey, Signature};
use serde::{Deserialize, Serialize};

use crate::error::{AuditError, AuditResult};

/// A single audit log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unique entry identifier.
    pub id: AuditEntryId,
    /// When this entry was created.
    pub timestamp: Timestamp,
    /// Session this entry belongs to.
    pub session_id: SessionId,
    /// The principal (user identity) this action was performed on behalf of.
    /// `None` for system actions that have no user context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<astrid_core::PrincipalId>,
    /// The action being audited.
    pub action: AuditAction,
    /// Authorization proof for this action.
    pub authorization: AuthorizationProof,
    /// Outcome of the action.
    pub outcome: AuditOutcome,
    /// Hash of the previous entry (chain linking).
    pub previous_hash: ContentHash,
    /// Runtime public key that signed this entry.
    pub runtime_key: PublicKey,
    /// Signature over entry contents.
    pub signature: Signature,
}

impl AuditEntry {
    /// Create a new audit entry (unsigned).
    fn new_unsigned(
        session_id: SessionId,
        action: AuditAction,
        authorization: AuthorizationProof,
        outcome: AuditOutcome,
        previous_hash: ContentHash,
        runtime_key: PublicKey,
    ) -> Self {
        Self {
            id: AuditEntryId::new(),
            timestamp: Timestamp::now(),
            session_id,
            principal: None,
            action,
            authorization,
            outcome,
            previous_hash,
            runtime_key,
            signature: Signature::from_bytes([0u8; 64]), // Placeholder
        }
    }

    /// Create and sign a new audit entry.
    #[must_use]
    pub fn create(
        session_id: SessionId,
        action: AuditAction,
        authorization: AuthorizationProof,
        outcome: AuditOutcome,
        previous_hash: ContentHash,
        runtime_key: &KeyPair,
    ) -> Self {
        let mut entry = Self::new_unsigned(
            session_id,
            action,
            authorization,
            outcome,
            previous_hash,
            runtime_key.export_public_key(),
        );

        let signing_data = entry.signing_data();
        entry.signature = runtime_key.sign(&signing_data);

        entry
    }

    /// Create and sign a new audit entry with a principal.
    ///
    /// Used when audit entries need to record which principal an action
    /// was performed on behalf of. Call sites will be wired when the
    /// kernel audit integration is updated.
    #[must_use]
    pub fn create_with_principal(
        session_id: SessionId,
        principal: astrid_core::PrincipalId,
        action: AuditAction,
        authorization: AuthorizationProof,
        outcome: AuditOutcome,
        previous_hash: ContentHash,
        runtime_key: &KeyPair,
    ) -> Self {
        let mut entry = Self::new_unsigned(
            session_id,
            action,
            authorization,
            outcome,
            previous_hash,
            runtime_key.export_public_key(),
        );
        entry.principal = Some(principal);

        let signing_data = entry.signing_data();
        entry.signature = runtime_key.sign(&signing_data);

        entry
    }

    /// Get the data used for signing.
    #[must_use]
    pub fn signing_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(self.id.0.as_bytes());
        data.extend_from_slice(&self.timestamp.0.timestamp().to_le_bytes());
        data.extend_from_slice(self.session_id.0.as_bytes());
        // Include principal in signing data with length-delimited encoding
        // to prevent ambiguity between None and adjacent field boundaries.
        // 0xFF marker + 4-byte length + bytes for Some, 0x00 marker for None.
        if let Some(ref p) = self.principal {
            let bytes = p.as_str().as_bytes();
            data.push(0xFF); // presence marker
            // PrincipalId is max 64 bytes — safe truncation.
            #[expect(clippy::cast_possible_truncation)]
            let len = bytes.len() as u32;
            data.extend_from_slice(&len.to_le_bytes());
            data.extend_from_slice(bytes);
        } else {
            data.push(0x00); // absence marker
        }
        // Action is serialized to JSON for consistent hashing
        if let Ok(action_json) = serde_json::to_vec(&self.action) {
            data.extend_from_slice(&action_json);
        }
        if let Ok(auth_json) = serde_json::to_vec(&self.authorization) {
            data.extend_from_slice(&auth_json);
        }
        // Outcome: include success/failure indicator
        data.push(u8::from(matches!(
            self.outcome,
            AuditOutcome::Success { .. }
        )));
        data.extend_from_slice(self.previous_hash.as_bytes());
        data.extend_from_slice(self.runtime_key.as_bytes());
        data
    }

    /// Compute the content hash of this entry.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        ContentHash::hash(&self.signing_data())
    }

    /// Verify the entry's signature.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError::InvalidSignature`] if the signature does not match
    /// the entry contents.
    pub fn verify_signature(&self) -> AuditResult<()> {
        let signing_data = self.signing_data();
        self.runtime_key
            .verify(&signing_data, &self.signature)
            .map_err(|_| AuditError::InvalidSignature {
                entry_id: self.id.to_string(),
            })
    }

    /// Check if this entry follows another (chain linking).
    #[must_use]
    pub fn follows(&self, previous: &AuditEntry) -> bool {
        self.previous_hash == previous.content_hash()
    }
}

/// Actions that can be audited.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum AuditAction {
    /// MCP tool was called.
    McpToolCall {
        /// Server name.
        server: String,
        /// Tool name.
        tool: String,
        /// Hash of the arguments (not the args themselves for privacy).
        args_hash: ContentHash,
    },

    /// Capsule tool was called.
    CapsuleToolCall {
        /// Capsule ID.
        capsule_id: String,
        /// Tool name.
        tool: String,
        /// Hash of the arguments (not the args themselves for privacy).
        args_hash: ContentHash,
    },

    /// MCP resource was read.
    McpResourceRead {
        /// Server name.
        server: String,
        /// Resource URI.
        uri: String,
    },

    /// MCP prompt was retrieved.
    McpPromptGet {
        /// Server name.
        server: String,
        /// Prompt name.
        name: String,
    },

    /// MCP elicitation (server requested user input).
    McpElicitation {
        /// Request ID.
        request_id: String,
        /// Schema type (text, select, confirm, etc.).
        schema: String,
    },

    /// MCP URL elicitation (OAuth, payments).
    McpUrlElicitation {
        /// URL presented to user.
        url: String,
        /// Interaction type (oauth, payment, verification, custom).
        interaction_type: String,
    },

    /// MCP sampling (server-initiated LLM call).
    McpSampling {
        /// Model used.
        model: String,
        /// Prompt token count.
        prompt_tokens: usize,
    },

    /// File was read.
    FileRead {
        /// File path.
        path: String,
    },

    /// File was written.
    FileWrite {
        /// File path.
        path: String,
        /// Hash of the written content.
        content_hash: ContentHash,
    },

    /// File was deleted.
    FileDelete {
        /// File path.
        path: String,
    },

    /// Outbound network connection attempt by a capsule host call.
    ///
    /// Recorded for every `astrid:net` connect — allowed, failed, or denied
    /// by the per-principal security gate — so a sensitive egress lands on
    /// the signed audit chain. Pair with [`AuthorizationProof::Denied`] +
    /// [`AuditOutcome::failure`] on the deny path.
    NetConnect {
        /// Destination host (as supplied to the connect call).
        host: String,
        /// Destination port.
        port: u16,
    },

    /// Socket bind by a capsule host call (`astrid:net` bind).
    NetBind {
        /// Bind address.
        addr: String,
    },

    /// Child-process spawn by a capsule host call (`astrid:process` spawn).
    ///
    /// Recorded for every spawn attempt — allowed, failed, or denied — so a
    /// sensitive exec lands on the signed audit chain.
    ProcessSpawn {
        /// Command being executed.
        command: String,
    },

    /// Capability token was created.
    CapabilityCreated {
        /// Token ID.
        token_id: TokenId,
        /// Resource pattern.
        resource: String,
        /// Permissions granted.
        permissions: Vec<Permission>,
        /// Token scope.
        scope: ApprovalScope,
    },

    /// Capability token was revoked.
    CapabilityRevoked {
        /// Token ID.
        token_id: TokenId,
        /// Reason for revocation.
        reason: String,
    },

    /// Approval was requested from the user.
    ApprovalRequested {
        /// Type of action being requested.
        action_type: String,
        /// Resource being accessed.
        resource: String,
    },

    /// User granted approval.
    ApprovalGranted {
        /// What was approved.
        action: String,
        /// Resource being accessed.
        resource: Option<String>,
        /// Scope of approval.
        scope: ApprovalScope,
    },

    /// User denied approval.
    ApprovalDenied {
        /// What was denied.
        action: String,
        /// Reason given.
        reason: Option<String>,
    },

    /// Session started.
    SessionStarted {
        /// User ID (key ID bytes).
        user_id: [u8; 8],
        /// Platform the session started from.
        platform: String,
    },

    /// Session ended.
    SessionEnded {
        /// Reason for ending.
        reason: String,
        /// Duration in seconds.
        duration_secs: u64,
    },

    /// Context was summarized (messages evicted).
    ContextSummarized {
        /// Number of messages evicted.
        evicted_count: usize,
        /// Approximate tokens freed.
        tokens_freed: usize,
    },

    /// LLM request was made.
    LlmRequest {
        /// Model used.
        model: String,
        /// Input token count.
        input_tokens: usize,
        /// Output token count.
        output_tokens: usize,
    },

    /// Server was started.
    ServerStarted {
        /// Server name.
        name: String,
        /// Transport type.
        transport: String,
        /// Binary hash (if verified).
        binary_hash: Option<ContentHash>,
    },

    /// Server was stopped.
    ServerStopped {
        /// Server name.
        name: String,
        /// Reason.
        reason: String,
    },

    /// Elicitation request sent to user.
    ElicitationSent {
        /// Request ID.
        request_id: String,
        /// Server requesting.
        server: String,
        /// Type of elicitation.
        elicitation_type: String,
    },

    /// Elicitation response received.
    ElicitationReceived {
        /// Request ID.
        request_id: String,
        /// Action taken (submit/cancel/dismiss).
        action: String,
    },

    /// Security policy violation detected.
    SecurityViolation {
        /// Type of violation.
        violation_type: String,
        /// Details.
        details: String,
    },

    /// Sub-agent was spawned (parent→child linkage).
    SubAgentSpawned {
        /// Parent session ID.
        parent_session_id: String,
        /// Child session ID.
        child_session_id: String,
        /// Task description.
        description: String,
    },

    /// Configuration was reloaded.
    ConfigReloaded,

    /// Kernel management-API request (admin surface) — allowed or denied by
    /// the [`CapabilityCheck`](astrid_capabilities::CapabilityCheck)
    /// enforcement preamble and any request-specific no-escalation checks.
    /// Pair this action with
    /// [`AuthorizationProof::Denied`] + [`AuditOutcome::failure`] for the
    /// deny path, or any of the positive authorization variants +
    /// [`AuditOutcome::success`] for the allow path.
    AdminRequest {
        /// Request variant name (e.g. `"Shutdown"`, `"ReloadCapsules"`).
        method: String,
        /// Capability string that was evaluated for this request.
        required_capability: String,
        /// Principal the request operates on, when distinct from the
        /// caller. `None` for operations that are scoped to the caller
        /// themselves (today's variants have no target-principal field).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        target_principal: Option<astrid_core::PrincipalId>,
        /// Request params for forensic replay (issue #672 follow-up).
        /// Captures what was actually asked — capabilities granted,
        /// quotas set, group membership changed — so audit consumers
        /// don't need to diff `profile.toml`/`groups.toml` snapshots
        /// to reconstruct intent. `None` for legacy `KernelRequest`
        /// entries that have no params struct.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        params: Option<serde_json::Value>,
        /// The authenticating device `key_id` when the request was
        /// device-scoped, so an auditor can see which paired device acted and
        /// whether the deny was a per-device-scope denial. Non-secret (derived
        /// from the public key); `None` for a full-authority request.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        device_key_id: Option<String>,
    },
}

impl AuditAction {
    /// Describe the MCP-prefixed actions (tool/capsule call, resource,
    /// prompt, elicitation, sampling). Returns `None` for non-MCP actions so
    /// [`description`](Self::description) can fall through. Factored out to
    /// keep `description` under the function-length lint.
    fn describe_mcp(&self) -> Option<String> {
        let s = match self {
            Self::McpToolCall { server, tool, .. } => {
                format!("Called tool {server}:{tool}")
            },
            Self::CapsuleToolCall {
                capsule_id, tool, ..
            } => {
                format!("Called capsule tool {capsule_id}:{tool}")
            },
            Self::McpResourceRead { server, uri } => {
                format!("Read resource {server}:{uri}")
            },
            Self::McpPromptGet { server, name } => {
                format!("Got prompt {server}:{name}")
            },
            Self::McpElicitation { request_id, schema } => {
                format!("Elicitation {request_id} ({schema})")
            },
            Self::McpUrlElicitation {
                interaction_type, ..
            } => {
                format!("URL elicitation ({interaction_type})")
            },
            Self::McpSampling { model, .. } => {
                format!("Sampling request to {model}")
            },
            _ => return None,
        };
        Some(s)
    }

    /// Get a human-readable description of the action.
    ///
    /// MCP-prefixed actions are described by [`describe_mcp`](Self::describe_mcp);
    /// everything else falls through to the match below. Split this way to stay
    /// under the function-length lint.
    #[must_use]
    pub fn description(&self) -> String {
        match self {
            // MCP-prefixed actions: delegate to the dedicated helper. The
            // helper returns `Some` for exactly these variants, so the
            // fallback is never taken — it keeps the call total instead of
            // panicking.
            Self::McpToolCall { .. }
            | Self::CapsuleToolCall { .. }
            | Self::McpResourceRead { .. }
            | Self::McpPromptGet { .. }
            | Self::McpElicitation { .. }
            | Self::McpUrlElicitation { .. }
            | Self::McpSampling { .. } => self.describe_mcp().unwrap_or_default(),
            Self::FileRead { path } => {
                format!("Read file {path}")
            },
            Self::FileWrite { path, .. } => {
                format!("Wrote file {path}")
            },
            Self::FileDelete { path } => {
                format!("Deleted file {path}")
            },
            Self::NetConnect { host, port } => {
                format!("Connected to {host}:{port}")
            },
            Self::NetBind { addr } => {
                format!("Bound socket {addr}")
            },
            Self::ProcessSpawn { command } => {
                format!("Spawned process {command}")
            },
            Self::CapabilityCreated { resource, .. } => {
                format!("Created capability for {resource}")
            },
            Self::CapabilityRevoked { token_id, .. } => {
                format!("Revoked capability {token_id}")
            },
            Self::ApprovalRequested {
                action_type,
                resource,
                ..
            } => {
                format!("Approval requested: {action_type} on {resource}")
            },
            Self::ApprovalGranted { action, .. } => {
                format!("Approved: {action}")
            },
            Self::ApprovalDenied { action, .. } => {
                format!("Denied: {action}")
            },
            Self::SessionStarted { platform, .. } => {
                format!("Session started via {platform}")
            },
            Self::SessionEnded { reason, .. } => {
                format!("Session ended: {reason}")
            },
            Self::ContextSummarized { evicted_count, .. } => {
                format!("Summarized {evicted_count} messages")
            },
            Self::LlmRequest { model, .. } => {
                format!("LLM request to {model}")
            },
            Self::ServerStarted { name, .. } => {
                format!("Started server {name}")
            },
            Self::ServerStopped { name, .. } => {
                format!("Stopped server {name}")
            },
            Self::ElicitationSent { server, .. } => {
                format!("Elicitation from {server}")
            },
            Self::ElicitationReceived { action, .. } => {
                format!("Elicitation response: {action}")
            },
            Self::SecurityViolation { violation_type, .. } => {
                format!("Security violation: {violation_type}")
            },
            Self::SubAgentSpawned { description, .. } => {
                format!("Spawned sub-agent: {description}")
            },
            Self::ConfigReloaded => "Configuration reloaded".to_string(),
            Self::AdminRequest {
                method,
                required_capability,
                target_principal,
                params: _,
                device_key_id: _,
            } => match target_principal {
                Some(target) => {
                    format!("Admin {method} on {target} (capability {required_capability})")
                },
                None => format!("Admin {method} (capability {required_capability})"),
            },
        }
    }
}

/// How an action was authorized.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuthorizationProof {
    /// Authorized by a verified user message.
    User {
        /// User ID (key ID).
        user_id: [u8; 8],
        /// The message that triggered the action.
        message_id: String,
    },
    /// Authorized by capability token.
    Capability {
        /// Token ID.
        token_id: TokenId,
        /// Token content hash.
        token_hash: ContentHash,
    },
    /// Authorized by user approval.
    UserApproval {
        /// User ID (key ID).
        user_id: [u8; 8],
        /// Audit entry ID of the prior approval decision that authorized this
        /// action. `None` when this entry IS the root approval decision
        /// (i.e. the user just said "yes" — there is no earlier entry).
        approval_entry_id: Option<AuditEntryId>,
    },
    /// No authorization required (low-risk operation).
    NotRequired {
        /// Reason no auth needed.
        reason: String,
    },
    /// System-initiated action.
    System {
        /// Reason for system action.
        reason: String,
    },
    /// Authorization was denied.
    Denied {
        /// Reason for denial.
        reason: String,
    },
}

/// Scope of an approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalScope {
    /// This one time only.
    Once,
    /// For the current session.
    Session,
    /// For the current workspace (persists beyond session).
    Workspace,
    /// Persistent (creates capability).
    Always,
}

impl std::fmt::Display for ApprovalScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Once => write!(f, "once"),
            Self::Session => write!(f, "session"),
            Self::Workspace => write!(f, "workspace"),
            Self::Always => write!(f, "always"),
        }
    }
}

/// Outcome of an audited action.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum AuditOutcome {
    /// Action succeeded.
    Success {
        /// Optional details.
        details: Option<String>,
    },
    /// Action failed.
    Failure {
        /// Error message.
        error: String,
    },
}

impl AuditOutcome {
    /// Create a success outcome.
    #[must_use]
    pub fn success() -> Self {
        Self::Success { details: None }
    }

    /// Create a success outcome with details.
    #[must_use]
    pub fn success_with(details: impl Into<String>) -> Self {
        Self::Success {
            details: Some(details.into()),
        }
    }

    /// Create a failure outcome.
    #[must_use]
    pub fn failure(error: impl Into<String>) -> Self {
        Self::Failure {
            error: error.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use astrid_crypto::KeyPair;

    fn test_keypair() -> KeyPair {
        KeyPair::generate()
    }

    #[test]
    fn test_entry_creation() {
        let keypair = test_keypair();
        let session_id = SessionId::new();

        let entry = AuditEntry::create(
            session_id,
            AuditAction::SessionStarted {
                user_id: keypair.key_id(),
                platform: "cli".to_string(),
            },
            AuthorizationProof::System {
                reason: "session start".to_string(),
            },
            AuditOutcome::success(),
            ContentHash::zero(),
            &keypair,
        );

        assert!(entry.verify_signature().is_ok());
    }

    #[test]
    fn test_chain_linking() {
        let keypair = test_keypair();
        let session_id = SessionId::new();

        let entry1 = AuditEntry::create(
            session_id.clone(),
            AuditAction::SessionStarted {
                user_id: keypair.key_id(),
                platform: "cli".to_string(),
            },
            AuthorizationProof::System {
                reason: "session start".to_string(),
            },
            AuditOutcome::success(),
            ContentHash::zero(),
            &keypair,
        );

        let entry2 = AuditEntry::create(
            session_id,
            AuditAction::McpToolCall {
                server: "test".to_string(),
                tool: "tool".to_string(),
                args_hash: ContentHash::hash(b"args"),
            },
            AuthorizationProof::NotRequired {
                reason: "test".to_string(),
            },
            AuditOutcome::success(),
            entry1.content_hash(),
            &keypair,
        );

        assert!(entry2.follows(&entry1));
        assert!(!entry1.follows(&entry2));
    }

    #[test]
    fn test_signature_tampering() {
        let keypair = test_keypair();
        let session_id = SessionId::new();

        let mut entry = AuditEntry::create(
            session_id,
            AuditAction::SessionStarted {
                user_id: keypair.key_id(),
                platform: "cli".to_string(),
            },
            AuthorizationProof::System {
                reason: "session start".to_string(),
            },
            AuditOutcome::success(),
            ContentHash::zero(),
            &keypair,
        );

        // Valid signature
        assert!(entry.verify_signature().is_ok());

        // Tamper with the entry
        entry.action = AuditAction::SessionEnded {
            reason: "tampered".to_string(),
            duration_secs: 0,
        };

        // Signature should now fail
        assert!(entry.verify_signature().is_err());
    }

    #[test]
    fn test_action_description() {
        let action = AuditAction::McpToolCall {
            server: "filesystem".to_string(),
            tool: "read_file".to_string(),
            args_hash: ContentHash::zero(),
        };

        assert!(action.description().contains("filesystem:read_file"));
    }
}
