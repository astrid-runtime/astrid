//! Audit entry types and actions.
//!
//! Every security-relevant operation is recorded as an audit entry.
//! Entries are chain-linked (each contains the hash of the previous)
//! and signed by the runtime.

use astrid_capabilities::AuditEntryId;
use astrid_core::{Permission, PrincipalId, SessionId, Timestamp, TokenId};
use astrid_crypto::{ContentHash, KeyPair, PublicKey, Signature};
use serde::{Deserialize, Serialize};

use crate::error::{AuditError, AuditResult};

mod coverage;
mod describe;
#[cfg(test)]
mod tests;

pub use coverage::{CapsuleActor, ProviderRequestId};

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
    ///
    /// The host records one entry per tool invocation it delivers to a tool
    /// capsule: the arguments and the published result are committed by hash
    /// only, and the outcome is a failure when the tool reported an error,
    /// published no result, or trapped.
    CapsuleToolCall {
        /// Capsule ID.
        capsule_id: String,
        /// Tool name.
        tool: String,
        /// Hash of the arguments (not the args themselves for privacy).
        args_hash: ContentHash,
        /// Caller-supplied correlation id of the call (for example the model's
        /// tool-call id). Correlation hint only; it is not host-minted.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        call_id: Option<String>,
        /// Hash of the result content the tool published, if it published one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        result_hash: Option<ContentHash>,
        /// Code identity of the capsule that ran the tool.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        actor: Option<CapsuleActor>,
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
        /// Code identity of the capsule that made the host call.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        actor: Option<CapsuleActor>,
    },

    /// File was written.
    FileWrite {
        /// File path.
        path: String,
        /// BLAKE3 hash of the written content. The zero hash means no content
        /// bytes were involved: a directory creation, a write denied before
        /// any content was accepted, or an entry written before content
        /// hashing was recorded.
        content_hash: ContentHash,
        /// Code identity of the capsule that made the host call.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        actor: Option<CapsuleActor>,
    },

    /// File was deleted.
    FileDelete {
        /// File path.
        path: String,
        /// Code identity of the capsule that made the host call.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        actor: Option<CapsuleActor>,
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
        /// Code identity of the capsule that made the host call.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        actor: Option<CapsuleActor>,
    },

    /// Socket bind by a capsule host call (`astrid:net` bind).
    NetBind {
        /// Bind address.
        addr: String,
        /// Code identity of the capsule that made the host call.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        actor: Option<CapsuleActor>,
    },

    /// Child-process spawn by a capsule host call (`astrid:process` spawn).
    ///
    /// Recorded for every spawn attempt — allowed, failed, or denied — so a
    /// sensitive exec lands on the signed audit chain.
    ProcessSpawn {
        /// Command being executed.
        command: String,
        /// Code identity of the capsule that made the host call.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        actor: Option<CapsuleActor>,
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
    ///
    /// The matching decision is an [`ApprovalGranted`](Self::ApprovalGranted)
    /// or [`ApprovalDenied`](Self::ApprovalDenied) entry carrying the same
    /// `request_id` and, when this entry was durably appended first, its entry
    /// id as `request_entry_id`.
    ApprovalRequested {
        /// Type of action being requested.
        action_type: String,
        /// Resource being accessed.
        resource: String,
        /// Host-minted id of the approval request.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        request_id: Option<String>,
        /// Code identity of the capsule that asked for approval.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        actor: Option<CapsuleActor>,
    },

    /// User granted approval.
    ApprovalGranted {
        /// What was approved.
        action: String,
        /// Resource being accessed.
        resource: Option<String>,
        /// Scope of approval.
        scope: ApprovalScope,
        /// Id of the approval request this decision answers. `None` when no
        /// prompt was issued (an existing allowance satisfied the request).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        request_id: Option<String>,
        /// Entry id of the matching [`ApprovalRequested`](Self::ApprovalRequested)
        /// entry, when it was durably appended before the decision.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        request_entry_id: Option<AuditEntryId>,
        /// How the approval was obtained (for example `user`,
        /// `session_allowance`, `remembered_consent`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        via: Option<String>,
        /// Code identity of the capsule that asked for approval.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        actor: Option<CapsuleActor>,
    },

    /// User denied approval.
    ApprovalDenied {
        /// What was denied.
        action: String,
        /// Reason given.
        reason: Option<String>,
        /// Id of the approval request this decision answers, if one was issued.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        request_id: Option<String>,
        /// Entry id of the matching [`ApprovalRequested`](Self::ApprovalRequested)
        /// entry, when it was durably appended before the decision.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        request_entry_id: Option<AuditEntryId>,
        /// Code identity of the capsule that asked for approval.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        actor: Option<CapsuleActor>,
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
    /// Pair this action with [`AuthorizationProof::Denied`] plus
    /// [`AuditOutcome::failure`] for an authorization denial. A request that
    /// passes authorization but fails request-shape validation carries a
    /// positive authorization proof plus a failure outcome; a completed allow
    /// path carries a positive proof plus [`AuditOutcome::success`].
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

    /// Inbound TCP connection accepted by a capsule listener.
    ///
    /// Appended after the variants that existed before it, so adding the
    /// action did not change the implicit discriminants of any of them. Later
    /// actions are appended after it for the same reason.
    NetAccept {
        /// Host-observed local listener endpoint.
        local_addr: String,
        /// Host-observed remote peer endpoint.
        peer_addr: String,
        /// Code identity of the capsule that owns the listener.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        actor: Option<CapsuleActor>,
    },

    /// Kernel-mediated HTTP request, recorded before it leaves the host.
    ///
    /// The capsule HTTP host appends this entry after the scheme, egress and
    /// security-gate checks pass and before the request is sent, and waits
    /// for the append, so every request the host sent has an entry that
    /// precedes it on the chain. A request refused by those checks is recorded
    /// with [`AuthorizationProof::Denied`]. Each redirect hop is a separate
    /// request. Content is never stored: `path_hash`, `headers_hash` and
    /// `body_hash` are BLAKE3 commitments computed after credentials are
    /// redacted. The completion is an [`HttpResponse`](Self::HttpResponse)
    /// entry with the same `sequence`.
    HttpRequest {
        /// Kernel-assigned request number, per principal and kernel run
        /// (`run_id`), starting at 1. Every `HttpRequest` entry takes the next
        /// number, so a gap within a run means an entry is missing.
        sequence: u64,
        /// Identifier of the kernel run that assigned `sequence`. A daemon
        /// restart starts a new run whose numbering restarts at 1.
        run_id: String,
        /// HTTP method.
        method: String,
        /// Destination host from the request URL.
        host: String,
        /// Destination port.
        port: u16,
        /// BLAKE3 of the redacted path and query.
        path_hash: ContentHash,
        /// BLAKE3 of the redacted request headers in canonical form.
        headers_hash: ContentHash,
        /// BLAKE3 of the redacted request body (of empty input when there is
        /// no body).
        body_hash: ContentHash,
        /// Length of the request body in bytes.
        body_len: u64,
        /// `0` for the capsule's request, `n` for the `n`-th redirect hop.
        redirect_hop: u32,
        /// Names of secrets the host injected into the request. The values are
        /// never part of any commitment.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        injected_secrets: Vec<String>,
        /// Code identity of the capsule that made the request.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        actor: Option<CapsuleActor>,
    },

    /// Completion of a kernel-mediated HTTP request.
    ///
    /// Written when the response body has been delivered to the capsule (or
    /// the exchange ended early). The body hash is computed incrementally over
    /// the bytes in the order the host delivered them.
    HttpResponse {
        /// `sequence` of the matching [`HttpRequest`](Self::HttpRequest).
        sequence: u64,
        /// `run_id` of the matching [`HttpRequest`](Self::HttpRequest).
        run_id: String,
        /// Entry id of the matching [`HttpRequest`](Self::HttpRequest), when
        /// its append succeeded.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        request_entry_id: Option<AuditEntryId>,
        /// Response status, when response headers were received.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        status: Option<u16>,
        /// BLAKE3 of the response body bytes delivered to the capsule. `None`
        /// when the body was not read (a followed redirect, or a transport
        /// error before the response).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        body_hash: Option<ContentHash>,
        /// Number of body bytes covered by `body_hash`.
        body_len: u64,
        /// Whether the body was read to its end.
        complete: bool,
        /// Provider request ids from the response headers (for example
        /// `x-request-id`).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        provider_request_ids: Vec<ProviderRequestId>,
        /// Code identity of the capsule that made the request.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        actor: Option<CapsuleActor>,
    },

    /// A principal's authority changed: capability patterns, capsule grants
    /// or group membership.
    ///
    /// Recorded after the change is applied, alongside the
    /// [`AdminRequest`](Self::AdminRequest) entry that authorized it (if any).
    /// Capability tokens use [`CapabilityCreated`](Self::CapabilityCreated)
    /// and [`CapabilityRevoked`](Self::CapabilityRevoked) instead.
    CapabilityChanged {
        /// Principal whose authority changed.
        target_principal: PrincipalId,
        /// What changed: `capability`, `capsule` or `group`.
        kind: String,
        /// Items granted or added.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        granted: Vec<String>,
        /// Items revoked or removed.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        revoked: Vec<String>,
        /// Mechanism that applied the change (for example `admin.caps.grant`
        /// or `grant_on_use`).
        via: String,
    },

    /// A capsule was installed.
    CapsuleInstalled {
        /// Capsule id.
        capsule_id: String,
        /// Capsule version.
        version: String,
        /// Principal the capsule was installed for.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        target_principal: Option<PrincipalId>,
        /// BLAKE3 of the installed wasm component, if the capsule has one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        wasm_hash: Option<ContentHash>,
        /// BLAKE3 of the exact installed `Capsule.toml` bytes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        manifest_hash: Option<ContentHash>,
    },

    /// A capsule runtime was loaded and activated.
    CapsuleLoaded {
        /// Capsule id.
        capsule_id: String,
        /// Capsule version.
        version: String,
        /// BLAKE3 of the verified wasm component, if the capsule has one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        wasm_hash: Option<ContentHash>,
        /// BLAKE3 of the exact `Capsule.toml` bytes the runtime was built from.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        manifest_hash: Option<ContentHash>,
        /// Identifier of the engine configuration the code was compiled for.
        engine_profile: String,
        /// Why the runtime was built: `load` or `replace`.
        trigger: String,
    },
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
