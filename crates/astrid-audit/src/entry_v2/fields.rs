//! Field tables: how the action, authorization and outcome of an entry map
//! onto the `[kind, FieldMap]` sections of an [`EntryV2`](super) body.
//!
//! Kind codes and field keys are part of the signed format. They are never
//! renumbered or reused; a new variant takes the next free code.

use astrid_core::Permission;
use astrid_crypto::ContentHash;

use super::cbor::Cbor;
use crate::entry::{ApprovalScope, AuditAction, AuditOutcome, AuthorizationProof};

/// How one field is carried in the signed body.
#[derive(Clone, Debug)]
pub(super) enum FieldValue {
    /// Carried as a salted commitment to this CBOR value.
    Committed(Cbor),
    /// Carried in the clear.
    Public(Cbor),
}

/// A `[kind, FieldMap]` section before commitments are computed.
#[derive(Clone, Debug)]
pub(super) struct Section {
    pub(super) kind: u64,
    pub(super) fields: Vec<(u64, FieldValue)>,
}

impl Section {
    fn new(kind: u64) -> Self {
        Self {
            kind,
            fields: Vec::new(),
        }
    }

    fn text(mut self, key: u64, value: &str) -> Self {
        self.fields
            .push((key, FieldValue::Committed(Cbor::text(value))));
        self
    }

    fn opt_text(self, key: u64, value: Option<&str>) -> Self {
        match value {
            Some(value) => self.text(key, value),
            None => self,
        }
    }

    fn secret_hash(mut self, key: u64, value: &ContentHash) -> Self {
        self.fields.push((
            key,
            FieldValue::Committed(Cbor::bytes(value.as_bytes().to_vec())),
        ));
        self
    }

    fn public(mut self, key: u64, value: Cbor) -> Self {
        self.fields.push((key, FieldValue::Public(value)));
        self
    }

    fn count(self, key: u64, value: u64) -> Self {
        self.public(key, Cbor::Uint(value))
    }

    fn committed(mut self, key: u64, value: Cbor) -> Self {
        self.fields.push((key, FieldValue::Committed(value)));
        self
    }
}

fn usize_count(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn uuid_bytes(value: &uuid::Uuid) -> Cbor {
    Cbor::bytes(value.as_bytes().to_vec())
}

/// Stable code of an [`ApprovalScope`].
pub(super) const fn scope_code(scope: ApprovalScope) -> u64 {
    match scope {
        ApprovalScope::Once => 0,
        ApprovalScope::Session => 1,
        ApprovalScope::Workspace => 2,
        ApprovalScope::Always => 3,
    }
}

/// Stable code of a [`Permission`].
pub(super) const fn permission_code(permission: Permission) -> u64 {
    match permission {
        Permission::Read => 1,
        Permission::Write => 2,
        Permission::Execute => 3,
        Permission::Delete => 4,
        Permission::Invoke => 5,
        Permission::List => 6,
        Permission::Create => 7,
    }
}

/// Section 9: the audited action.
#[expect(
    clippy::too_many_lines,
    reason = "one arm per action variant keeps the signed field table in one place"
)]
pub(super) fn action_section(action: &AuditAction) -> Section {
    match action {
        AuditAction::McpToolCall {
            server,
            tool,
            args_hash,
        } => Section::new(1)
            .text(1, server)
            .text(2, tool)
            .secret_hash(3, args_hash),
        AuditAction::CapsuleToolCall {
            capsule_id,
            tool,
            args_hash,
        } => Section::new(2)
            .text(1, capsule_id)
            .text(2, tool)
            .secret_hash(3, args_hash),
        AuditAction::McpResourceRead { server, uri } => {
            Section::new(3).text(1, server).text(2, uri)
        },
        AuditAction::McpPromptGet { server, name } => Section::new(4).text(1, server).text(2, name),
        AuditAction::McpElicitation { request_id, schema } => {
            Section::new(5).text(1, request_id).text(2, schema)
        },
        AuditAction::McpUrlElicitation {
            url,
            interaction_type,
        } => Section::new(6).text(1, url).text(2, interaction_type),
        AuditAction::McpSampling {
            model,
            prompt_tokens,
        } => Section::new(7)
            .text(1, model)
            .count(2, usize_count(*prompt_tokens)),
        AuditAction::FileRead { path } => Section::new(8).text(1, path),
        AuditAction::FileWrite { path, content_hash } => {
            Section::new(9).text(1, path).secret_hash(2, content_hash)
        },
        AuditAction::FileDelete { path } => Section::new(10).text(1, path),
        AuditAction::NetConnect { host, port } => {
            Section::new(11).text(1, host).count(2, u64::from(*port))
        },
        AuditAction::NetBind { addr } => Section::new(12).text(1, addr),
        AuditAction::ProcessSpawn { command } => Section::new(13).text(1, command),
        AuditAction::CapabilityCreated {
            token_id,
            resource,
            permissions,
            scope,
        } => Section::new(14)
            .public(1, uuid_bytes(&token_id.0))
            .text(2, resource)
            .public(
                3,
                Cbor::Array(
                    permissions
                        .iter()
                        .map(|permission| Cbor::Uint(permission_code(*permission)))
                        .collect(),
                ),
            )
            .count(4, scope_code(*scope)),
        AuditAction::CapabilityRevoked { token_id, reason } => Section::new(15)
            .public(1, uuid_bytes(&token_id.0))
            .text(2, reason),
        AuditAction::ApprovalRequested {
            action_type,
            resource,
        } => Section::new(16).text(1, action_type).text(2, resource),
        AuditAction::ApprovalGranted {
            action,
            resource,
            scope,
        } => Section::new(17)
            .text(1, action)
            .opt_text(2, resource.as_deref())
            .count(3, scope_code(*scope)),
        AuditAction::ApprovalDenied { action, reason } => Section::new(18)
            .text(1, action)
            .opt_text(2, reason.as_deref()),
        AuditAction::SessionStarted { user_id, platform } => Section::new(19)
            .public(1, Cbor::bytes(user_id.to_vec()))
            .text(2, platform),
        AuditAction::SessionEnded {
            reason,
            duration_secs,
        } => Section::new(20).text(1, reason).count(2, *duration_secs),
        AuditAction::ContextSummarized {
            evicted_count,
            tokens_freed,
        } => Section::new(21)
            .count(1, usize_count(*evicted_count))
            .count(2, usize_count(*tokens_freed)),
        AuditAction::LlmRequest {
            model,
            input_tokens,
            output_tokens,
        } => Section::new(22)
            .text(1, model)
            .count(2, usize_count(*input_tokens))
            .count(3, usize_count(*output_tokens)),
        AuditAction::ServerStarted {
            name,
            transport,
            binary_hash,
        } => {
            let section = Section::new(23).text(1, name).text(2, transport);
            match binary_hash {
                Some(hash) => section.public(3, Cbor::bytes(hash.as_bytes().to_vec())),
                None => section,
            }
        },
        AuditAction::ServerStopped { name, reason } => {
            Section::new(24).text(1, name).text(2, reason)
        },
        AuditAction::ElicitationSent {
            request_id,
            server,
            elicitation_type,
        } => Section::new(25)
            .text(1, request_id)
            .text(2, server)
            .text(3, elicitation_type),
        AuditAction::ElicitationReceived { request_id, action } => {
            Section::new(26).text(1, request_id).text(2, action)
        },
        AuditAction::SecurityViolation {
            violation_type,
            details,
        } => Section::new(27).text(1, violation_type).text(2, details),
        AuditAction::SubAgentSpawned {
            parent_session_id,
            child_session_id,
            description,
        } => Section::new(28)
            .text(1, parent_session_id)
            .text(2, child_session_id)
            .text(3, description),
        AuditAction::ConfigReloaded => Section::new(29),
        AuditAction::AdminRequest {
            method,
            required_capability,
            target_principal,
            params,
            device_key_id,
        } => {
            let section = Section::new(30)
                .text(1, method)
                .text(2, required_capability)
                .opt_text(
                    3,
                    target_principal
                        .as_ref()
                        .map(astrid_core::PrincipalId::as_str),
                );
            let section = match params {
                Some(params) => section.committed(4, super::json::to_cbor(params)),
                None => section,
            };
            section.opt_text(5, device_key_id.as_deref())
        },
        AuditAction::NetAccept {
            local_addr,
            peer_addr,
        } => Section::new(31).text(1, local_addr).text(2, peer_addr),
    }
}

/// Section 10: how the action was authorized.
pub(super) fn authorization_section(authorization: &AuthorizationProof) -> Section {
    match authorization {
        AuthorizationProof::User {
            user_id,
            message_id,
        } => Section::new(1)
            .public(1, Cbor::bytes(user_id.to_vec()))
            .text(2, message_id),
        AuthorizationProof::Capability {
            token_id,
            token_hash,
        } => Section::new(2)
            .public(1, uuid_bytes(&token_id.0))
            .public(2, Cbor::bytes(token_hash.as_bytes().to_vec())),
        AuthorizationProof::UserApproval {
            user_id,
            approval_entry_id,
        } => {
            let section = Section::new(3).public(1, Cbor::bytes(user_id.to_vec()));
            match approval_entry_id {
                Some(id) => section.public(2, uuid_bytes(&id.0)),
                None => section,
            }
        },
        AuthorizationProof::NotRequired { reason } => Section::new(4).text(1, reason),
        AuthorizationProof::System { reason } => Section::new(5).text(1, reason),
        AuthorizationProof::Denied { reason } => Section::new(6).text(1, reason),
    }
}

/// Section 11: the full outcome.
pub(super) fn outcome_section(outcome: &AuditOutcome) -> Section {
    match outcome {
        AuditOutcome::Success { details } => Section::new(0).opt_text(1, details.as_deref()),
        AuditOutcome::Failure { error } => Section::new(1).text(1, error),
    }
}
