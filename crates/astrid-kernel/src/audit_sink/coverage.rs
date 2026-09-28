//! Mapping helpers for the audit-coverage records: the capsule actor stamped
//! on host-call entries, HTTP exchange records, the per-principal HTTP
//! request sequence, and records that must be durable before the host call
//! proceeds.

use std::sync::PoisonError;

use astrid_audit::{AuditAction, CapsuleActor, ProviderRequestId};
use astrid_capsule::{
    HostAuditActor, HostAuditEvent, HostAuditOutcome, HostAuditReceipt, HostHttpRequest,
    HostHttpResponse,
};
use astrid_core::PrincipalId;
use tracing::warn;

use super::{KernelAuditSink, truncate_guest_str};

/// Most provider request ids kept on one HTTP completion.
const MAX_PROVIDER_REQUEST_IDS: usize = 8;
/// Longest provider request id value kept (bytes).
const MAX_PROVIDER_REQUEST_ID_BYTES: usize = 128;
/// Most injected secret names kept on one HTTP request entry.
const MAX_INJECTED_SECRET_NAMES: usize = 16;
/// Longest header or secret name kept (bytes).
const MAX_NAME_BYTES: usize = 64;

/// Truncate `s` to at most `cap` bytes on a UTF-8 char boundary.
fn truncate_to(s: &str, cap: usize) -> String {
    if s.len() <= cap {
        return s.to_owned();
    }
    let end = (0..=cap)
        .rev()
        .find(|&i| s.is_char_boundary(i))
        .unwrap_or(0);
    s[..end].to_owned()
}

/// Convert the engine's load-time actor into the signed audit form.
pub(super) fn to_capsule_actor(actor: &HostAuditActor) -> CapsuleActor {
    CapsuleActor {
        capsule_id: truncate_guest_str(&actor.capsule_id),
        wasm_hash: actor.wasm_hash,
    }
}

/// The capsule a host-observed action is attributed to, if any.
pub(super) fn action_actor(action: &AuditAction) -> Option<&CapsuleActor> {
    match action {
        AuditAction::FileRead { actor, .. }
        | AuditAction::FileWrite { actor, .. }
        | AuditAction::FileDelete { actor, .. }
        | AuditAction::NetConnect { actor, .. }
        | AuditAction::NetBind { actor, .. }
        | AuditAction::NetAccept { actor, .. }
        | AuditAction::ProcessSpawn { actor, .. }
        | AuditAction::HttpRequest { actor, .. }
        | AuditAction::HttpResponse { actor, .. } => actor.as_ref(),
        _ => None,
    }
}

/// Map an HTTP pre-commit. The sink stamps the sequence afterwards.
pub(super) fn http_request_action(
    request: &HostHttpRequest<'_>,
    actor: Option<CapsuleActor>,
) -> AuditAction {
    AuditAction::HttpRequest {
        sequence: 0,
        method: truncate_to(request.method, MAX_NAME_BYTES),
        host: truncate_guest_str(request.host),
        port: request.port,
        path_hash: request.path_hash,
        headers_hash: request.headers_hash,
        body_hash: request.body_hash,
        body_len: request.body_len,
        redirect_hop: request.redirect_hop,
        injected_secrets: request
            .injected_secrets
            .iter()
            .take(MAX_INJECTED_SECRET_NAMES)
            .map(|name| truncate_to(name, MAX_NAME_BYTES))
            .collect(),
        actor,
    }
}

/// Map an HTTP completion onto its request's sequence and entry id.
pub(super) fn http_response_action(
    response: &HostHttpResponse<'_>,
    actor: Option<CapsuleActor>,
) -> AuditAction {
    AuditAction::HttpResponse {
        sequence: response.request.sequence.unwrap_or(0),
        request_entry_id: response.request.entry_id.clone(),
        status: response.status,
        body_hash: response.body_hash,
        body_len: response.body_len,
        complete: response.complete,
        provider_request_ids: response
            .provider_request_ids
            .iter()
            .take(MAX_PROVIDER_REQUEST_IDS)
            .map(|(header, value)| ProviderRequestId {
                header: truncate_to(header, MAX_NAME_BYTES),
                value: truncate_to(value, MAX_PROVIDER_REQUEST_ID_BYTES),
            })
            .collect(),
        actor,
    }
}

impl KernelAuditSink {
    /// Take the next HTTP request number for `principal`.
    fn next_http_sequence(&self, principal: &PrincipalId) -> u64 {
        let mut sequences = self
            .http_sequences
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let next = sequences.entry(principal.clone()).or_insert(0);
        *next = next.saturating_add(1);
        *next
    }

    /// Stamp the next sequence number on an HTTP request action. Every
    /// `HttpRequest` entry — committed or denied — takes one, so a gap in a
    /// principal's sequence means an entry is missing.
    pub(super) fn stamp_http_sequence(
        &self,
        principal: &PrincipalId,
        action: &mut AuditAction,
    ) -> Option<u64> {
        if let AuditAction::HttpRequest { sequence, .. } = action {
            *sequence = self.next_http_sequence(principal);
            return Some(*sequence);
        }
        None
    }

    /// Append one allowed record and wait for the durable append.
    ///
    /// A failed append does not fail the host call: it is logged and reported
    /// as a receipt without an entry id. The sequence number stays consumed,
    /// so the lost entry shows as a gap.
    pub(super) async fn commit_direct(
        &self,
        principal: &PrincipalId,
        event: HostAuditEvent<'_>,
    ) -> HostAuditReceipt {
        let mut action = Self::to_action(event, self.actor.as_deref().cloned());
        let sequence = self.stamp_http_sequence(principal, &mut action);
        let (authorization, outcome) = Self::to_proof_outcome(HostAuditOutcome::Allowed);
        let result = self
            .audit_log
            .append_with_principal(
                self.session_id.clone(),
                principal.clone(),
                action,
                authorization,
                outcome,
            )
            .await;
        let entry_id = match result {
            Ok(id) => Some(id),
            Err(error) => {
                warn!(
                    security_event = true,
                    %principal,
                    %error,
                    "Failed to append pre-commit audit entry; continuing"
                );
                None
            },
        };
        HostAuditReceipt { sequence, entry_id }
    }
}
