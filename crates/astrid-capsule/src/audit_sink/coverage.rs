//! Types for the audit-coverage records a host call reports: the code
//! identity a sink stamps on its records, HTTP exchange commitments, and
//! approval decisions.

use std::sync::Arc;

use super::HostAuditSink;

/// Code identity a sink stamps on the records it writes: the capsule id and
/// the BLAKE3 hash of the wasm component the engine verified and loaded.
///
/// Built by the engine from its own load state, never from guest data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostAuditActor {
    /// Capsule id (manifest package name).
    pub capsule_id: String,
    /// BLAKE3 of the verified wasm component, if the capsule has one.
    pub wasm_hash: Option<astrid_crypto::ContentHash>,
}

/// Return `sink` bound to `actor` when the sink supports attribution
/// ([`HostAuditSink::attributed`]), else `sink` unchanged.
#[must_use]
pub fn attribute_sink(
    sink: &Arc<dyn HostAuditSink>,
    actor: HostAuditActor,
) -> Arc<dyn HostAuditSink> {
    sink.attributed(actor).unwrap_or_else(|| Arc::clone(sink))
}

/// Commitments to one outbound HTTP request (one wire hop), computed by the
/// host after credential redaction. No request content is carried.
#[derive(Debug, Clone, Copy)]
pub struct HostHttpRequest<'a> {
    /// HTTP method.
    pub method: &'a str,
    /// Destination host from the request URL.
    pub host: &'a str,
    /// Destination port.
    pub port: u16,
    /// BLAKE3 of the redacted path and query.
    pub path_hash: astrid_crypto::ContentHash,
    /// BLAKE3 of the redacted capsule-supplied headers in canonical form.
    pub headers_hash: astrid_crypto::ContentHash,
    /// BLAKE3 of the redacted request body.
    pub body_hash: astrid_crypto::ContentHash,
    /// Request body length in bytes.
    pub body_len: u64,
    /// `0` for the capsule's request, `n` for the `n`-th redirect hop.
    pub redirect_hop: u32,
    /// Names of secrets the host injected into the request headers.
    pub injected_secrets: &'a [String],
}

/// Completion of one outbound HTTP request (one wire hop).
#[derive(Debug, Clone, Copy)]
pub struct HostHttpResponse<'a> {
    /// Receipt of the matching [`HostAuditEvent::HttpRequest`](super::HostAuditEvent::HttpRequest) pre-commit.
    pub request: &'a HostAuditReceipt,
    /// Response status, when headers were received.
    pub status: Option<u16>,
    /// BLAKE3 of the body bytes delivered to the capsule, in delivery order.
    /// `None` when the body was not read.
    pub body_hash: Option<astrid_crypto::ContentHash>,
    /// Number of body bytes covered by `body_hash`.
    pub body_len: u64,
    /// Whether the body was read to its end.
    pub complete: bool,
    /// Provider request ids from the response headers, as
    /// `(lower-case header name, value)`.
    pub provider_request_ids: &'a [(String, String)],
}

/// What a sink reports back for a record appended through
/// [`HostAuditSink::commit`](super::HostAuditSink::commit).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostAuditReceipt {
    /// Sequence number the sink assigned to the record, when it assigns one
    /// (the kernel numbers HTTP requests per principal).
    pub sequence: Option<u64>,
    /// Id of the durable audit entry. `None` when the append failed or the
    /// sink does not append durably.
    pub entry_id: Option<astrid_capabilities::AuditEntryId>,
}

/// How long an approval grant lasts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostApprovalScope {
    /// This request only.
    Once,
    /// The rest of the session.
    Session,
    /// Persisted across sessions.
    Always,
}

/// The decision for one approval check.
#[derive(Debug, Clone, Copy)]
pub struct HostApprovalDecision<'a> {
    /// Id of the prompt this decision answers; `None` when no prompt was
    /// issued (an existing grant decided).
    pub request_id: Option<&'a str>,
    /// Receipt of the matching [`HostAuditEvent::ApprovalRequested`](super::HostAuditEvent::ApprovalRequested)
    /// record.
    pub request: Option<&'a HostAuditReceipt>,
    /// Action being approved.
    pub action: &'a str,
    /// Resource the action targets.
    pub resource: &'a str,
    /// Scope of a grant; `None` for a denial.
    pub scope: Option<HostApprovalScope>,
    /// How the decision was reached (for example `user`, `session_grant`,
    /// `remembered_consent`, `timeout`).
    pub via: &'a str,
}
