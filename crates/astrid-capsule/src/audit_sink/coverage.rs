//! Types for the audit-coverage records a host call reports: the code
//! identity a sink stamps on its records.

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
