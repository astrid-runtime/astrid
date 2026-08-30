//! Kernel-private security-event audit chain.
//!
//! Private canonical frames, checked sequence order, a rolling BLAKE3 root,
//! one atomic mutation-side append transition, and a bounded verifier handoff
//! relay. The kernel is the only authority; the separate
//! `native-audit-verifier` host tool reconstructs and compares. Relay and
//! verifier delivery are downstream evidence only and never feed the root.

mod chain;
mod codec;
mod relay;
mod root;
mod types;

#[cfg(test)]
mod tests;

/// Frozen canonical frame-codec version. The rolling-root tag and the
/// checkpoint wire form bind it.
pub(crate) const CODEC_VERSION: u16 = 1;

// Crate-visible re-exports stay ahead of the first production consumer, the
// same dead-code-preserving posture as the landed relation projection.
#[allow(unused_imports)]
pub(crate) use chain::AuditChain;
#[allow(unused_imports)]
pub(crate) use codec::{Frame, MAX_FRAME_BYTES, decode, decode_checkpoint, encode_checkpoint};
#[allow(unused_imports)]
pub(crate) use relay::{AUDIT_RELAY_SLOTS, AuditRelay, RelayRecord};
#[allow(unused_imports)]
pub(crate) use types::{
    AUDIT_CAP_OBJECT_POOL, AUDIT_CAP_SLOTS_PER_DOMAIN, AUDIT_DOMAIN_SLOTS, AUDIT_ENDPOINT_POOL,
    AUDIT_MAX_PAYLOAD, AuditAuthority, AuditCapabilityInstance, AuditCheckpoint, AuditClass,
    AuditError, AuditEvent, AuditObject, AuditObjectKind, AuditRights, AuditSubject, BootSessionId,
    DenialContext, DenialReason, MAX_TERMINAL_RECORDS_PER_BATCH,
};
