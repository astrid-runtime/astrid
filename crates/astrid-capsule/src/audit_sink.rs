//! Bounded asynchronous host-audit sink: the seam by which sensitive per-action
//! host calls (fs read/write/delete, net connect/bind, process spawn)
//! reach the kernel's durable, signed, hash-chained audit log.
//!
//! # Why a sink trait rather than a direct append
//!
//! This WASM host engine has no dependency on `astrid-audit` and no
//! custody of the runtime ed25519 signing key (the key lives kernel-side,
//! `Arc`-shared into the audit log). It therefore cannot construct or sign
//! an audit entry itself. Instead a host fn reports a neutral, primitives-
//! only [`HostAuditEvent`] + [`HostAuditOutcome`] to this trait; the kernel
//! implements the trait (it holds both the audit log and the key), maps the
//! event onto its internal `AuditAction`, and appends + signs it.
//!
//! # Why bounded asynchronous
//!
//! Host calls enqueue a bounded, host-owned record and return without waiting
//! for an individual storage commit. A dedicated kernel writer coalesces
//! accepted records and acknowledges persistence through operator health. A
//! full queue applies explicit backpressure; a dead writer or failed commit is
//! visible as degraded health. Per-action audit deliberately does NOT route
//! over the event bus: the bus is broadcast-with-lag-drop, and a droppable
//! record is not a provable one. The chain append remains the system of record.

/// A sensitive host-call action being reported to the audit sink.
///
/// Variants borrow their string payloads from the host fn's own stack —
/// no allocation on the report path. The kernel-side implementation owns
/// the mapping from these neutral events onto its internal audit-action
/// enum, so this engine never names an `astrid-audit` type.
#[derive(Debug, Clone, Copy)]
pub enum HostAuditEvent<'a> {
    /// A filesystem read (content read or metadata probe).
    FileRead {
        /// The path that was read (logical or physical, per the call site).
        path: &'a str,
    },
    /// A filesystem mutation (write or directory creation).
    FileWrite {
        /// The path that was written.
        path: &'a str,
    },
    /// A filesystem removal (unlink or directory removal).
    FileDelete {
        /// The path that was removed.
        path: &'a str,
    },
    /// An outbound TCP connection attempt.
    NetConnect {
        /// The destination host (as supplied to the connect call).
        host: &'a str,
        /// The destination port.
        port: u16,
    },
    /// A socket bind.
    NetBind {
        /// The bind address.
        addr: &'a str,
    },
    /// A child-process spawn.
    ProcessSpawn {
        /// The command being executed.
        command: &'a str,
    },
    /// An inbound TCP connection accepted by a capsule listener.
    NetAccept {
        /// Host-observed local listener endpoint.
        local_addr: &'a str,
        /// Host-observed remote peer endpoint.
        peer_addr: &'a str,
    },
}

/// The outcome of a sensitive host call, as seen at the host-fn seam.
#[derive(Debug, Clone, Copy)]
pub enum HostAuditOutcome<'a> {
    /// The security gate passed and the effect succeeded.
    Allowed,
    /// The security gate passed but the effect itself errored (e.g. the
    /// file did not exist, the connection was refused). The payload is a
    /// short error description.
    Failed(&'a str),
    /// The security gate rejected the call before any effect ran. The
    /// payload is the denial reason.
    Denied(&'a str),
}

/// Records sensitive per-action host calls onto a durable audit trail.
///
/// # Implementation contract
///
/// Implementations **MUST** enqueue a bounded, owned copy before returning.
/// They may decouple host-call latency from storage commit, but must not drop
/// an accepted record. Queue saturation supplies bounded backpressure, and a
/// worker or persistence failure must be exposed through the implementation's
/// operator health surface. Graceful shutdown must drain accepted records
/// before closing the authoritative audit projection.
///
/// Implementations **MUST** stamp the `principal` argument exactly as
/// passed. The host fn derives that principal from trusted, host-populated
/// state ([`effective_principal`](crate::engine::wasm::host_state::HostState::effective_principal)),
/// never from guest-supplied data; an implementation that re-derived the
/// principal from the event payload would reintroduce a forgery seam.
///
/// A persistence failure must not panic the host call; it degrades to
/// "continue + alert" and remains visible in health. The host fn has already
/// decided allow/deny by the time it reports; the audit record is a side
/// effect, never a gate.
pub trait HostAuditSink: Send + Sync {
    /// Record one sensitive host call against `principal`'s audit chain.
    fn record(
        &self,
        principal: &astrid_core::PrincipalId,
        event: HostAuditEvent<'_>,
        outcome: HostAuditOutcome<'_>,
    );
}
