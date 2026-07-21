//! Synchronous host-audit sink: the seam by which sensitive per-action
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
//! # Why synchronous
//!
//! The sink call happens inside the host fn's existing blocking context —
//! the fs/net/process security gates already run on `bounded_block_on`, so a
//! synchronous append on the same thread is correct and adds no new
//! concurrency class. Per-action audit deliberately does NOT route over the
//! event bus: the bus is broadcast-with-lag-drop, and a droppable record is
//! not a provable one. The chain append is the system of record.

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
/// Implementations **MUST** persist the entry synchronously before
/// returning — the report path holds no retry queue, so an asynchronous or
/// best-effort-dropped append would silently lose the record.
///
/// Implementations **MUST** stamp the `principal` argument exactly as
/// passed. The host fn derives that principal from trusted, host-populated
/// state ([`effective_principal`](crate::engine::wasm::host_state::HostState::effective_principal)),
/// never from guest-supplied data; an implementation that re-derived the
/// principal from the event payload would reintroduce a forgery seam.
///
/// A persistence failure must not propagate as a panic or block the host
/// call — audit degrades to "continue + alert", matching the admin-audit
/// path. The host fn has already decided allow/deny by the time it reports;
/// the audit record is a side effect, never a gate.
pub trait HostAuditSink: Send + Sync {
    /// Record one sensitive host call against `principal`'s audit chain.
    fn record(
        &self,
        principal: &astrid_core::PrincipalId,
        event: HostAuditEvent<'_>,
        outcome: HostAuditOutcome<'_>,
    );

    /// Record a generic compute control-plane action. The default preserves
    /// source compatibility for third-party sinks; the kernel implementation
    /// persists this as an existing `CapsuleToolCall` audit action.
    fn record_compute(
        &self,
        _principal: &astrid_core::PrincipalId,
        _capsule_id: &str,
        _operation: &str,
        _worker: &str,
        _outcome: HostAuditOutcome<'_>,
    ) {
    }
}
