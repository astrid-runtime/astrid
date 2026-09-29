//! Bounded asynchronous host-audit sink: the seam by which sensitive per-action
//! host calls (fs read/write/delete, net connect/bind, process spawn, HTTP
//! exchanges) reach the kernel's durable, signed, hash-chained audit log.
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
//! for an individual storage commit. A dedicated kernel writer records each
//! principal's calls in call order, coalesces consecutive calls losslessly,
//! and writes a signed loss record for calls a full queue could not hold, so
//! a gap is visible on the chain itself. Per-action audit deliberately does
//! NOT route over the event bus: the bus is broadcast-with-lag-drop, and a
//! droppable record is not a provable one. The chain append remains the
//! system of record.
//!
//! # Fail-closed classes
//!
//! An operator may configure host-call classes that fail closed. For those,
//! the host fn calls [`HostAuditSink::admit`] after its security gate and
//! before the effect; the effect runs only once a write-ahead entry is
//! durable.

//! HTTP requests and completions can await a durable receipt through
//! [`HostAuditSink::commit`]; append failures remain explicit in that receipt.

mod coverage;

pub use coverage::{
    HostApprovalDecision, HostApprovalScope, HostAuditActor, HostAuditReceipt, HostHttpRequest,
    HostHttpResponse, attribute_sink,
};

/// A sensitive host-call action being reported to the audit sink.
///
/// Variants borrow their string payloads from the host fn's own stack —
/// no allocation on the report path. The kernel-side implementation owns
/// the mapping from these neutral events onto its internal audit-action
/// enum, so this engine never names an `astrid-audit` type.
#[derive(Debug, Clone, Copy)]
pub enum HostAuditEvent<'a> {
    /// A filesystem content read (`read-file`).
    FileRead {
        /// The path that was read (logical or physical, per the call site).
        path: &'a str,
    },
    /// A filesystem metadata probe (`stat` / `exists` / `readdir`).
    ///
    /// Distinct from [`FileRead`] so the kernel can omit allowed probes from
    /// the signed chain (POSIX path probes are not OS-level security events)
    /// while still recording denials.
    FileProbe {
        /// The path that was probed.
        path: &'a str,
    },
    /// A filesystem mutation (write or directory creation).
    FileWrite {
        /// The path that was written.
        path: &'a str,
        /// BLAKE3 of the bytes written. `None` for a directory creation or a
        /// write denied before any content was accepted.
        content_hash: Option<astrid_crypto::ContentHash>,
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
    /// A kernel-mediated HTTP request about to be sent (or refused).
    HttpRequest(HostHttpRequest<'a>),
    /// Completion of a kernel-mediated HTTP request.
    HttpResponse(HostHttpResponse<'a>),
    /// A tool invocation delivered to a tool capsule, with the result it
    /// published during the invocation (if any).
    ToolCall {
        /// Capsule that ran the tool.
        capsule_id: &'a str,
        /// Tool name, taken from the request topic.
        tool: &'a str,
        /// Caller-supplied call id (correlation hint only).
        call_id: Option<&'a str>,
        /// BLAKE3 of the JSON-encoded arguments.
        args_hash: astrid_crypto::ContentHash,
        /// BLAKE3 of the result content the tool published.
        result_hash: Option<astrid_crypto::ContentHash>,
    },
    /// An approval prompt about to be published to the user.
    ApprovalRequested {
        /// Host-minted request id.
        request_id: &'a str,
        /// Action being approved.
        action: &'a str,
        /// Resource the action targets.
        resource: &'a str,
    },
    /// The decision for an approval check. Report a denial with
    /// [`HostAuditOutcome::Denied`].
    ApprovalDecided(HostApprovalDecision<'a>),
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
/// an accepted record without a trace on the chain: a call that cannot be
/// recorded individually must still be counted by a signed loss record.
/// Records of one principal must reach the chain in call order. A worker or
/// persistence failure must be exposed through the implementation's operator
/// health surface. Graceful shutdown must drain accepted records before
/// closing the authoritative audit projection.
///
/// Implementations **MUST** stamp the `principal` argument exactly as
/// passed. The host fn derives that principal from trusted, host-populated
/// state ([`effective_principal`](crate::engine::wasm::host_state::HostState::effective_principal)),
/// never from guest-supplied data; an implementation that re-derived the
/// principal from the event payload would reintroduce a forgery seam.
///
/// A persistence failure must not panic the host call; it degrades to
/// "continue + alert" and remains visible in health. The host fn has already
/// decided allow/deny by the time it reports; [`record`](Self::record) is a
/// side effect, never a gate. The only gate is [`admit`](Self::admit), and
/// only for classes the operator configured as fail-closed.
pub trait HostAuditSink: Send + Sync {
    /// Record one sensitive host call against `principal`'s audit chain.
    fn record(
        &self,
        principal: &astrid_core::PrincipalId,
        event: HostAuditEvent<'_>,
        outcome: HostAuditOutcome<'_>,
    );

    /// Admit a host call that passed its security gate, before its effect
    /// runs.
    ///
    /// For a class the operator configured as fail-closed, the implementation
    /// returns `Ok` only once a write-ahead entry for the call is durable, and
    /// returns a refusal when it cannot make it durable. The host fn must then
    /// fail the call without running the effect; the implementation records
    /// the refusal itself. For every other class this returns `Ok` at once.
    /// Either way the host fn still reports the call's outcome through
    /// [`record`](Self::record).
    ///
    /// # Errors
    ///
    /// Returns [`HostAuditRefusal`] when a fail-closed call cannot be
    /// recorded.
    fn admit(
        &self,
        principal: &astrid_core::PrincipalId,
        event: HostAuditEvent<'_>,
    ) -> Result<(), HostAuditRefusal> {
        let _ = (principal, event);
        Ok(())
    }
    /// Return a sink that stamps `actor` on every record it writes, or `None`
    /// when this implementation does not attribute records.
    ///
    /// The engine calls this once per capsule load with the identity it
    /// verified, and hands the returned sink to that capsule's host state, so
    /// the attribution is host-owned and a guest cannot choose it.
    fn attributed(&self, actor: HostAuditActor) -> Option<std::sync::Arc<dyn HostAuditSink>> {
        let _ = actor;
        None
    }

    /// Append one record and wait until it is durable.
    ///
    /// For records that must not be lost to queue pressure or must precede
    /// an effect: the HTTP host awaits this before a request leaves the host
    /// and for the request's completion. A failed append must not fail the
    /// caller; it returns a receipt without an `entry_id` and is logged. The
    /// default enqueues the record through [`record`](Self::record) and
    /// returns an empty receipt.
    fn commit<'a>(
        &'a self,
        principal: &'a astrid_core::PrincipalId,
        event: HostAuditEvent<'a>,
        outcome: HostAuditOutcome<'a>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = HostAuditReceipt> + Send + 'a>> {
        self.record(principal, event, outcome);
        Box::pin(std::future::ready(HostAuditReceipt::default()))
    }
}

/// Refusal of a fail-closed host call whose write-ahead audit entry could not
/// be made durable. The reason is for the audit log and operator logs; host
/// fns must not pass it to the guest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostAuditRefusal {
    reason: String,
}

impl HostAuditRefusal {
    /// Build a refusal with an operator-facing reason.
    #[must_use]
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }

    /// The operator-facing reason.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

impl std::fmt::Display for HostAuditRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "host-call audit unavailable: {}", self.reason)
    }
}
