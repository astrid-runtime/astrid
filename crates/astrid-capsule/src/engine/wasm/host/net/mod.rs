//! `astrid:net@1.0.0` host implementation.
//!
//! Storage model: every accepted / connected stream is pushed into the
//! wasmtime `ResourceTable` as a `NetStream` value. The `Resource<TcpStream>`
//! handle returned to the guest is just a wrapper around the table rep —
//! drop semantics, lifetime tracking, and cross-capsule isolation come
//! for free from wasmtime. No parallel `HashMap<u64, NetStream>` on
//! `HostState` anymore.
//!
//! Stubbed surface (port-back follow-ups):
//!
//! - `bind-tcp` / `TcpListener` — inbound TCP for capsule-hosted servers.
//! - `udp-bind` / `UdpSocket` — datagram I/O, connected + unconnected.
//! - `tcp-stream.{read-stream, write-stream}` — Astrid-stream halves of a
//!   TCP connection (needs a wasmtime-wasi-io `InputStream`/`OutputStream`
//!   impl over our `NetStream`; planned in a dedicated commit so the
//!   splice path lands with proper readiness wiring rather than a stub
//!   that traps).
//!
//! Live surface:
//!
//! - `bind-unix` + `UnixListener.{accept, poll-accept}` — kernel-pre-bound
//!   Unix listener with session-token + peer-credential handshake.
//! - `connect-tcp` — DNS-resolved, SSRF-airlocked outbound TCP.
//! - `lookup-host` — airlocked DNS lookup.
//! - `TcpStream`: read / write (length-prefixed), read-bytes / write-bytes
//!   (raw), peek (TCP-only), shutdown, peer-addr / local-addr, nodelay
//!   getters/setters, read/write-timeout getters/setters, keepalive,
//!   hop-limit, linger, reuseaddr socket options.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use wasmtime::component::Resource;

use crate::audit_sink::{HostAuditEvent, HostAuditOutcome};
use crate::engine::wasm::bindings::astrid::net::host::{
    self as net, ErrorCode, TcpListener, TcpStream, UdpSocket, UnixListener,
};
use crate::engine::wasm::host::http::is_safe_ip;
use crate::engine::wasm::host::util;
use crate::engine::wasm::host_state::{HostState, NetStream, SharedTcpListener, TcpStreamSlot};

mod client_lifecycle;
pub(crate) mod handshake;
mod stream;
mod tcp_listener;
mod tcp_stream;
mod udp_socket;
mod unix_listener;

use stream::CONNECT_TIMEOUT;

/// Maximum concurrent socket connections per capsule. Defense-in-depth
/// cap on top of the per-principal profile quota. Tracked via
/// the capsule-wide stream counter, bumped on every successful
/// `accept` / `connect-tcp` push and decremented in the resource
/// drop path.
pub(super) const MAX_ACTIVE_STREAMS: usize = 8;

/// Maximum simultaneously bound inbound TCP listeners per capsule instance,
/// matching the published `astrid:net` WIT contract.
pub(super) const MAX_ACTIVE_TCP_LISTENERS: usize = 4;

impl HostState {
    pub(in crate::engine::wasm) fn reserve_net_stream(&mut self) -> bool {
        let reserved = self
            .capsule_net_stream_count
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < MAX_ACTIVE_STREAMS).then_some(count + 1)
            })
            .is_ok();
        if reserved {
            self.local_net_stream_count.fetch_add(1, Ordering::AcqRel);
            self.net_stream_count += 1;
        }
        reserved
    }

    pub(in crate::engine::wasm) fn release_net_stream(&mut self) {
        let decremented = self.capsule_net_stream_count.fetch_update(
            Ordering::AcqRel,
            Ordering::Acquire,
            |count| count.checked_sub(1),
        );
        debug_assert!(decremented.is_ok(), "network stream quota underflow");
        let local = self.local_net_stream_count.fetch_update(
            Ordering::AcqRel,
            Ordering::Acquire,
            |count| count.checked_sub(1),
        );
        debug_assert!(local.is_ok(), "local network stream quota underflow");
        self.net_stream_count = self.net_stream_count.saturating_sub(1);
    }

    pub(in crate::engine::wasm) fn claim_reserved_net_stream(&mut self) {
        self.net_stream_count += 1;
    }
}

/// Stamp marking a resource slot in the table as a `UnixListener` handle.
/// The kernel pre-binds the listener; the resource handle is just a
/// capability token that the capsule must hold to call `accept`.
pub(super) struct UnixListenerSlot;

/// Resource slot holding a bound inbound TCP listener. The
/// `Resource<TcpListener>` handed to the guest is a token over this slot;
/// `accept` / `poll-accept` / `local-addr` reach the `tokio` listener
/// through it, and `Drop` closes the socket.
pub(super) struct TcpListenerSlot {
    pub(super) listener: Arc<tokio::net::TcpListener>,
    pub(super) pending: Arc<PendingTcpConnection>,
    pub(super) cancel_token: tokio_util::sync::CancellationToken,
    /// Concrete-port registry lease. Last drop evicts the entry (closing the
    /// OS socket) and releases the listener quota. `None` for an unshareable
    /// (port 0) bind, which charges and releases quota on this slot alone.
    pub(super) share: Option<TcpListenerShare>,
    /// Quota release for an unshareable bind. Concrete-port quota tracks the
    /// live socket via [`TcpListenerShare`], not the binder slot.
    pub(super) listener_count: Option<Arc<std::sync::atomic::AtomicUsize>>,
}

/// Lease on a `shared_listeners` registry entry for one guest slot.
pub(super) struct TcpListenerShare {
    key: (String, u16),
    registry: Arc<dashmap::DashMap<(String, u16), SharedTcpListener>>,
    quota: Arc<std::sync::atomic::AtomicUsize>,
}

impl TcpListenerShare {
    fn release(self) {
        match self.registry.entry(self.key) {
            dashmap::mapref::entry::Entry::Occupied(occupied) => {
                let previous = occupied.get().holders.fetch_update(
                    Ordering::AcqRel,
                    Ordering::Acquire,
                    |count| count.checked_sub(1),
                );
                match previous {
                    Ok(1) => {
                        occupied.remove();
                        let released =
                            self.quota
                                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                                    count.checked_sub(1)
                                });
                        debug_assert!(released.is_ok(), "TCP listener quota underflow");
                    },
                    Ok(_) => {},
                    Err(_) => debug_assert!(false, "TCP listener holder underflow"),
                }
            },
            dashmap::mapref::entry::Entry::Vacant(_) => {
                debug_assert!(false, "shared listener missing on slot drop");
            },
        }
    }
}

pub(super) struct PendingTcpConnection {
    pub(super) connection: tokio::sync::Mutex<Option<PendingTcpAccepted>>,
    pub(super) stream_count: Arc<std::sync::atomic::AtomicUsize>,
    pub(super) local_stream_count: Arc<std::sync::atomic::AtomicUsize>,
}

pub(super) struct PendingTcpAccepted {
    pub(super) stream: tokio::net::TcpStream,
    pub(super) local_addr: String,
    pub(super) peer_addr: String,
}

impl Drop for PendingTcpConnection {
    fn drop(&mut self) {
        if self.connection.get_mut().is_some() {
            let decremented =
                self.stream_count
                    .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                        count.checked_sub(1)
                    });
            debug_assert!(decremented.is_ok(), "pending TCP quota underflow");
            let local = self.local_stream_count.fetch_update(
                Ordering::AcqRel,
                Ordering::Acquire,
                |count| count.checked_sub(1),
            );
            debug_assert!(local.is_ok(), "pending local TCP quota underflow");
        }
    }
}

impl Drop for TcpListenerSlot {
    fn drop(&mut self) {
        if let Some(share) = self.share.take() {
            share.release();
            return;
        }
        let Some(listener_count) = self.listener_count.as_ref() else {
            return;
        };
        let decremented =
            listener_count.fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                count.checked_sub(1)
            });
        debug_assert!(decremented.is_ok(), "TCP listener quota underflow");
    }
}

/// Stamp marking a resource slot as a `UdpSocket`. Same reason as above.
#[allow(dead_code)]
pub(super) struct UdpSocketSlot;

/// DNS hostname guards before reaching the resolver.
pub(super) fn validate_host(host: &str) -> Result<(), ErrorCode> {
    if host.is_empty() {
        return Err(ErrorCode::AddressNotAvailable);
    }
    if host.len() > 255 {
        return Err(ErrorCode::AddressNotAvailable);
    }
    if host.bytes().any(|b| b == 0) {
        return Err(ErrorCode::AddressNotAvailable);
    }
    Ok(())
}

/// Whether a TCP-bind host names a loopback interface. Capsule-hosted
/// servers are confined to loopback (see `bind_tcp`): `127.0.0.0/8`, `::1`,
/// or the literal `localhost`. A hostname other than `localhost` is refused
/// rather than resolved — binding must name a concrete local interface, and
/// resolving arbitrary names for a bind target is an SSRF-shaped footgun.
pub(super) fn is_loopback_bind_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<std::net::IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

/// Classify a tokio io::Error into the typed `net::ErrorCode`.
pub(super) fn map_io_err(err: std::io::Error) -> ErrorCode {
    use std::io::ErrorKind;
    match err.kind() {
        ErrorKind::WouldBlock => ErrorCode::WouldBlock,
        ErrorKind::ConnectionRefused => ErrorCode::ConnectionRefused,
        ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted | ErrorKind::BrokenPipe => {
            ErrorCode::ConnectionReset
        },
        ErrorKind::TimedOut => ErrorCode::Timeout,
        ErrorKind::AddrInUse => ErrorCode::AddressInUse,
        ErrorKind::AddrNotAvailable => ErrorCode::AddressNotAvailable,
        _ => ErrorCode::Unknown(err.to_string()),
    }
}

/// Audit a net host fn invocation (per-principal, with operation name + status).
pub(super) fn audit_net<T, E: std::fmt::Debug>(
    state: &HostState,
    op: &'static str,
    bytes: u64,
    result: &Result<T, E>,
) {
    let capsule_id = state.capsule_id.as_str();
    let principal = state.effective_principal();
    match result {
        Ok(_) => tracing::debug!(
            target: "astrid.audit.net",
            %capsule_id,
            %principal,
            fn = op,
            bytes,
            "audit",
        ),
        Err(e) => tracing::debug!(
            target: "astrid.audit.net",
            %capsule_id,
            %principal,
            fn = op,
            error = ?e,
            "audit",
        ),
    }
}

/// Audit an outbound TCP connect, carrying the destination host + port.
///
/// Wraps the generic [`audit_net`] tracing line and additionally reports a
/// typed [`NetConnect`](crate::audit_sink::HostAuditEvent::NetConnect)
/// event to the per-action audit sink so a connect lands on the signed
/// audit chain (not just the off-by-default observability target). Use this
/// for `connect-tcp` instead of the bare [`audit_net`].
pub(crate) fn audit_net_connect<T, E: std::fmt::Debug>(
    state: &HostState,
    host: &str,
    port: u16,
    result: &Result<T, E>,
) {
    audit_net(state, "astrid:net/host.connect-tcp", 0, result);
    let Some(sink) = state.audit_sink.as_ref() else {
        return;
    };
    let err_buf;
    let outcome = match result {
        Ok(_) => HostAuditOutcome::Allowed,
        Err(e) => {
            err_buf = format!("{e:?}");
            HostAuditOutcome::Failed(&err_buf)
        },
    };
    sink.record(
        &state.effective_principal(),
        HostAuditEvent::NetConnect { host, port },
        outcome,
    );
}

/// Record an inbound TCP accept with the host-observed local and peer
/// endpoints, so traffic entering a capsule retains durable provenance.
pub(crate) fn audit_net_accept<T, E: std::fmt::Debug>(
    state: &HostState,
    local_addr: &str,
    peer_addr: &str,
    result: &Result<T, E>,
) {
    audit_net(state, "astrid:net/host.tcp-listener.accept", 0, result);
    let Some(sink) = state.audit_sink.as_ref() else {
        return;
    };
    let error;
    let outcome = match result {
        Ok(_) => HostAuditOutcome::Allowed,
        Err(err) => {
            error = format!("{err:?}");
            HostAuditOutcome::Failed(&error)
        },
    };
    sink.record(
        &state.effective_principal(),
        HostAuditEvent::NetAccept {
            local_addr,
            peer_addr,
        },
        outcome,
    );
}

/// Report a denied net operation to the per-action audit sink. The connect
/// gate rejects before any socket effect and early-returns, so this is the
/// only audit report a denied connect makes (exactly-once recording).
pub(crate) fn record_net_denied(state: &HostState, event: HostAuditEvent<'_>, reason: &str) {
    if let Some(sink) = state.audit_sink.as_ref() {
        sink.record(
            &state.effective_principal(),
            event,
            HostAuditOutcome::Denied(reason),
        );
    }
}

/// Report a local-transport bind outcome (allowed or failed) to the per-action
/// audit sink. The bind path has no host:port, so it carries a fixed
/// descriptor for the pre-provisioned listener. Mirrors [`audit_net_connect`]
/// for the listener side; a gate denial uses [`record_net_denied`] instead
/// (it rejects before any effect, exactly-once).
pub(crate) fn audit_net_bind(state: &HostState, addr: &str, outcome: HostAuditOutcome<'_>) {
    if let Some(sink) = state.audit_sink.as_ref() {
        sink.record(
            &state.effective_principal(),
            HostAuditEvent::NetBind { addr },
            outcome,
        );
    }
}

/// Borrow the `NetStream` stored at `rep` in the resource table.
pub(super) fn net_stream(
    table: &wasmtime::component::ResourceTable,
    rep: u32,
) -> Result<NetStream, ErrorCode> {
    table
        .get::<NetStream>(&Resource::new_borrow(rep))
        .cloned()
        .map_err(|_| ErrorCode::InvalidHandle)
}

/// Get-and-mutate the timeout fields of a `NetStream::Tcp` slot.
pub(super) fn with_tcp_slot_mut<F>(
    table: &mut wasmtime::component::ResourceTable,
    rep: u32,
    op: F,
) -> Result<(), ErrorCode>
where
    F: FnOnce(&mut TcpStreamSlot),
{
    let s = table
        .get_mut::<NetStream>(&Resource::new_borrow(rep))
        .map_err(|_| ErrorCode::InvalidHandle)?;
    match s {
        NetStream::Tcp(slot) => {
            op(slot);
            Ok(())
        },
        NetStream::Unix(_) => Err(ErrorCode::NotTcp),
    }
}

/// Run `op` against the inner `tokio::net::TcpStream` of an outbound TCP
/// stream. Returns `not-tcp` if the handle is a Unix-domain stream.
pub(super) fn with_tcp_stream<T, F>(state: &mut HostState, rep: u32, op: F) -> Result<T, ErrorCode>
where
    F: FnOnce(&tokio::net::TcpStream) -> Result<T, ErrorCode>,
{
    let stream = net_stream(&state.resource_table, rep)?;
    let rt = state.runtime_handle.clone();
    let sem = state.blocking_semaphore.clone();
    let tok = state.effective_cancel_token();
    match stream {
        NetStream::Tcp(slot) => {
            let result = util::bounded_block_on_cancellable(&rt, &sem, &tok, async move {
                let s = slot.stream.lock().await;
                op(&s)
            });
            result.unwrap_or(Err(ErrorCode::Closed))
        },
        NetStream::Unix(_) => Err(ErrorCode::NotTcp),
    }
}

// ────────────────────────────────────────────────────────────────────────
// astrid:net/host::Host — top-level factory functions
// ────────────────────────────────────────────────────────────────────────

impl net::Host for HostState {
    fn bind_unix(&mut self) -> Result<Resource<UnixListener>, ErrorCode> {
        // Stable descriptor for the pre-provisioned CLI control socket — a
        // Unix-domain listener has no host:port, so this names the bind on
        // the audit chain.
        let bind_addr = "unix:cli-socket";
        if let Some(ref gate) = self.security {
            let capsule_id = self.capsule_id.as_str().to_owned();
            let gate = gate.clone();
            let handle = self.runtime_handle.clone();
            let semaphore = self.blocking_semaphore.clone();
            let check = util::bounded_block_on(&handle, &semaphore, async move {
                gate.check_net_bind(&capsule_id).await
            });
            if let Err(reason) = check {
                // Deny path: record before the early return — the success
                // report below is never reached (exactly-once recording).
                record_net_denied(self, HostAuditEvent::NetBind { addr: bind_addr }, &reason);
                return Err(ErrorCode::CapabilityDenied);
            }
        }

        // Native astrid-daemon claims the control socket first. Capsules that
        // still call bind_unix (aos-cli) must not fail the run loop: accept()
        // on this handle returns Closed and the capsule backs off.
        let res = match self.resource_table.push(UnixListenerSlot) {
            Ok(res) => res,
            Err(e) => {
                let reason = format!("resource table: {e}");
                audit_net_bind(self, bind_addr, HostAuditOutcome::Failed(&reason));
                return Err(ErrorCode::Unknown(reason));
            },
        };
        // Success: the capsule bound its listener — land it on the signed
        // audit chain alongside the failed/denied paths above.
        audit_net_bind(self, bind_addr, HostAuditOutcome::Allowed);
        Ok(Resource::new_own(res.rep()))
    }

    fn bind_tcp(&mut self, host: String, port: u16) -> Result<Resource<TcpListener>, ErrorCode> {
        validate_host(&host)?;
        let bind_addr = format!("tcp:{host}:{port}");

        // Capability gate: host:port must match the capsule's `net_bind`
        // allowlist (TCP entries share that field with unix binds).
        if let Some(ref gate) = self.security {
            let capsule_id = self.capsule_id.as_str().to_owned();
            let host_for_check = host.clone();
            let gate = gate.clone();
            let rt = self.runtime_handle.clone();
            let semaphore = self.blocking_semaphore.clone();
            let check = util::bounded_block_on(&rt, &semaphore, async move {
                gate.check_net_tcp_bind(&capsule_id, &host_for_check, port)
                    .await
            });
            if let Err(reason) = check {
                // Deny path records before the early return (exactly-once).
                record_net_denied(self, HostAuditEvent::NetBind { addr: &bind_addr }, &reason);
                return Err(ErrorCode::CapabilityDenied);
            }
        }

        // Security rail: capsule-hosted servers are loopback-only. Exposing a
        // capsule listener beyond loopback is a deliberate future opt-in; this
        // mirrors `connect-tcp`, which runs its `is_safe_ip` airlock AFTER the
        // capability gate. A non-loopback bind is refused here, not silently
        // downgraded.
        if !is_loopback_bind_host(&host) {
            let reason = "non-loopback TCP bind refused (capsule servers are loopback-only)";
            audit_net_bind(self, &bind_addr, HostAuditOutcome::Failed(reason));
            return Err(ErrorCode::AirlockRejected);
        }

        // Resolve the listener via the shared registry so a run-loop capsule's
        // N worker Stores dedupe onto ONE bound socket (Approach B): the first
        // worker binds, the rest observe the Occupied entry and clone its
        // `Arc<TcpListener>`. All N then block on `accept()` against the single
        // OS accept queue, which load-balances (SO_REUSEPORT does NOT on macOS:
        // it delivers every connection to the most-recent bind).
        //
        // The bind runs UNDER the shard lock so racing workers serialize here —
        // without it a second concurrent bind fails EADDRINUSE (macOS sets no
        // SO_REUSEADDR). Quick op, so the non-cancellable bounded_block_on is
        // fine; accept, which blocks indefinitely, uses the cancellable variant.
        //
        // Interceptor / non-worker pool instances each have a fresh
        // `shared_listeners` map, so a concrete-port bind is not cloned across
        // pooled HostStates. Worker Stores (`bind_workers > 1`) share one map
        // AND set `share_tcp_listeners`. N=1 keeps the map private *and*
        // skips the Occupied clone, so a second bind is AddressInUse.
        //
        // `localhost` is accepted for ergonomics but never handed to the
        // resolver: local name service is mutable host configuration and may
        // map it to a non-loopback address. Bind a concrete loopback literal.
        // Normalized BEFORE the registry key so `localhost` and `127.0.0.1`
        // dedupe onto one entry rather than racing for the same OS port.
        let host = if host.eq_ignore_ascii_case("localhost") {
            "127.0.0.1".to_string()
        } else {
            host
        };
        // Sharing is a worker-Store feature (`share_tcp_listeners`), not a
        // property of the port. N=1 and interceptor HostStates must attempt a
        // real OS bind so a second bind_tcp on the same state is AddressInUse
        // — byte-identical to pre-bind_workers. Port 0 still never shares:
        // two ephemeral requests are different addresses. Concrete-port
        // sharing is what a run-loop capsule's workers bind: the port
        // declared in `net_bind`.
        let shareable = self.share_tcp_listeners && port != 0;
        let mut share = None;
        let mut listener_count = None;
        let listener: Arc<tokio::net::TcpListener> = if !shareable {
            let rt = self.runtime_handle.clone();
            let sem = self.blocking_semaphore.clone();
            let host_owned = host.clone();
            let bind_result: Result<tokio::net::TcpListener, std::io::Error> =
                util::bounded_block_on(&rt, &sem, async move {
                    tokio::net::TcpListener::bind((host_owned.as_str(), port)).await
                });
            match bind_result {
                Ok(l) => {
                    if self
                        .tcp_listener_count
                        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                            (count < MAX_ACTIVE_TCP_LISTENERS).then_some(count + 1)
                        })
                        .is_err()
                    {
                        let reason = "inbound TCP listener quota exceeded";
                        audit_net_bind(self, &bind_addr, HostAuditOutcome::Failed(reason));
                        return Err(ErrorCode::Quota);
                    }
                    listener_count = Some(Arc::clone(&self.tcp_listener_count));
                    Arc::new(l)
                },
                Err(e) => {
                    let mapped = map_io_err(e);
                    let reason = format!("{mapped:?}");
                    audit_net_bind(self, &bind_addr, HostAuditOutcome::Failed(&reason));
                    return Err(mapped);
                },
            }
        } else {
            enum SharedBind {
                Listener(Arc<tokio::net::TcpListener>),
                Io(ErrorCode),
                Quota,
            }
            let outcome = match self.shared_listeners.entry((host.clone(), port)) {
                dashmap::mapref::entry::Entry::Occupied(existing) => {
                    let previous = existing.get().holders.fetch_add(1, Ordering::AcqRel);
                    debug_assert!(
                        previous > 0,
                        "occupied shared listener must have a live holder"
                    );
                    SharedBind::Listener(Arc::clone(&existing.get().listener))
                },
                dashmap::mapref::entry::Entry::Vacant(vacant) => {
                    let rt = self.runtime_handle.clone();
                    let sem = self.blocking_semaphore.clone();
                    let host_owned = host.clone();
                    let bind_result: Result<tokio::net::TcpListener, std::io::Error> =
                        util::bounded_block_on(&rt, &sem, async move {
                            tokio::net::TcpListener::bind((host_owned.as_str(), port)).await
                        });
                    match bind_result {
                        Ok(l) => {
                            // Charge quota before insert so a racing sibling cannot
                            // clone a socket that then fails the quota gate.
                            if self
                                .tcp_listener_count
                                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                                    (count < MAX_ACTIVE_TCP_LISTENERS).then_some(count + 1)
                                })
                                .is_err()
                            {
                                SharedBind::Quota
                            } else {
                                let listener = Arc::new(l);
                                vacant.insert(SharedTcpListener {
                                    listener: Arc::clone(&listener),
                                    holders: std::sync::atomic::AtomicUsize::new(1),
                                });
                                SharedBind::Listener(listener)
                            }
                        },
                        Err(e) => SharedBind::Io(map_io_err(e)),
                    }
                },
            };
            match outcome {
                SharedBind::Listener(listener) => listener,
                SharedBind::Quota => {
                    let reason = "inbound TCP listener quota exceeded";
                    audit_net_bind(self, &bind_addr, HostAuditOutcome::Failed(reason));
                    return Err(ErrorCode::Quota);
                },
                SharedBind::Io(mapped) => {
                    let reason = format!("{mapped:?}");
                    audit_net_bind(self, &bind_addr, HostAuditOutcome::Failed(&reason));
                    return Err(mapped);
                },
            }
        };
        if shareable {
            share = Some(TcpListenerShare {
                key: (host.clone(), port),
                registry: Arc::clone(&self.shared_listeners),
                quota: Arc::clone(&self.tcp_listener_count),
            });
        }
        let actual_addr = match listener.local_addr() {
            Ok(addr) if addr.ip().is_loopback() => format!("tcp:{addr}"),
            Ok(addr) => {
                let reason = format!("resolved bind escaped loopback: {addr}");
                audit_net_bind(self, &bind_addr, HostAuditOutcome::Failed(&reason));
                if let Some(share) = share {
                    share.release();
                } else if let Some(listener_count) = listener_count.as_ref() {
                    let _ =
                        listener_count.fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                            count.checked_sub(1)
                        });
                }
                return Err(ErrorCode::AirlockRejected);
            },
            Err(e) => {
                let mapped = map_io_err(e);
                let reason = format!("{mapped:?}");
                audit_net_bind(self, &bind_addr, HostAuditOutcome::Failed(&reason));
                if let Some(share) = share {
                    share.release();
                } else if let Some(listener_count) = listener_count.as_ref() {
                    let _ =
                        listener_count.fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                            count.checked_sub(1)
                        });
                }
                return Err(mapped);
            },
        };

        let slot = TcpListenerSlot {
            listener,
            pending: Arc::new(PendingTcpConnection {
                connection: tokio::sync::Mutex::new(None),
                stream_count: Arc::clone(&self.capsule_net_stream_count),
                local_stream_count: Arc::clone(&self.local_net_stream_count),
            }),
            cancel_token: self.effective_cancel_token(),
            share,
            listener_count,
        };
        let res = match self.resource_table.push(slot) {
            Ok(res) => res,
            Err(e) => {
                // The socket is already bound; the push consumes and drops the
                // listener here, releasing it. Record the failure.
                let reason = format!("resource table: {e}");
                audit_net_bind(self, &bind_addr, HostAuditOutcome::Failed(&reason));
                return Err(ErrorCode::Unknown(reason));
            },
        };
        audit_net_bind(self, &actual_addr, HostAuditOutcome::Allowed);
        Ok(Resource::new_own(res.rep()))
    }

    fn connect_tcp(&mut self, host: String, port: u16) -> Result<Resource<TcpStream>, ErrorCode> {
        validate_host(&host)?;

        if !self.principal_egress_allows(&host, Some(port)) {
            record_net_denied(
                self,
                HostAuditEvent::NetConnect { host: &host, port },
                "restricted principal network policy denied endpoint",
            );
            return Err(ErrorCode::CapabilityDenied);
        }

        if let Some(ref gate) = self.security {
            let capsule_id = self.capsule_id.as_str().to_owned();
            let host_for_check = host.clone();
            let gate = gate.clone();
            let rt = self.runtime_handle.clone();
            let semaphore = self.blocking_semaphore.clone();
            let check = util::bounded_block_on(&rt, &semaphore, async move {
                gate.check_net_connect(&capsule_id, &host_for_check, port)
                    .await
            });
            if let Err(reason) = check {
                // Deny path: record before the early return — the
                // success-path audit below is never reached (exactly-once).
                record_net_denied(
                    self,
                    HostAuditEvent::NetConnect { host: &host, port },
                    &reason,
                );
                return Err(ErrorCode::CapabilityDenied);
            }
        }

        if self.capsule_net_stream_count.load(Ordering::Acquire) >= MAX_ACTIVE_STREAMS {
            let result: Result<Resource<TcpStream>, ErrorCode> = Err(ErrorCode::Quota);
            audit_net_connect(self, &host, port, &result);
            return result;
        }

        let rt_handle = self.runtime_handle.clone();
        let blocking_semaphore = self.blocking_semaphore.clone();
        let cancel_token = self.effective_cancel_token();

        let connect_result = util::bounded_block_on_cancellable(
            &rt_handle,
            &blocking_semaphore,
            &cancel_token,
            async {
                tokio::time::timeout(CONNECT_TIMEOUT, async {
                    let addrs: Vec<std::net::SocketAddr> =
                        tokio::net::lookup_host((host.as_str(), port))
                            .await
                            .map_err(|_| ErrorCode::NameUnresolvable)?
                            .collect();
                    if addrs.is_empty() {
                        return Err(ErrorCode::NameUnresolvable);
                    }
                    for addr in &addrs {
                        if !is_safe_ip(addr.ip()) {
                            return Err(ErrorCode::AirlockRejected);
                        }
                    }
                    tokio::net::TcpStream::connect(&addrs[..])
                        .await
                        .map_err(map_io_err)
                })
                .await
                .map_err(|_| ErrorCode::Timeout)
                .and_then(|inner| inner)
            },
        );

        let stream = match connect_result {
            Some(Ok(s)) => s,
            Some(Err(e)) => {
                let result: Result<Resource<TcpStream>, ErrorCode> = Err(e);
                audit_net_connect(self, &host, port, &result);
                return result;
            },
            None => {
                let result: Result<Resource<TcpStream>, ErrorCode> = Err(ErrorCode::Closed);
                audit_net_connect(self, &host, port, &result);
                return result;
            },
        };

        if !self.reserve_net_stream() {
            drop(stream);
            let result: Result<Resource<TcpStream>, ErrorCode> = Err(ErrorCode::Quota);
            audit_net_connect(self, &host, port, &result);
            return result;
        }

        let net_stream = NetStream::Tcp(TcpStreamSlot {
            stream: Arc::new(tokio::sync::Mutex::new(stream)),
            read_timeout: None,
            write_timeout: None,
        });
        let res = match self.resource_table.push(net_stream) {
            Ok(res) => res,
            Err(e) => {
                self.release_net_stream();
                // The TCP connect ALREADY SUCCEEDED (the socket is open); the
                // push consumes and drops the stream here, aborting the
                // connection. Record the connect as having happened with a
                // Failed outcome rather than returning silently via `?`.
                let result: Result<Resource<TcpStream>, ErrorCode> =
                    Err(ErrorCode::Unknown(format!("resource table: {e}")));
                audit_net_connect(self, &host, port, &result);
                return result;
            },
        };
        let result: Result<Resource<TcpStream>, ErrorCode> = Ok(Resource::new_own(res.rep()));
        audit_net_connect(self, &host, port, &result);
        result
    }

    fn udp_bind(&mut self, _host: String, _port: u16) -> Result<Resource<UdpSocket>, ErrorCode> {
        // UDP bind needs the per-call SSRF airlock + capability gate +
        // capsule UDP socket cap. Port-back lands alongside TcpListener.
        Err(ErrorCode::CapabilityDenied)
    }

    fn lookup_host(&mut self, host: String) -> Result<Vec<String>, ErrorCode> {
        validate_host(&host)?;
        if !self.principal_egress_allows(&host, None) {
            return Err(ErrorCode::CapabilityDenied);
        }
        if let Some(ref gate) = self.security {
            let capsule_id = self.capsule_id.as_str().to_owned();
            let host_for_check = host.clone();
            let gate = gate.clone();
            let rt = self.runtime_handle.clone();
            let semaphore = self.blocking_semaphore.clone();
            // Port 0 here is "no specific port": the gate is being
            // asked "may this capsule resolve this hostname?" rather
            // than "may it connect to host:port?". Manifest entries
            // that pin a port (`api.example.com:443`) must therefore
            // have a permissive sibling (`api.example.com:*`) to
            // permit resolution — strict per-port gating today
            // requires splitting the manifest into resolve-only and
            // connect-only entries. A dedicated `check_net_resolve`
            // gate method is tracked as a future refinement so this
            // overload of port 0 can be removed.
            let check = util::bounded_block_on(&rt, &semaphore, async move {
                gate.check_net_connect(&capsule_id, &host_for_check, 0)
                    .await
            });
            if check.is_err() {
                return Err(ErrorCode::CapabilityDenied);
            }
        }

        let rt = self.runtime_handle.clone();
        let sem = self.blocking_semaphore.clone();
        let host_owned = host.clone();
        // Collect inside the closure so the borrow on `host_owned` ends
        // before the async block returns — the iterator from
        // `tokio::net::lookup_host` borrows its host string.
        let resolved: Vec<std::net::SocketAddr> = util::bounded_block_on(&rt, &sem, async move {
            tokio::net::lookup_host((host_owned.as_str(), 0))
                .await
                .map(|it| it.collect::<Vec<_>>())
        })
        .map_err(|_| ErrorCode::NameUnresolvable)?;
        let mut out = Vec::new();
        for addr in resolved {
            if is_safe_ip(addr.ip()) {
                out.push(addr.to_string());
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
