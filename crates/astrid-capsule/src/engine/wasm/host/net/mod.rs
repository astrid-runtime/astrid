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

use wasmtime::component::Resource;

use crate::engine::wasm::bindings::astrid::net::host::{
    self as net, ErrorCode, TcpListener, TcpStream, UdpSocket, UnixListener,
};
use crate::engine::wasm::host::http::is_safe_ip;
use crate::engine::wasm::host::util;
use crate::engine::wasm::host_state::{HostState, NetStream, TcpStreamSlot};

mod handshake;
mod stream;
mod tcp_listener;
mod tcp_stream;
mod udp_socket;
mod unix_listener;

use stream::CONNECT_TIMEOUT;

/// Maximum concurrent socket connections per capsule. Defense-in-depth
/// cap on top of the per-principal profile quota. Tracked via
/// [`HostState::net_stream_count`], bumped on every successful
/// `accept` / `connect-tcp` push and decremented in the resource
/// drop path.
pub(super) const MAX_ACTIVE_STREAMS: usize = 8;

/// Stamp marking a resource slot in the table as a `UnixListener` handle.
/// The kernel pre-binds the listener; the resource handle is just a
/// capability token that the capsule must hold to call `accept`.
pub(super) struct UnixListenerSlot;

/// Stamp marking a resource slot as a `TcpListener` for future inbound
/// TCP server support. Pre-allocated so the type is in scope even though
/// `bind-tcp` is still a stub.
#[allow(dead_code)]
pub(super) struct TcpListenerSlot;

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
    let sem = state.host_semaphore.clone();
    let tok = state.cancel_token.clone();
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
        if let Some(ref gate) = self.security {
            let capsule_id = self.capsule_id.as_str().to_owned();
            let gate = gate.clone();
            let handle = self.runtime_handle.clone();
            let semaphore = self.host_semaphore.clone();
            let check = util::bounded_block_on(&handle, &semaphore, async move {
                gate.check_net_bind(&capsule_id).await
            });
            if check.is_err() {
                return Err(ErrorCode::CapabilityDenied);
            }
        }

        if self.cli_socket_listener.is_none() {
            return Err(ErrorCode::Unknown(
                "no pre-bound Unix listener configured".to_string(),
            ));
        }

        let res = self
            .resource_table
            .push(UnixListenerSlot)
            .map_err(|e| ErrorCode::Unknown(format!("resource table: {e}")))?;
        Ok(Resource::new_own(res.rep()))
    }

    fn bind_tcp(&mut self, _host: String, _port: u16) -> Result<Resource<TcpListener>, ErrorCode> {
        // Inbound TCP server hosting — needs a fresh tokio listener +
        // capability gate (net_tcp_bind allowlist) + per-capsule accept
        // loop. Lands in a follow-up commit; capsules importing
        // `bind-tcp` today see CapabilityDenied so they fail closed.
        Err(ErrorCode::CapabilityDenied)
    }

    fn connect_tcp(&mut self, host: String, port: u16) -> Result<Resource<TcpStream>, ErrorCode> {
        validate_host(&host)?;

        if let Some(ref gate) = self.security {
            let capsule_id = self.capsule_id.as_str().to_owned();
            let host_for_check = host.clone();
            let gate = gate.clone();
            let rt = self.runtime_handle.clone();
            let semaphore = self.host_semaphore.clone();
            let check = util::bounded_block_on(&rt, &semaphore, async move {
                gate.check_net_connect(&capsule_id, &host_for_check, port)
                    .await
            });
            if check.is_err() {
                return Err(ErrorCode::CapabilityDenied);
            }
        }

        if self.net_stream_count >= MAX_ACTIVE_STREAMS {
            return Err(ErrorCode::Quota);
        }

        let rt_handle = self.runtime_handle.clone();
        let host_semaphore = self.host_semaphore.clone();
        let cancel_token = self.cancel_token.clone();

        let connect_result =
            util::bounded_block_on_cancellable(&rt_handle, &host_semaphore, &cancel_token, async {
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
            });

        let stream = match connect_result {
            Some(Ok(s)) => s,
            Some(Err(e)) => return Err(e),
            None => return Err(ErrorCode::Closed),
        };

        if self.net_stream_count >= MAX_ACTIVE_STREAMS {
            drop(stream);
            return Err(ErrorCode::Quota);
        }

        let net_stream = NetStream::Tcp(TcpStreamSlot {
            stream: Arc::new(tokio::sync::Mutex::new(stream)),
            read_timeout: None,
            write_timeout: None,
        });
        let res = self
            .resource_table
            .push(net_stream)
            .map_err(|e| ErrorCode::Unknown(format!("resource table: {e}")))?;
        self.net_stream_count += 1;
        let result: Result<Resource<TcpStream>, ErrorCode> = Ok(Resource::new_own(res.rep()));
        audit_net(self, "astrid:net/host.connect-tcp", 0, &result);
        result
    }

    fn udp_bind(&mut self, _host: String, _port: u16) -> Result<Resource<UdpSocket>, ErrorCode> {
        // UDP bind needs the per-call SSRF airlock + capability gate +
        // capsule UDP socket cap. Port-back lands alongside TcpListener.
        Err(ErrorCode::CapabilityDenied)
    }

    fn lookup_host(&mut self, host: String) -> Result<Vec<String>, ErrorCode> {
        validate_host(&host)?;
        if let Some(ref gate) = self.security {
            let capsule_id = self.capsule_id.as_str().to_owned();
            let host_for_check = host.clone();
            let gate = gate.clone();
            let rt = self.runtime_handle.clone();
            let semaphore = self.host_semaphore.clone();
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
        let sem = self.host_semaphore.clone();
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
mod tests {
    use super::*;

    #[test]
    fn max_active_streams_pinned() {
        assert_eq!(MAX_ACTIVE_STREAMS, 8);
    }

    #[test]
    fn validate_host_accepts_normal_names() {
        assert!(validate_host("example.com").is_ok());
        assert!(validate_host("fulcrum.unicity.network").is_ok());
        assert!(validate_host("127.0.0.1").is_ok());
        assert!(validate_host("::1").is_ok());
    }

    #[test]
    fn validate_host_rejects_empty() {
        assert!(validate_host("").is_err());
    }

    #[test]
    fn validate_host_rejects_null_bytes() {
        assert!(validate_host("evil\0.com").is_err());
    }

    #[test]
    fn validate_host_rejects_overlength() {
        let long = "a".repeat(256);
        assert!(validate_host(&long).is_err());
    }

    #[test]
    fn validate_host_accepts_max_length() {
        let max = "a".repeat(255);
        assert!(validate_host(&max).is_ok());
    }
}
