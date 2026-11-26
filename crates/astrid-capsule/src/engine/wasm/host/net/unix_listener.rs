//! `HostUnixListener` impl — the kernel-pre-bound Unix listener.
//!
//! `accept` / `poll-accept` perform session-token + peer-credential
//! handshake before exposing the authenticated stream as a
//! `NetStream::Unix` resource handle.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use astrid_core::local_transport;
use wasmtime::component::Resource;
use wasmtime_wasi::p2::DynPollable;

use super::client_lifecycle;
use super::handshake::{validate_handshake, verify_peer_credentials};
use super::{HostState, MAX_ACTIVE_STREAMS, NetStream, UnixListenerSlot, audit_net, map_io_err};
use crate::engine::wasm::bindings::astrid::net::host::{
    ErrorCode, HostUnixListener, TcpStream, UnixListener,
};
use crate::engine::wasm::host::util;
use crate::engine::wasm::host_state::{ConnectionIdentity, SignedSocket};

/// Authentication reloads device keys from disk under the same root used for
/// dispatch. Standalone hosts without an injected cache use the process home.
fn handshake_home(state: &HostState) -> std::io::Result<astrid_core::dirs::AstridHome> {
    match &state.profile_cache {
        Some(cache) => Ok(cache.home().clone()),
        None => astrid_core::dirs::AstridHome::resolve(),
    }
}

pub(super) fn install_accepted(
    state: &mut HostState,
    stream: local_transport::LocalStream,
    identity: Option<(
        astrid_core::PrincipalId,
        String,
        astrid_core::profile::device_sessions::DeviceSession,
    )>,
) -> Result<Resource<TcpStream>, ErrorCode> {
    let (stream, signed) = match identity {
        Some((principal, key, session)) => {
            let identity = ConnectionIdentity::new(principal, Some(key));
            let socket = SignedSocket::new(stream, session, identity, &state.runtime_handle);
            (NetStream::Signed(socket.clone()), Some(socket))
        },
        None => (
            NetStream::Unix(Arc::new(tokio::sync::Mutex::new(stream))),
            None,
        ),
    };
    let resource = state.resource_table.push(stream).map_err(|error| {
        state.release_net_stream();
        ErrorCode::Unknown(format!("resource table: {error}"))
    })?;
    let rep = resource.rep();
    if let Some(socket) = signed {
        if !socket.register_connection(state) {
            let _ = state.resource_table.delete(resource);
            state.release_net_stream();
            return Err(ErrorCode::Closed);
        }
    } else {
        client_lifecycle::register_and_emit_connect(
            state,
            rep,
            astrid_core::PrincipalId::anonymous(),
        );
    }
    Ok(Resource::new_own(rep))
}

impl HostUnixListener for HostState {
    fn accept(&mut self, _self_: Resource<UnixListener>) -> Result<Resource<TcpStream>, ErrorCode> {
        if self.capsule_net_stream_count.load(Ordering::Acquire) >= MAX_ACTIVE_STREAMS {
            return Err(ErrorCode::Quota);
        }

        let rt_handle = self.runtime_handle.clone();
        let cancel_token = self.effective_cancel_token();
        let session_token = self.session_token.clone();
        let blocking_semaphore = self.blocking_semaphore.clone();
        let Some(listener_arc) = self.cli_socket_listener.clone() else {
            // Native daemon already claimed the control socket. Park until
            // teardown so aos-cli stays Ready instead of trapping on Closed.
            let parked = util::bounded_block_on_cancellable(
                &rt_handle,
                &blocking_semaphore,
                &cancel_token,
                std::future::pending::<()>(),
            );
            let _ = parked;
            return Err(ErrorCode::Closed);
        };

        // Resolved once and reused for every accept iteration: where a claimed
        // principal's profile/keys load from during the handshake challenge
        // (issue #45/#852). Only resolved when a session token gates the
        // handshake; an unauthenticated daemon never reaches
        // `validate_handshake`, so `None` is fine there.
        let astrid_home = if session_token.is_some() {
            Some(
                handshake_home(self)
                    .map_err(|e| ErrorCode::Unknown(format!("cannot resolve astrid home: {e}")))?,
            )
        } else {
            None
        };

        // The handshake yields `Some((principal, device_key_id))` for a
        // crypto-authenticated connection — the device id rides forward so the
        // cap-gate can scope it — or `None` for a legacy/unauthenticated peer.
        let (stream, verified_identity) = loop {
            let accept_result = util::bounded_block_on_cancellable(
                &rt_handle,
                &blocking_semaphore,
                &cancel_token,
                async {
                    let l = listener_arc.lock().await;
                    local_transport::accept(&l).await
                },
            );
            let stream = match accept_result {
                Some(result) => result.map_err(map_io_err)?,
                None => return Err(ErrorCode::Closed),
            };

            if let Err(reason) = verify_peer_credentials(&stream) {
                tracing::warn!(
                    security_event = true,
                    reason = %reason,
                    "rejected unix accept: peer creds"
                );
                drop(stream);
                // Backoff to keep a flood of UID-mismatched clients
                // from spinning the accept loop at syscall speed.
                // The handshake path has a 5s timeout that already
                // throttles slow-but-valid-creds clients; this branch
                // doesn't enter the handshake at all.
                let _ = util::bounded_block_on_cancellable(
                    &rt_handle,
                    &blocking_semaphore,
                    &cancel_token,
                    async {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    },
                );
                continue;
            }

            let mut stream = stream;
            if let (Some(token), Some(home)) = (&session_token, &astrid_home) {
                let handshake_result = util::bounded_block_on_cancellable(
                    &rt_handle,
                    &blocking_semaphore,
                    &cancel_token,
                    validate_handshake(&mut stream, token, home, &self.device_sessions),
                );
                match handshake_result {
                    None => return Err(ErrorCode::Closed),
                    Some(Ok(identity)) => break (stream, identity),
                    Some(Err(reason)) => {
                        tracing::warn!(
                            security_event = true,
                            reason = %reason,
                            "rejected unix accept: handshake"
                        );
                        drop(stream);
                        continue;
                    },
                }
            } else {
                break (stream, None);
            }
        };

        if !self.reserve_net_stream() {
            drop(stream);
            return Err(ErrorCode::Quota);
        }

        let result = install_accepted(self, stream, verified_identity);
        audit_net(self, "astrid:net/host.unix-listener.accept", 0, &result);
        result
    }

    fn poll_accept(
        &mut self,
        _self_: Resource<UnixListener>,
        timeout_ms: u64,
    ) -> Result<Option<Resource<TcpStream>>, ErrorCode> {
        let rt_handle = self.runtime_handle.clone();
        let cancel_token = self.effective_cancel_token();
        let session_token = self.session_token.clone();
        let blocking_semaphore = self.blocking_semaphore.clone();
        let Some(listener_arc) = self.cli_socket_listener.clone() else {
            // Native daemon already claimed the control socket. Park until
            // teardown so aos-cli stays Ready instead of trapping on Closed.
            let parked = util::bounded_block_on_cancellable(
                &rt_handle,
                &blocking_semaphore,
                &cancel_token,
                std::future::pending::<()>(),
            );
            let _ = parked;
            return Err(ErrorCode::Closed);
        };

        if self.capsule_net_stream_count.load(Ordering::Acquire) >= MAX_ACTIVE_STREAMS {
            return Ok(None);
        }

        let timeout_ms = timeout_ms.min(60_000);
        let accept_result = util::bounded_block_on_cancellable(
            &rt_handle,
            &blocking_semaphore,
            &cancel_token,
            async {
                let l = listener_arc.lock().await;
                tokio::time::timeout(
                    Duration::from_millis(timeout_ms),
                    local_transport::accept(&l),
                )
                .await
            },
        );

        let stream = match accept_result {
            None => return Ok(None),
            Some(Err(_)) => return Ok(None),
            Some(Ok(Err(e))) => return Err(map_io_err(e)),
            Some(Ok(Ok(stream))) => stream,
        };

        if let Err(reason) = verify_peer_credentials(&stream) {
            tracing::warn!(
                security_event = true,
                reason = %reason,
                "rejected unix poll_accept: peer creds"
            );
            drop(stream);
            return Ok(None);
        }

        let mut stream = stream;
        let mut verified_identity = None;
        if let Some(ref token) = session_token {
            // See `accept` for why home is resolved here (issue #45/#852).
            let home = match handshake_home(self) {
                Ok(h) => h,
                Err(e) => {
                    tracing::warn!(
                        security_event = true,
                        error = %e,
                        "rejected unix poll_accept: cannot resolve astrid home"
                    );
                    drop(stream);
                    return Ok(None);
                },
            };
            let handshake_result = util::bounded_block_on_cancellable(
                &rt_handle,
                &blocking_semaphore,
                &cancel_token,
                validate_handshake(&mut stream, token, &home, &self.device_sessions),
            );
            match handshake_result {
                None => return Ok(None),
                Some(Err(reason)) => {
                    tracing::warn!(
                        security_event = true,
                        reason = %reason,
                        "rejected unix poll_accept: handshake"
                    );
                    drop(stream);
                    return Ok(None);
                },
                Some(Ok(identity)) => verified_identity = identity,
            }
        }

        if !self.reserve_net_stream() {
            drop(stream);
            return Ok(None);
        }

        install_accepted(self, stream, verified_identity).map(Some)
    }

    fn subscribe_readiness(&mut self, _self_: Resource<UnixListener>) -> Resource<DynPollable> {
        // Real wiring (tokio UnixListener::poll_accept-backed) lands
        // with the dedicated pollable commit. Always-ready sentinel
        // until then — guests poll, call accept, get a connection or
        // wait inside accept's own blocking path.
        super::super::stubs::always_ready_pollable(&mut self.resource_table)
    }

    fn drop(&mut self, rep: Resource<UnixListener>) -> wasmtime::Result<()> {
        let _ = self
            .resource_table
            .delete::<UnixListenerSlot>(Resource::new_own(rep.rep()));
        Ok(())
    }
}
