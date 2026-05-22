//! `HostUnixListener` impl — the kernel-pre-bound Unix listener.
//!
//! `accept` / `poll-accept` perform session-token + peer-credential
//! handshake before exposing the authenticated stream as a
//! `NetStream::Unix` resource handle.

use std::sync::Arc;
use std::time::Duration;

use wasmtime::component::Resource;
use wasmtime_wasi::p2::DynPollable;

use super::handshake::validate_handshake;
#[cfg(unix)]
use super::handshake::verify_peer_credentials;
use super::{
    HostState, MAX_ACTIVE_STREAMS, NetStream, UnixListenerSlot, audit_net, count_net_streams,
    map_io_err,
};
use crate::engine::wasm::bindings::astrid::net::host::{
    ErrorCode, HostUnixListener, TcpStream, UnixListener,
};
use crate::engine::wasm::host::util;

impl HostUnixListener for HostState {
    fn accept(&mut self, _self_: Resource<UnixListener>) -> Result<Resource<TcpStream>, ErrorCode> {
        if count_net_streams(&mut self.resource_table) >= MAX_ACTIVE_STREAMS {
            return Err(ErrorCode::Quota);
        }

        let listener_arc = self.cli_socket_listener.clone().ok_or(ErrorCode::Closed)?;
        let rt_handle = self.runtime_handle.clone();
        let cancel_token = self.cancel_token.clone();
        let session_token = self.session_token.clone();
        let host_semaphore = self.host_semaphore.clone();

        let stream = loop {
            let accept_result = util::bounded_block_on_cancellable(
                &rt_handle,
                &host_semaphore,
                &cancel_token,
                async {
                    let l = listener_arc.lock().await;
                    l.accept().await
                },
            );
            let (stream, _addr) = match accept_result {
                Some(result) => result.map_err(map_io_err)?,
                None => return Err(ErrorCode::Closed),
            };

            #[cfg(unix)]
            if let Err(reason) = verify_peer_credentials(&stream) {
                tracing::warn!(
                    security_event = true,
                    reason = %reason,
                    "rejected unix accept: peer creds"
                );
                drop(stream);
                continue;
            }

            let mut stream = stream;
            if let Some(ref token) = session_token {
                let handshake_result = util::bounded_block_on_cancellable(
                    &rt_handle,
                    &host_semaphore,
                    &cancel_token,
                    validate_handshake(&mut stream, token),
                );
                match handshake_result {
                    None => return Err(ErrorCode::Closed),
                    Some(Ok(())) => break stream,
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
                break stream;
            }
        };

        if count_net_streams(&mut self.resource_table) >= MAX_ACTIVE_STREAMS {
            drop(stream);
            return Err(ErrorCode::Quota);
        }

        let net_stream = NetStream::Unix(Arc::new(tokio::sync::Mutex::new(stream)));
        let res = self
            .resource_table
            .push(net_stream)
            .map_err(|e| ErrorCode::Unknown(format!("resource table: {e}")))?;
        let result: Result<Resource<TcpStream>, ErrorCode> = Ok(Resource::new_own(res.rep()));
        audit_net(self, "astrid:net/host.unix-listener.accept", 0, &result);
        result
    }

    fn poll_accept(
        &mut self,
        _self_: Resource<UnixListener>,
        timeout_ms: u64,
    ) -> Result<Option<Resource<TcpStream>>, ErrorCode> {
        let listener_arc = self.cli_socket_listener.clone().ok_or(ErrorCode::Closed)?;
        let rt_handle = self.runtime_handle.clone();
        let cancel_token = self.cancel_token.clone();
        let session_token = self.session_token.clone();
        let host_semaphore = self.host_semaphore.clone();

        if count_net_streams(&mut self.resource_table) >= MAX_ACTIVE_STREAMS {
            return Ok(None);
        }

        let timeout_ms = timeout_ms.min(60_000);
        let accept_result =
            util::bounded_block_on_cancellable(&rt_handle, &host_semaphore, &cancel_token, async {
                let l = listener_arc.lock().await;
                tokio::time::timeout(Duration::from_millis(timeout_ms), l.accept()).await
            });

        let (stream, _addr) = match accept_result {
            None => return Ok(None),
            Some(Err(_)) => return Ok(None),
            Some(Ok(Err(e))) => return Err(map_io_err(e)),
            Some(Ok(Ok(pair))) => pair,
        };

        #[cfg(unix)]
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
        if let Some(ref token) = session_token {
            let handshake_result = util::bounded_block_on_cancellable(
                &rt_handle,
                &host_semaphore,
                &cancel_token,
                validate_handshake(&mut stream, token),
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
                Some(Ok(())) => {},
            }
        }

        if count_net_streams(&mut self.resource_table) >= MAX_ACTIVE_STREAMS {
            drop(stream);
            return Ok(None);
        }

        let net_stream = NetStream::Unix(Arc::new(tokio::sync::Mutex::new(stream)));
        let res = self
            .resource_table
            .push(net_stream)
            .map_err(|e| ErrorCode::Unknown(format!("resource table: {e}")))?;
        Ok(Some(Resource::new_own(res.rep())))
    }

    fn subscribe_readiness(&mut self, _self_: Resource<UnixListener>) -> Resource<DynPollable> {
        // Readiness wiring for inbound unix accept lands with the stream-
        // halves commit (same pollable infra).
        todo!("UnixListener.subscribe_readiness: pollable wiring pending")
    }

    fn drop(&mut self, rep: Resource<UnixListener>) -> wasmtime::Result<()> {
        let _ = self
            .resource_table
            .delete::<UnixListenerSlot>(Resource::new_own(rep.rep()));
        Ok(())
    }
}
