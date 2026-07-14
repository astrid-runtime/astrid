//! `HostTcpListener` impl — inbound TCP server hosting.
//!
//! The listener is created and capability-gated in
//! [`super::Host::bind_tcp`]; the `Resource<TcpListener>` is a token over a
//! [`TcpListenerSlot`] holding the live `tokio` listener. `accept` /
//! `poll_accept` produce `TcpStream` resources that reuse the SAME
//! [`NetStream::Tcp`] representation as outbound `connect-tcp` streams, so
//! every existing read / write / peek / timeout host fn works on accepted
//! connections with no extra wiring.

use std::sync::Arc;

use wasmtime::component::Resource;
use wasmtime_wasi::p2::DynPollable;

use super::{HostState, MAX_ACTIVE_STREAMS, TcpListenerSlot, map_io_err};
use crate::engine::wasm::bindings::astrid::net::host::{
    ErrorCode, HostTcpListener, TcpListener, TcpStream,
};
use crate::engine::wasm::host::util;
use crate::engine::wasm::host_state::{NetStream, TcpStreamSlot};

impl HostState {
    /// Clone the `Arc<tokio::net::TcpListener>` out of the resource slot,
    /// releasing the table borrow before any blocking accept.
    fn tcp_listener_arc(
        &self,
        rep: u32,
    ) -> Result<Arc<tokio::net::TcpListener>, ErrorCode> {
        let slot = self
            .resource_table
            .get::<TcpListenerSlot>(&Resource::new_borrow(rep))
            .map_err(|_| ErrorCode::InvalidHandle)?;
        Ok(Arc::clone(&slot.listener))
    }

    /// Register an accepted stream as a `NetStream::Tcp` resource, bumping the
    /// per-capsule active-stream counter. Shared by `accept` / `poll_accept`.
    fn register_accepted(
        &mut self,
        stream: tokio::net::TcpStream,
    ) -> Result<Resource<TcpStream>, ErrorCode> {
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
        Ok(Resource::new_own(res.rep()))
    }
}

impl HostTcpListener for HostState {
    fn accept(&mut self, self_: Resource<TcpListener>) -> Result<Resource<TcpStream>, ErrorCode> {
        let listener = self.tcp_listener_arc(self_.rep())?;
        if self.net_stream_count >= MAX_ACTIVE_STREAMS {
            return Err(ErrorCode::Quota);
        }
        // Mark cooperative progress so a bound accept-loop is not mistaken for
        // a no-yield spinner and epoch-trapped (parity with `ipc::recv`).
        self.recv_yielded = true;

        let rt = self.runtime_handle.clone();
        let sem = self.blocking_semaphore.clone();
        let tok = self.effective_cancel_token();
        let accepted = util::bounded_block_on_cancellable(&rt, &sem, &tok, async move {
            listener.accept().await
        });
        let stream = match accepted {
            Some(Ok((s, _addr))) => s,
            Some(Err(e)) => return Err(map_io_err(e)),
            None => return Err(ErrorCode::Closed), // cancelled (capsule unload)
        };
        self.register_accepted(stream)
    }

    fn poll_accept(
        &mut self,
        self_: Resource<TcpListener>,
        timeout_ms: u64,
    ) -> Result<Option<Resource<TcpStream>>, ErrorCode> {
        let listener = self.tcp_listener_arc(self_.rep())?;
        if self.net_stream_count >= MAX_ACTIVE_STREAMS {
            return Err(ErrorCode::Quota);
        }
        self.recv_yielded = true;

        let rt = self.runtime_handle.clone();
        let sem = self.blocking_semaphore.clone();
        let tok = self.effective_cancel_token();
        let timeout = std::time::Duration::from_millis(timeout_ms);
        let accepted = util::bounded_block_on_cancellable(&rt, &sem, &tok, async move {
            tokio::time::timeout(timeout, listener.accept()).await
        });
        match accepted {
            Some(Ok(Ok((s, _addr)))) => Ok(Some(self.register_accepted(s)?)),
            Some(Ok(Err(e))) => Err(map_io_err(e)),
            Some(Err(_elapsed)) => Ok(None), // no connection within the window
            None => Err(ErrorCode::Closed),  // cancelled (capsule unload)
        }
    }

    fn local_addr(&mut self, self_: Resource<TcpListener>) -> Result<String, ErrorCode> {
        let listener = self.tcp_listener_arc(self_.rep())?;
        listener
            .local_addr()
            .map(|a| a.to_string())
            .map_err(map_io_err)
    }

    fn subscribe_readiness(&mut self, _self_: Resource<TcpListener>) -> Resource<DynPollable> {
        // POC: always-ready. Guests use `poll_accept(timeout)` for bounded
        // waits; a real readiness pollable over the listener fd is a follow-up.
        super::super::stubs::always_ready_pollable(&mut self.resource_table)
    }

    fn drop(&mut self, rep: Resource<TcpListener>) -> wasmtime::Result<()> {
        // Deleting the slot drops the Arc<tokio listener> → closes the socket.
        let _ = self
            .resource_table
            .delete::<TcpListenerSlot>(Resource::new_own(rep.rep()));
        Ok(())
    }
}
