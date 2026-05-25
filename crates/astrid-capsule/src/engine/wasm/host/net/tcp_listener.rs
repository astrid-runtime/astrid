//! `HostTcpListener` impl — inbound TCP server hosting.
//!
//! STUB SHELL — the bindings type exists in the WIT and the trait must
//! be implemented for the kernel to link. Every method returns
//! `CapabilityDenied` so capsules importing `bind-tcp` fail closed
//! rather than panic. Real impl lands alongside UDP in a follow-up.

use wasmtime::component::Resource;
use wasmtime_wasi::p2::DynPollable;

use super::{HostState, TcpListenerSlot};
use crate::engine::wasm::bindings::astrid::net::host::{
    ErrorCode, HostTcpListener, TcpListener, TcpStream,
};

impl HostTcpListener for HostState {
    fn accept(&mut self, _self_: Resource<TcpListener>) -> Result<Resource<TcpStream>, ErrorCode> {
        Err(ErrorCode::CapabilityDenied)
    }

    fn poll_accept(
        &mut self,
        _self_: Resource<TcpListener>,
        _timeout_ms: u64,
    ) -> Result<Option<Resource<TcpStream>>, ErrorCode> {
        Err(ErrorCode::CapabilityDenied)
    }

    fn local_addr(&mut self, _self_: Resource<TcpListener>) -> Result<String, ErrorCode> {
        Err(ErrorCode::CapabilityDenied)
    }

    fn subscribe_readiness(&mut self, _self_: Resource<TcpListener>) -> Resource<DynPollable> {
        super::super::stubs::always_ready_pollable(&mut self.resource_table)
    }

    fn drop(&mut self, rep: Resource<TcpListener>) -> wasmtime::Result<()> {
        let _ = self
            .resource_table
            .delete::<TcpListenerSlot>(Resource::new_own(rep.rep()));
        Ok(())
    }
}
