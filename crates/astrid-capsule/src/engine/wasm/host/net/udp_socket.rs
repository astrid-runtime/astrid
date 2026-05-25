//! `HostUdpSocket` impl — stubbed pending UDP port-back.

use wasmtime::component::Resource;
use wasmtime_wasi::p2::DynPollable;

use super::{HostState, UdpSocketSlot};
use crate::engine::wasm::bindings::astrid::net::host::{
    ErrorCode, HostUdpSocket, UdpDatagram, UdpSocket,
};

impl HostUdpSocket for HostState {
    fn send_to(
        &mut self,
        _self_: Resource<UdpSocket>,
        _data: Vec<u8>,
        _peer_host: String,
        _peer_port: u16,
    ) -> Result<u32, ErrorCode> {
        Err(ErrorCode::CapabilityDenied)
    }

    fn recv_from(
        &mut self,
        _self_: Resource<UdpSocket>,
        _max_bytes: u32,
    ) -> Result<Option<UdpDatagram>, ErrorCode> {
        Err(ErrorCode::CapabilityDenied)
    }

    fn connect(
        &mut self,
        _self_: Resource<UdpSocket>,
        _peer_host: String,
        _peer_port: u16,
    ) -> Result<(), ErrorCode> {
        Err(ErrorCode::CapabilityDenied)
    }

    fn disconnect(&mut self, _self_: Resource<UdpSocket>) -> Result<(), ErrorCode> {
        Err(ErrorCode::CapabilityDenied)
    }

    fn send(&mut self, _self_: Resource<UdpSocket>, _data: Vec<u8>) -> Result<u32, ErrorCode> {
        Err(ErrorCode::CapabilityDenied)
    }

    fn recv(
        &mut self,
        _self_: Resource<UdpSocket>,
        _max_bytes: u32,
    ) -> Result<Option<Vec<u8>>, ErrorCode> {
        Err(ErrorCode::CapabilityDenied)
    }

    fn peer_addr(&mut self, _self_: Resource<UdpSocket>) -> Result<Option<String>, ErrorCode> {
        Err(ErrorCode::CapabilityDenied)
    }

    fn set_read_timeout(
        &mut self,
        _self_: Resource<UdpSocket>,
        _timeout_ms: Option<u64>,
    ) -> Result<(), ErrorCode> {
        Err(ErrorCode::CapabilityDenied)
    }

    fn local_addr(&mut self, _self_: Resource<UdpSocket>) -> Result<String, ErrorCode> {
        Err(ErrorCode::CapabilityDenied)
    }

    fn subscribe_readable(&mut self, _self_: Resource<UdpSocket>) -> Resource<DynPollable> {
        super::super::stubs::always_ready_pollable(&mut self.resource_table)
    }

    fn drop(&mut self, rep: Resource<UdpSocket>) -> wasmtime::Result<()> {
        let _ = self
            .resource_table
            .delete::<UdpSocketSlot>(Resource::new_own(rep.rep()));
        Ok(())
    }
}
