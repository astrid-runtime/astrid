//! `astrid:net@1.0.0` host implementation.
//!
//! STUB SHELL — trait shape matches the new WIT but all methods return
//! `todo!()`. The previous 1100+-line implementation (Unix-listener
//! handshake, outbound TCP, length-prefixed framing) ports back in a
//! follow-up commit alongside the four new resource types
//! (UnixListener, TcpListener, TcpStream, UdpSocket).

use wasmtime::component::Resource;
use wasmtime_wasi::p2::DynPollable;

use crate::engine::wasm::bindings::astrid::net::host::{
    self as net, ErrorCode, HostTcpListener, HostTcpStream, HostUdpSocket, HostUnixListener,
    NetReadStatus, ShutdownHow, TcpListener, TcpStream, UdpDatagram, UdpSocket, UnixListener,
};
use crate::engine::wasm::host_state::HostState;

// The previous submodules `handshake.rs` and `stream.rs` are retained
// on disk but their contents reference the old bindings shape — they
// are excluded from the module tree until the full port lands.
//
// mod handshake;
// mod stream;

impl net::Host for HostState {
    fn bind_unix(&mut self) -> Result<Resource<UnixListener>, ErrorCode> {
        todo!("net.bind_unix: UnixListener resource integration pending")
    }

    fn bind_tcp(&mut self, _host: String, _port: u16) -> Result<Resource<TcpListener>, ErrorCode> {
        todo!("net.bind_tcp: TcpListener resource integration pending")
    }

    fn connect_tcp(&mut self, _host: String, _port: u16) -> Result<Resource<TcpStream>, ErrorCode> {
        todo!("net.connect_tcp: outbound TCP port pending")
    }

    fn udp_bind(&mut self, _host: String, _port: u16) -> Result<Resource<UdpSocket>, ErrorCode> {
        todo!("net.udp_bind: UDP socket resource integration pending")
    }

    fn lookup_host(&mut self, _host: String) -> Result<Vec<String>, ErrorCode> {
        todo!("net.lookup_host: airlocked DNS impl pending")
    }
}

impl HostUnixListener for HostState {
    fn accept(&mut self, _self_: Resource<UnixListener>) -> Result<Resource<TcpStream>, ErrorCode> {
        todo!("UnixListener.accept: handshake port pending")
    }

    fn poll_accept(
        &mut self,
        _self_: Resource<UnixListener>,
        _timeout_ms: u64,
    ) -> Result<Option<Resource<TcpStream>>, ErrorCode> {
        todo!("UnixListener.poll_accept: handshake port pending")
    }

    fn subscribe_readiness(&mut self, _self_: Resource<UnixListener>) -> Resource<DynPollable> {
        todo!("UnixListener.subscribe_readiness: pollable wiring pending")
    }

    fn drop(&mut self, _rep: Resource<UnixListener>) -> wasmtime::Result<()> {
        Ok(())
    }
}

impl HostTcpListener for HostState {
    fn accept(&mut self, _self_: Resource<TcpListener>) -> Result<Resource<TcpStream>, ErrorCode> {
        todo!("TcpListener.accept: inbound TCP port pending")
    }

    fn poll_accept(
        &mut self,
        _self_: Resource<TcpListener>,
        _timeout_ms: u64,
    ) -> Result<Option<Resource<TcpStream>>, ErrorCode> {
        todo!("TcpListener.poll_accept: inbound TCP port pending")
    }

    fn local_addr(&mut self, _self_: Resource<TcpListener>) -> Result<String, ErrorCode> {
        todo!("TcpListener.local_addr: getsockname port pending")
    }

    fn subscribe_readiness(&mut self, _self_: Resource<TcpListener>) -> Resource<DynPollable> {
        todo!("TcpListener.subscribe_readiness: pollable wiring pending")
    }

    fn drop(&mut self, _rep: Resource<TcpListener>) -> wasmtime::Result<()> {
        Ok(())
    }
}

impl HostTcpStream for HostState {
    fn read(&mut self, _self_: Resource<TcpStream>) -> Result<NetReadStatus, ErrorCode> {
        todo!("TcpStream.read: length-prefixed read port pending")
    }
    fn write(&mut self, _self_: Resource<TcpStream>, _data: Vec<u8>) -> Result<(), ErrorCode> {
        todo!("TcpStream.write: length-prefixed write port pending")
    }
    fn read_bytes(
        &mut self,
        _self_: Resource<TcpStream>,
        _max_bytes: u32,
    ) -> Result<Vec<u8>, ErrorCode> {
        todo!("TcpStream.read_bytes: raw byte-stream port pending")
    }
    fn write_bytes(
        &mut self,
        _self_: Resource<TcpStream>,
        _data: Vec<u8>,
    ) -> Result<u32, ErrorCode> {
        todo!("TcpStream.write_bytes: raw byte-stream port pending")
    }
    fn peek(&mut self, _self_: Resource<TcpStream>, _max_bytes: u32) -> Result<Vec<u8>, ErrorCode> {
        todo!("TcpStream.peek: MSG_PEEK port pending")
    }
    fn shutdown(
        &mut self,
        _self_: Resource<TcpStream>,
        _how: ShutdownHow,
    ) -> Result<(), ErrorCode> {
        todo!("TcpStream.shutdown: half-close port pending")
    }
    fn peer_addr(&mut self, _self_: Resource<TcpStream>) -> Result<String, ErrorCode> {
        todo!("TcpStream.peer_addr port pending")
    }
    fn local_addr(&mut self, _self_: Resource<TcpStream>) -> Result<String, ErrorCode> {
        todo!("TcpStream.local_addr port pending")
    }
    fn set_nodelay(
        &mut self,
        _self_: Resource<TcpStream>,
        _nodelay: bool,
    ) -> Result<(), ErrorCode> {
        todo!("TcpStream.set_nodelay port pending")
    }
    fn nodelay(&mut self, _self_: Resource<TcpStream>) -> Result<bool, ErrorCode> {
        todo!("TcpStream.nodelay port pending")
    }
    fn set_read_timeout(
        &mut self,
        _self_: Resource<TcpStream>,
        _timeout_ms: Option<u64>,
    ) -> Result<(), ErrorCode> {
        todo!("TcpStream.set_read_timeout port pending")
    }
    fn read_timeout(&mut self, _self_: Resource<TcpStream>) -> Result<Option<u64>, ErrorCode> {
        todo!("TcpStream.read_timeout port pending")
    }
    fn set_write_timeout(
        &mut self,
        _self_: Resource<TcpStream>,
        _timeout_ms: Option<u64>,
    ) -> Result<(), ErrorCode> {
        todo!("TcpStream.set_write_timeout port pending")
    }
    fn write_timeout(&mut self, _self_: Resource<TcpStream>) -> Result<Option<u64>, ErrorCode> {
        todo!("TcpStream.write_timeout port pending")
    }
    fn set_hop_limit(&mut self, _self_: Resource<TcpStream>, _hops: u32) -> Result<(), ErrorCode> {
        todo!("TcpStream.set_hop_limit port pending")
    }
    fn hop_limit(&mut self, _self_: Resource<TcpStream>) -> Result<u32, ErrorCode> {
        todo!("TcpStream.hop_limit port pending")
    }
    fn set_keepalive(
        &mut self,
        _self_: Resource<TcpStream>,
        _keepalive_secs: Option<u64>,
    ) -> Result<(), ErrorCode> {
        todo!("TcpStream.set_keepalive port pending")
    }
    fn keepalive(&mut self, _self_: Resource<TcpStream>) -> Result<Option<u64>, ErrorCode> {
        todo!("TcpStream.keepalive port pending")
    }
    fn set_linger(
        &mut self,
        _self_: Resource<TcpStream>,
        _linger_ms: Option<u64>,
    ) -> Result<(), ErrorCode> {
        todo!("TcpStream.set_linger port pending")
    }
    fn linger(&mut self, _self_: Resource<TcpStream>) -> Result<Option<u64>, ErrorCode> {
        todo!("TcpStream.linger port pending")
    }
    fn set_reuseaddr(
        &mut self,
        _self_: Resource<TcpStream>,
        _reuse: bool,
    ) -> Result<(), ErrorCode> {
        todo!("TcpStream.set_reuseaddr port pending")
    }
    fn reuseaddr(&mut self, _self_: Resource<TcpStream>) -> Result<bool, ErrorCode> {
        todo!("TcpStream.reuseaddr port pending")
    }
    fn subscribe_readable(&mut self, _self_: Resource<TcpStream>) -> Resource<DynPollable> {
        todo!("TcpStream.subscribe_readable pending")
    }
    fn drop(&mut self, _rep: Resource<TcpStream>) -> wasmtime::Result<()> {
        Ok(())
    }
}

impl HostUdpSocket for HostState {
    fn send_to(
        &mut self,
        _self_: Resource<UdpSocket>,
        _data: Vec<u8>,
        _peer_host: String,
        _peer_port: u16,
    ) -> Result<u32, ErrorCode> {
        todo!("UdpSocket.send_to port pending")
    }
    fn recv_from(
        &mut self,
        _self_: Resource<UdpSocket>,
        _max_bytes: u32,
    ) -> Result<Option<UdpDatagram>, ErrorCode> {
        todo!("UdpSocket.recv_from port pending")
    }
    fn connect(
        &mut self,
        _self_: Resource<UdpSocket>,
        _peer_host: String,
        _peer_port: u16,
    ) -> Result<(), ErrorCode> {
        todo!("UdpSocket.connect port pending")
    }
    fn disconnect(&mut self, _self_: Resource<UdpSocket>) -> Result<(), ErrorCode> {
        todo!("UdpSocket.disconnect port pending")
    }
    fn send(&mut self, _self_: Resource<UdpSocket>, _data: Vec<u8>) -> Result<u32, ErrorCode> {
        todo!("UdpSocket.send port pending")
    }
    fn recv(
        &mut self,
        _self_: Resource<UdpSocket>,
        _max_bytes: u32,
    ) -> Result<Option<Vec<u8>>, ErrorCode> {
        todo!("UdpSocket.recv port pending")
    }
    fn peer_addr(&mut self, _self_: Resource<UdpSocket>) -> Result<Option<String>, ErrorCode> {
        todo!("UdpSocket.peer_addr port pending")
    }
    fn set_read_timeout(
        &mut self,
        _self_: Resource<UdpSocket>,
        _timeout_ms: Option<u64>,
    ) -> Result<(), ErrorCode> {
        todo!("UdpSocket.set_read_timeout port pending")
    }
    fn local_addr(&mut self, _self_: Resource<UdpSocket>) -> Result<String, ErrorCode> {
        todo!("UdpSocket.local_addr port pending")
    }
    fn subscribe_readable(&mut self, _self_: Resource<UdpSocket>) -> Resource<DynPollable> {
        todo!("UdpSocket.subscribe_readable port pending")
    }
    fn drop(&mut self, _rep: Resource<UdpSocket>) -> wasmtime::Result<()> {
        Ok(())
    }
}
