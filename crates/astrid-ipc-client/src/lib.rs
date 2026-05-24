//! Astrid daemon socket client.
//!
//! Length-prefixed JSON `IpcMessage` I/O over the system Unix
//! socket with bearer-token handshake. Extracted from `astrid-cli`
//! for reuse by the MCP bridge.

pub mod socket_client;
pub use socket_client::SocketClient;
