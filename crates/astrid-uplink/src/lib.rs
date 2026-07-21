//! Shared uplink client library.
//!
//! The Astrid kernel exposes a Unix-domain socket protected by a
//! 256-bit token at `~/.astrid/run/system.token`. Anything with
//! filesystem-level read access to that token can authenticate to the
//! daemon and publish/subscribe IPC messages. Today there are two
//! uplinks:
//!
//! * **CLI** (`astrid` binary) — long-lived interactive operator
//!   sessions plus short-lived admin verbs.
//! * **HTTP gateway** (`astrid-gateway`) — fronts the same admin IPC
//!   surface for browser dashboards behind ed25519-signed bearer
//!   tokens; resolves the HTTP principal and stamps it on every
//!   outbound message.
//!
//! Both consumers share the framing, handshake, and admin
//! request/response correlation logic that lives in this crate.
//! `SocketClient` is the transport (length-prefixed JSON, handshake,
//! frame readers). `AdminClient` wraps it with the
//! `astrid.v1.admin.<suffix>` → `astrid.v1.admin.response.<suffix>`
//! request/response pattern.
//!
//! Trust shape: every consumer passes the caller `PrincipalId`
//! explicitly. There is no global "active agent" lookup in this crate
//! — the CLI resolves its operator context, the gateway resolves the
//! verified bearer principal, and both stamp `IpcMessage.principal`
//! before calling [`SocketClient::send_message`].

pub mod admin_client;
pub mod kernel_client;
pub mod socket_client;

pub use admin_client::{AdminClient, into_result, request_topic, response_topic, topic_suffix};
pub use kernel_client::{KernelClient, KernelClientError, TimeoutKind};
pub use socket_client::{
    SocketClient, daemon_generation_path, proxy_socket_path, readiness_path, token_path,
};
