//! Astrid-owned local uplink transport.
//!
//! The Astrid kernel exposes a host-local endpoint protected by a 256-bit token
//! at `~/.astrid/run/system.token`. The token admits a peer to the handshake;
//! authority requires a signed challenge from a key registered to the claimed
//! principal. Token-only legacy peers are reduced to `anonymous`. Today there
//! are two uplinks:
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
//! Trust shape: every consumer passes the caller `PrincipalId` explicitly.
//! There is no global "active agent" lookup in this crate. The local client
//! proves that identity during the signed handshake, and the native server
//! overwrites authority-bearing message fields with host-verified values. The
//! gateway independently resolves its signed bearer principal.

pub mod admin_client;
pub mod kernel_client;
#[cfg(not(target_family = "wasm"))]
#[doc(hidden)]
pub mod native;
pub mod socket_client;

pub use admin_client::{AdminClient, into_result, request_topic, response_topic, topic_suffix};
pub use kernel_client::{KernelClient, KernelClientError, TimeoutKind};
pub use socket_client::{SocketClient, proxy_socket_path, readiness_path, token_path};
