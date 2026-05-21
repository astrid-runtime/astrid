//! Host function implementations for the wasmtime Component Model.
//!
//! Each submodule implements the corresponding `Host` trait from the
//! WIT-generated bindings on `HostState`. The trait implementations
//! are automatically wired to the wasmtime linker via
//! `Capsule::add_to_linker()`.

/// Capsule-level approval requests.
pub(crate) mod approval;
/// Elicit lifecycle API (install/upgrade user input collection).
pub(crate) mod elicit;
/// File system operations for plugins.
pub(crate) mod fs;
/// HTTP network executions for plugins.
pub mod http;
/// Identity operations (resolve, link, create user).
pub(crate) mod identity;
/// Astrid-owned readiness multiplexing (`astrid:io/poll@1.0.0`).
///
/// Replaces the wasi:io/poll dependency. Every readiness operation is
/// audited, principal-scoped, races against the capsule cancellation
/// token, and is bounded by the per-principal quota profile.
pub(crate) mod io;
/// Inter-Process Communication bus.
pub(crate) mod ipc;
/// Key-Value persistent storage primitives.
pub(crate) mod kv;
pub(crate) mod net;
/// Process spawning and sandboxing.
pub mod process;
/// System configuration primitives.
pub mod sys;
/// Uplink communications with host capabilities.
pub(crate) mod uplink;
/// Utility functions for WASM host implementations.
pub(crate) mod util;

// Host registration is handled by [`Kernel::add_to_linker`] in
// `engine/wasm/mod.rs`, which wires every per-domain `Host` /
// `HostResource` trait impl on `HostState` into the wasmtime `Linker`.
//
// The legacy `astrid:capsule/types` interface was split into per-domain
// type modules when the WIT was sharded (see `wit/host/`), so there is
// no longer a single empty `types::Host` trait to implement.

// `lifecycle` is the package providing `capsule-result` used by the
// guest's `astrid-hook-trigger` export. It defines only types — the
// generated `Host` trait is empty — but bindgen still emits the trait,
// so the kernel needs to assert it on `HostState` for the linker
// scaffolding to type-check.
impl crate::engine::wasm::bindings::astrid::guest::lifecycle::Host
    for crate::engine::wasm::host_state::HostState
{
}

// `astrid:io/poll` is implemented in `host/io.rs` — kernel-owned with
// audit + cancel-token + per-principal accounting. The wasi:io/poll
// forwarder used during the initial scaffolding pass has been removed:
// no wasi:* interface is exposed to capsules.
