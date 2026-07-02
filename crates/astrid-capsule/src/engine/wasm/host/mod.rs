//! Host function implementations for the wasmtime Component Model.
//!
//! Each submodule implements the corresponding `Host` trait from the
//! WIT-generated bindings on `HostState`. The trait implementations
//! are wired to the wasmtime linker via the shared
//! `engine::wasm::configure_kernel_linker` helper, which calls
//! `bindings::Kernel::add_to_linker` (the synthetic kernel world that
//! imports every host package).

/// Capsule-level approval requests.
pub(crate) mod approval;
/// Synchronous host-audit sink: routes sensitive per-action host calls
/// (fs/net/process) to the kernel's signed, hash-chained audit log.
pub mod audit_sink;
#[cfg(test)]
mod audit_sink_tests;
/// Runtime operator-consent for local-egress (transport-origin gated).
pub(crate) mod consent_egress;
/// Elicit API (interactive user input collection).
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
/// Sentinel `Pollable` / `InputStream` / `OutputStream` impls used as
/// no-panic placeholders by resource methods whose full implementation
/// is still pending (stream-half adapter + per-resource pollable
/// wiring planned in dedicated follow-up commits).
pub(crate) mod stubs;
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
