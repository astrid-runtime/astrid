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

// `wasi:io/poll` is referenced transitively by every host package that
// returns a `pollable` (ipc, net, http, process). The wasmtime-wasi
// crate implements `Host` and `HostPollable` for `ResourceTable`; we
// forward through `HostState.resource_table` so the kernel's
// `Kernel::add_to_linker` (which type-bounds its host getter to a
// single `HasSelf<HostState>`) type-checks without splitting the
// linker into a per-interface getter dance.
//
// These are thin shims: every call delegates to the underlying
// `ResourceTable` impl.
mod wasi_poll_forward {
    use crate::engine::wasm::host_state::HostState;
    use wasmtime::Result;
    use wasmtime::component::Resource;
    use wasmtime_wasi::p2::DynPollable;
    use wasmtime_wasi::p2::bindings::sync::io::poll;

    impl poll::Host for HostState {
        fn poll(&mut self, pollables: Vec<Resource<DynPollable>>) -> Result<Vec<u32>> {
            poll::Host::poll(&mut self.resource_table, pollables)
        }
    }

    impl poll::HostPollable for HostState {
        fn ready(&mut self, pollable: Resource<DynPollable>) -> Result<bool> {
            poll::HostPollable::ready(&mut self.resource_table, pollable)
        }

        fn block(&mut self, pollable: Resource<DynPollable>) -> Result<()> {
            poll::HostPollable::block(&mut self.resource_table, pollable)
        }

        fn drop(&mut self, pollable: Resource<DynPollable>) -> Result<()> {
            poll::HostPollable::drop(&mut self.resource_table, pollable)
        }
    }
}
