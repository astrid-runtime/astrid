//! Component Model bindings for the kernel's host ABI.
//!
//! Generated from the per-domain WIT files in `wit/host/` (the
//! `unicity-astrid/wit` submodule). `build.rs` stages those files into
//! `wit-staging/deps/astrid-<pkg>/`; a single `bindgen!` invocation then
//! emits one Rust module per package under a synthetic kernel world that
//! imports every host package.
//!
//! This gives the kernel a deduplicated set of generated types plus one
//! `Kernel::add_to_linker_imports*` family of functions to wire every
//! host trait impl on `HostState` into the wasmtime linker.
//!
//! Guest exports (`astrid-hook-trigger`, `run`, `astrid-install`,
//! `astrid-upgrade`) are looked up by name via `instance.get_typed_func`
//! at invocation time, so a capsule only sees the kernel-side bindings
//! for the host packages it imports — no toolchain-stubbed exports show
//! up at runtime.
//!
//! Note: every package is pinned at `@1.0.0`. When a new frozen version
//! ships (e.g. `host/ipc@1.1.0.wit`), add it here as an additional import
//! AND register a second `add_to_linker` call — the wasmtime Component
//! Model linker enforces exact `(package, version)` matches, so multiple
//! versions must be registered explicitly to allow old and new capsules
//! to coexist.

wasmtime::component::bindgen!({
    inline: "
        package kernel:host;

        /// Synthetic world that imports every frozen host package plus the
        /// `astrid:guest/lifecycle` interface (for the `capsule-result`
        /// type used by `astrid-hook-trigger`). One world keeps the
        /// generated module deduplicated.
        ///
        /// `wasi:io/poll` is reachable transitively through the host
        /// packages (ipc/net/http/process all `use` its `pollable`
        /// type). The `with:` map below points the generated `pollable`
        /// type at the wasmtime-wasi crate's `DynPollable` so the
        /// kernel does NOT re-generate the poll Host trait — wasi:io
        /// support is installed separately via
        /// `wasmtime_wasi::p2::add_to_linker_sync` in
        /// `engine/wasm/mod.rs`.
        world kernel {
            import astrid:fs/host@1.0.0;
            import astrid:ipc/host@1.0.0;
            import astrid:kv/host@1.0.0;
            import astrid:net/host@1.0.0;
            import astrid:http/host@1.0.0;
            import astrid:sys/host@1.0.0;
            import astrid:process/host@1.0.0;
            import astrid:uplink/host@1.0.0;
            import astrid:elicit/host@1.0.0;
            import astrid:approval/host@1.0.0;
            import astrid:identity/host@1.0.0;
            import astrid:guest/lifecycle@1.0.0;
        }
    ",
    path: "../../crates/astrid-capsule/wit-staging",
    // `wasi:io/poll` is reused from the wasmtime-wasi crate. The kernel
    // installs the wasi:io implementation on the linker via
    // `wasmtime_wasi::p2::add_to_linker_sync` in `engine/wasm/mod.rs`;
    // pointing the bindgen `with:` map at the wasmtime-wasi module
    // re-uses its generated types AND its Host trait impls (so the
    // kernel doesn't need to re-implement them on `HostState`).
    with: {
        "wasi:io/poll@0.2.0": wasmtime_wasi::p2::bindings::sync::io::poll,
    },
});
