//! Component Model bindings for the kernel's host ABI.
//!
//! Generated from the per-domain WIT files in `wit/host/` (the
//! `unicity-astrid/wit` submodule). `build.rs` stages those files into
//! `wit-staging/deps/astrid-<pkg>/`; a single `bindgen!` invocation then
//! emits one Rust module per package under a synthetic kernel world that
//! imports every host package.
//!
//! This gives the kernel a deduplicated set of generated types plus one
//! `Kernel::add_to_linker` family of functions to wire every host trait
//! impl on `HostState` into the wasmtime linker.
//!
//! The host ABI is fully Astrid-owned — there is no `wasi:*` import.
//! Readiness multiplexing is provided by `astrid:io/poll@1.0.0`, whose
//! `Host` and `HostPollable` impls live in `engine/wasm/host/io.rs`.
//! Every readiness operation is audited, principal-scoped, races against
//! the capsule's cancellation token, and is bounded by the per-principal
//! quota profile. No carve-outs for "foundation types."
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

        /// Synthetic world that imports every frozen host package plus
        /// the `astrid:guest/lifecycle` interface (for the
        /// `capsule-result` type used by `astrid-hook-trigger`). One
        /// world keeps the generated module deduplicated.
        ///
        /// `astrid:io/poll` is the Astrid-owned readiness primitive
        /// (replaces the historical wasi:io/poll dependency). Every
        /// readiness operation goes through Astrid host code so it is
        /// audited, principal-scoped, cancellable, and quota-bounded.
        world kernel {
            import astrid:io/error@1.0.0;
            import astrid:io/poll@1.0.0;
            import astrid:io/streams@1.0.0;
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
    path: "wit-staging",
    // The `pollable` resource is stored in the wasmtime resource table
    // as a `DynPollable` (Future-based) — that is the same internal
    // representation wasmtime-wasi already uses, so we re-use the
    // *storage type* for free. What we do NOT re-use is wasmtime-
    // wasi's `Host` trait impl: `astrid::io::poll::Host` and
    // `HostPollable` are implemented by Astrid in
    // `engine/wasm/host/io.rs` with audit + cancel-token + per-
    // principal accounting on every `poll` / `block` call.
    with: {
        // Key format is `<interface-versioned>.<resource>` — see the
        // `lookup_keys` walk in wasmtime-internal-wit-bindgen. Forgetting
        // the dot or substituting a slash makes the key "unused" and the
        // build fails before bindings codegen completes.
        //
        // The wasmtime-wasi-io types are reused for *storage only* — they
        // are Future/Box<dyn ...> wrappers, not syscalls. Our Host trait
        // impls live in `engine/wasm/host/io.rs` and add audit + cancel +
        // per-principal accounting around every operation.
        "astrid:io/poll@1.0.0.pollable": wasmtime_wasi::p2::DynPollable,
        "astrid:io/error@1.0.0.error": wasmtime_wasi::p2::IoError,
        "astrid:io/streams@1.0.0.input-stream": wasmtime_wasi::p2::DynInputStream,
        "astrid:io/streams@1.0.0.output-stream": wasmtime_wasi::p2::DynOutputStream,
    },
    // Lower the `stream-error` variant to wasmtime-wasi-io's runtime
    // `StreamError` enum (Closed / LastOperationFailed(wasmtime::Error)
    // / Trap(wasmtime::Error)) instead of the bindgen-generated enum.
    // This matches what wasi-sync does for its own streams interface
    // and lets the Astrid Host impl delegate to wasi-sync without a
    // structural shuffle on every call. The kernel's audit + cancel
    // envelope wraps the runtime errors transparently.
    //
    // `imports: { default: trappable }` is what makes bindgen actually
    // rewrite the trait signatures to return the trappable type
    // directly (rather than just generating a `convert_stream_error`
    // hook). Without it, host impls still return the bindgen-emitted
    // enum and a separate convert pass runs on each return.
    trappable_error_type: {
        "astrid:io/streams.stream-error" => wasmtime_wasi::p2::StreamError,
    },
    imports: {
        "astrid:io/streams": trappable,
        // `subscription.recv` is the only host import on the orchestration
        // hot path that *blocks* — every chained capsule (react ->
        // prompt-builder -> registry -> openai-compat) waits here for the
        // next stage's response. Making just this one function `async`
        // lets the host impl `.await` the broadcast receiver instead of
        // pinning a tokio worker via `block_in_place`/`block_on`, which is
        // the actual fix for the worker-pool exhaustion in issue #816.
        // Selector is function-level (per wasmtime-wasi-45's own bindgen):
        // `<iface>.[method]<resource>.<func>`, no version, dot-separated.
        // Every other import stays synchronous — non-blocking host fns
        // (publish/subscribe/kv/sys/...) gain nothing from async and the
        // larger migration (net/http/elicit) is a tracked follow-up.
        "astrid:ipc/host.[method]subscription.recv": async,
    },
});
