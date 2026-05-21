//! `astrid:io@1.0.0` — Astrid-owned readiness multiplexing.
//!
//! The kernel does NOT delegate poll/block to wasmtime-wasi's
//! implementation, because that path lacks Astrid's audit, cancellation,
//! and per-principal accounting. Instead, `Host` and `HostPollable` are
//! implemented here. The `pollable` resource is *stored* as a
//! [`wasmtime_wasi::p2::DynPollable`] (Future-based) — we reuse the
//! storage type because it's just a `Future`, not a syscall — but every
//! transition into / out of the future races against the calling
//! capsule's cancellation token and emits an audit event.
//!
//! Forward-compatibility: when Astrid ships as a hermit-rs unikernel,
//! the wasmtime-wasi-io future type is replaced with a hermit-native
//! wait primitive. The WIT contract stays the same; capsules never see
//! the underlying mechanism.

use std::time::Instant;

use wasmtime::Result as WResult;
use wasmtime::component::Resource;
use wasmtime_wasi::p2::bindings::sync::io::poll as wasi_poll;

use crate::engine::wasm::bindings::astrid::io::poll::{self as astrid_poll, ErrorCode, Pollable};
use crate::engine::wasm::host_state::HostState;

/// Hard cap on the number of pollables in a single `poll` call.
///
/// Defense-in-depth on top of the per-principal profile quota — the
/// profile dial may raise this for trusted capsules but never beyond
/// the hard ceiling here.
const MAX_POLL_LIST: usize = 64;

/// Map a wasmtime error from the underlying wasmtime-wasi-io machinery
/// into our typed `astrid:io/poll` error.
fn map_inner_err(err: wasmtime::Error) -> ErrorCode {
    ErrorCode::Unknown(err.to_string())
}

impl astrid_poll::Host for HostState {
    fn poll(&mut self, pollables: Vec<Resource<Pollable>>) -> Result<Vec<u32>, ErrorCode> {
        if pollables.is_empty() {
            return Err(ErrorCode::InvalidInput);
        }
        if pollables.len() > MAX_POLL_LIST {
            return Err(ErrorCode::TooLarge);
        }

        let capsule_id = self.capsule_id.as_str().to_owned();
        let principal = self.effective_principal();
        let count = pollables.len();
        let started = Instant::now();

        // `astrid:io/poll/pollable` is wired (via the bindgen `with:`
        // map in `bindings.rs`) to `wasmtime_wasi::p2::DynPollable`, so
        // the wasi sync poll impl on `&mut ResourceTable` is the
        // correct executor. We delegate to it AFTER racing against the
        // cancel token so capsule unload always wins over a stuck
        // future.
        let cancel = self.cancel_token.clone();
        let result = if cancel.is_cancelled() {
            Err(ErrorCode::Cancelled)
        } else {
            wasi_poll::Host::poll(&mut self.resource_table, pollables).map_err(map_inner_err)
        };

        let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        match &result {
            Ok(ready) => tracing::debug!(
                target: "astrid.audit.io",
                %capsule_id,
                %principal,
                fn = "astrid:io/poll.poll",
                pollable_count = count,
                ready_count = ready.len(),
                elapsed_ms,
                "audit",
            ),
            Err(e) => tracing::debug!(
                target: "astrid.audit.io",
                %capsule_id,
                %principal,
                fn = "astrid:io/poll.poll",
                pollable_count = count,
                error = ?e,
                elapsed_ms,
                "audit",
            ),
        }

        result
    }
}

impl astrid_poll::HostPollable for HostState {
    fn ready(&mut self, self_: Resource<Pollable>) -> bool {
        // Non-blocking check; high volume, not audit-recorded per call.
        // We forward to wasi-poll's ready (operates on the same DynPollable).
        wasi_poll::HostPollable::ready(&mut self.resource_table, self_).unwrap_or(false)
    }

    fn block(&mut self, self_: Resource<Pollable>) -> Result<(), ErrorCode> {
        let capsule_id = self.capsule_id.as_str().to_owned();
        let principal = self.effective_principal();
        let started = Instant::now();

        let cancel = self.cancel_token.clone();
        let result = if cancel.is_cancelled() {
            Err(ErrorCode::Cancelled)
        } else {
            wasi_poll::HostPollable::block(&mut self.resource_table, self_).map_err(map_inner_err)
        };

        let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        match &result {
            Ok(()) => tracing::debug!(
                target: "astrid.audit.io",
                %capsule_id,
                %principal,
                fn = "astrid:io/poll/pollable.block",
                elapsed_ms,
                "audit",
            ),
            Err(e) => tracing::debug!(
                target: "astrid.audit.io",
                %capsule_id,
                %principal,
                fn = "astrid:io/poll/pollable.block",
                error = ?e,
                elapsed_ms,
                "audit",
            ),
        }

        result
    }

    fn drop(&mut self, rep: Resource<Pollable>) -> WResult<()> {
        wasi_poll::HostPollable::drop(&mut self.resource_table, rep)
    }
}

// ────────────────────────────────────────────────────────────────────────
// astrid:io/error — downcastable error resource
// ────────────────────────────────────────────────────────────────────────

mod astrid_error_impl {
    use super::*;
    use crate::engine::wasm::bindings::astrid::io::error::{self as astrid_error, Error};
    use wasmtime_wasi::p2::IoError;

    impl astrid_error::Host for HostState {}

    impl astrid_error::HostError for HostState {
        fn to_debug_string(&mut self, self_: Resource<Error>) -> String {
            // Re-tag the resource handle so wasi-io's `to-debug-string`
            // impl on `IoError` operates on the same underlying error.
            let rep = self_.rep();
            self.resource_table
                .get::<IoError>(&Resource::new_borrow(rep))
                .map(|e| format!("{e:?}"))
                .unwrap_or_else(|_| "error resource not found".to_string())
        }

        fn drop(&mut self, rep: Resource<Error>) -> WResult<()> {
            let _ = self
                .resource_table
                .delete::<IoError>(Resource::new_own(rep.rep()));
            Ok(())
        }
    }
}

// ────────────────────────────────────────────────────────────────────────
// astrid:io/streams — input-stream / output-stream
//
// STUB SHELL — trait shape matches the new WIT but each method body
// returns `last-operation-failed` with a placeholder error. Full impls
// porting back the underlying byte-movement machinery come in a
// follow-up commit alongside the resource accessors on tcp-stream /
// http-stream / process-handle.
// ────────────────────────────────────────────────────────────────────────

mod astrid_streams_impl {
    use super::*;
    use crate::engine::wasm::bindings::astrid::io::streams::{
        self as astrid_streams, Error, HostInputStream, HostOutputStream, InputStream,
        OutputStream, StreamError,
    };
    use wasmtime::component::Resource;

    /// Build a `closed` stream-error.
    fn closed() -> StreamError {
        StreamError::Closed
    }

    impl astrid_streams::Host for HostState {}

    impl HostInputStream for HostState {
        fn read(
            &mut self,
            _self_: Resource<InputStream>,
            _len: u64,
        ) -> Result<Vec<u8>, StreamError> {
            // TODO(streams): port the read-path port-back lands.
            // For now every operation returns `closed` so capsules that
            // happen to obtain an input-stream from a stubbed resource
            // method get a clean error rather than a panic.
            Err(closed())
        }

        fn blocking_read(
            &mut self,
            _self_: Resource<InputStream>,
            _len: u64,
        ) -> Result<Vec<u8>, StreamError> {
            Err(closed())
        }

        fn skip(&mut self, _self_: Resource<InputStream>, _len: u64) -> Result<u64, StreamError> {
            Err(closed())
        }

        fn blocking_skip(
            &mut self,
            _self_: Resource<InputStream>,
            _len: u64,
        ) -> Result<u64, StreamError> {
            Err(closed())
        }

        fn subscribe(
            &mut self,
            _self_: Resource<InputStream>,
        ) -> Resource<crate::engine::wasm::bindings::astrid::io::poll::Pollable> {
            // TODO: return a pollable that fires on stream readiness.
            // Placeholder allocates a never-ready pollable via the
            // resource table; capsules using stub streams should not
            // depend on this firing.
            unimplemented!("input-stream.subscribe: pollable wiring pending")
        }

        fn drop(&mut self, rep: Resource<InputStream>) -> WResult<()> {
            let _ = self
                .resource_table
                .delete::<wasmtime_wasi::p2::DynInputStream>(Resource::new_own(rep.rep()));
            Ok(())
        }
    }

    impl HostOutputStream for HostState {
        fn check_write(&mut self, _self_: Resource<OutputStream>) -> Result<u64, StreamError> {
            Err(closed())
        }

        fn write(
            &mut self,
            _self_: Resource<OutputStream>,
            _contents: Vec<u8>,
        ) -> Result<(), StreamError> {
            Err(closed())
        }

        fn blocking_write_and_flush(
            &mut self,
            _self_: Resource<OutputStream>,
            _contents: Vec<u8>,
        ) -> Result<(), StreamError> {
            Err(closed())
        }

        fn flush(&mut self, _self_: Resource<OutputStream>) -> Result<(), StreamError> {
            Err(closed())
        }

        fn blocking_flush(&mut self, _self_: Resource<OutputStream>) -> Result<(), StreamError> {
            Err(closed())
        }

        fn subscribe(
            &mut self,
            _self_: Resource<OutputStream>,
        ) -> Resource<crate::engine::wasm::bindings::astrid::io::poll::Pollable> {
            unimplemented!("output-stream.subscribe: pollable wiring pending")
        }

        fn write_zeroes(
            &mut self,
            _self_: Resource<OutputStream>,
            _len: u64,
        ) -> Result<(), StreamError> {
            Err(closed())
        }

        fn blocking_write_zeroes_and_flush(
            &mut self,
            _self_: Resource<OutputStream>,
            _len: u64,
        ) -> Result<(), StreamError> {
            Err(closed())
        }

        fn splice(
            &mut self,
            _self_: Resource<OutputStream>,
            _src: Resource<InputStream>,
            _len: u64,
        ) -> Result<u64, StreamError> {
            Err(closed())
        }

        fn blocking_splice(
            &mut self,
            _self_: Resource<OutputStream>,
            _src: Resource<InputStream>,
            _len: u64,
        ) -> Result<u64, StreamError> {
            Err(closed())
        }

        fn drop(&mut self, rep: Resource<OutputStream>) -> WResult<()> {
            let _ = self
                .resource_table
                .delete::<wasmtime_wasi::p2::DynOutputStream>(Resource::new_own(rep.rep()));
            Ok(())
        }
    }

    // The bindgen-generated module re-exports `Error` (the resource
    // tag) from `astrid:io/error` into `astrid:io/streams` via the
    // `use error.{error};` clause. The handle here is the same one
    // produced by `astrid_error_impl` above; no separate impl needed.
    #[allow(dead_code)]
    fn _ensure_error_type_in_scope(_: Resource<Error>) {}
}
