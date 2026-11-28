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

mod authority;
mod dispatch;
mod disposal;
mod release;
mod splice;
mod transfer;

use std::time::Instant;

use wasmtime::Result as WResult;
use wasmtime::component::Resource;
use wasmtime_wasi::p2::bindings::sync::io::poll as wasi_poll;

use crate::engine::wasm::bindings::astrid::io::poll::{self as astrid_poll, ErrorCode, Pollable};
use crate::engine::wasm::host_state::HostState;

/// Hard cap on the number of pollables in a single `poll` call.
///
/// Matches the WIT contract (`astrid:io/poll@1.0.0`). The cap is sized
/// so a capsule at its full IPC subscription quota (128) plus its TCP /
/// UDP / HTTP / process stream pollables can wait on them all in one
/// call. Defense-in-depth on top of the per-principal profile quota —
/// the profile dial may lower the effective cap for less-trusted
/// capsules but never raise it above this hard ceiling.
const MAX_POLL_LIST: usize = 256;

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
        let cancel = self.effective_cancel_token();
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

        let cancel = self.effective_cancel_token();
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
        release::from_table(&mut self.resource_table, rep, wasi_poll::HostPollable::drop)?
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
            super::release::from_table(&mut self.resource_table, rep, |table, error| {
                table.delete(error).map(drop)
            })??;
            Ok(())
        }
    }
}

// ────────────────────────────────────────────────────────────────────────
// astrid:io/streams — input-stream / output-stream
//
// The table stores WASI dynamic stream types. Immediate operations use the
// synchronous trait. Blocking operations await the asynchronous trait under
// caller admission and bounded I/O capacity. Both paths pass the selected
// handle and arguments through the directory binding before dispatch.
//
// The WIT error translation preserves the shared IoError resource type.

mod astrid_streams_impl {
    use super::*;
    use crate::engine::wasm::bindings::astrid::io::poll::Pollable;
    use crate::engine::wasm::bindings::astrid::io::streams::{
        self as astrid_streams, HostInputStream, HostOutputStream, InputStream, OutputStream,
    };
    use wasmtime::component::Resource;
    use wasmtime_wasi::p2::StreamError as RtStreamError;
    use wasmtime_wasi::p2::bindings::io::streams as async_streams;
    use wasmtime_wasi::p2::bindings::sync::io::streams as wasi_streams;

    /// `trappable_error_type` in `bindings.rs` rewrites every fallible
    /// stream method's return type to `Result<T, RtStreamError>` (the
    /// wasmtime-wasi-io runtime enum: Closed / LastOperationFailed /
    /// Trap). The bindgen-generated `convert_stream_error` lowers that
    /// back to the on-wire `astrid:io/streams.stream-error` variant for
    /// the guest.
    type StreamResult<T> = Result<T, RtStreamError>;

    fn audit_io<T, E: std::fmt::Debug>(
        state: &HostState,
        op: &'static str,
        bytes: u64,
        elapsed_ms: u64,
        result: &Result<T, E>,
    ) {
        let capsule_id = state.capsule_id.as_str();
        let principal = state.effective_principal();
        match result {
            Ok(_) => tracing::debug!(
                target: "astrid.audit.io",
                %capsule_id,
                %principal,
                fn = op,
                bytes,
                elapsed_ms,
                "audit",
            ),
            Err(e) => tracing::debug!(
                target: "astrid.audit.io",
                %capsule_id,
                %principal,
                fn = op,
                bytes,
                elapsed_ms,
                error = ?e,
                "audit",
            ),
        }
    }

    impl astrid_streams::Host for HostState {
        fn convert_stream_error(
            &mut self,
            err: RtStreamError,
        ) -> WResult<astrid_streams::StreamError> {
            // Delegate to wasi-sync's conversion — the bindgen-generated
            // wire variant for astrid:io/streams is structurally
            // identical to wasi:io/streams (Closed /
            // LastOperationFailed(Resource<Error>)) and the Error
            // resource is the same underlying type via the `with:` map,
            // so we re-tag the resource handle by rep.
            use wasmtime_wasi::p2::bindings::sync::io::streams::Host as WasiHost;
            let wasi_variant = WasiHost::convert_stream_error(&mut self.resource_table, err)?;
            Ok(match wasi_variant {
                wasi_streams::StreamError::Closed => astrid_streams::StreamError::Closed,
                wasi_streams::StreamError::LastOperationFailed(e) => {
                    astrid_streams::StreamError::LastOperationFailed(Resource::new_own(e.rep()))
                },
            })
        }
    }

    impl HostInputStream for HostState {
        fn read(&mut self, self_: Resource<InputStream>, len: u64) -> StreamResult<Vec<u8>> {
            let started = Instant::now();
            let result =
                super::authority::access(self, self_, len, wasi_streams::HostInputStream::read);
            let bytes = result.as_ref().map(|v| v.len() as u64).unwrap_or(0);
            let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
            audit_io(
                self,
                "astrid:io/streams/input-stream.read",
                bytes,
                elapsed_ms,
                &result,
            );
            result
        }

        async fn blocking_read(
            &mut self,
            self_: Resource<InputStream>,
            len: u64,
        ) -> StreamResult<Vec<u8>> {
            let started = Instant::now();
            let result = super::authority::blocking_access(
                self,
                self_,
                len,
                async_streams::HostInputStream::blocking_read,
            )
            .await;
            let bytes = result.as_ref().map(|v| v.len() as u64).unwrap_or(0);
            let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
            audit_io(
                self,
                "astrid:io/streams/input-stream.blocking-read",
                bytes,
                elapsed_ms,
                &result,
            );
            result
        }

        fn skip(&mut self, self_: Resource<InputStream>, len: u64) -> StreamResult<u64> {
            super::authority::access(self, self_, len, wasi_streams::HostInputStream::skip)
        }

        async fn blocking_skip(
            &mut self,
            self_: Resource<InputStream>,
            len: u64,
        ) -> StreamResult<u64> {
            super::authority::blocking_access(
                self,
                self_,
                len,
                async_streams::HostInputStream::blocking_skip,
            )
            .await
        }

        fn subscribe(&mut self, self_: Resource<InputStream>) -> WResult<Resource<Pollable>> {
            super::authority::access(
                self,
                Resource::new_borrow(self_.rep()),
                (),
                |table, stream, ()| wasi_streams::HostInputStream::subscribe(table, stream),
            )
        }

        async fn drop(&mut self, rep: Resource<InputStream>) -> WResult<()> {
            super::release::from_table(
                &mut self.resource_table,
                rep,
                async_streams::HostInputStream::drop,
            )?
            .await
        }
    }

    impl HostOutputStream for HostState {
        fn check_write(&mut self, self_: Resource<OutputStream>) -> StreamResult<u64> {
            super::authority::access(self, self_, (), |table, stream, ()| {
                wasi_streams::HostOutputStream::check_write(table, stream)
            })
        }

        fn write(&mut self, self_: Resource<OutputStream>, contents: Vec<u8>) -> StreamResult<()> {
            let started = Instant::now();
            let bytes = contents.len() as u64;
            let result = super::authority::access(
                self,
                self_,
                contents,
                wasi_streams::HostOutputStream::write,
            );
            let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
            audit_io(
                self,
                "astrid:io/streams/output-stream.write",
                bytes,
                elapsed_ms,
                &result,
            );
            result
        }

        async fn blocking_write_and_flush(
            &mut self,
            self_: Resource<OutputStream>,
            contents: Vec<u8>,
        ) -> StreamResult<()> {
            let started = Instant::now();
            let bytes = contents.len() as u64;
            let result = super::authority::blocking_access(
                self,
                self_,
                contents,
                async_streams::HostOutputStream::blocking_write_and_flush,
            )
            .await;
            let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
            audit_io(
                self,
                "astrid:io/streams/output-stream.blocking-write-and-flush",
                bytes,
                elapsed_ms,
                &result,
            );
            result
        }

        fn flush(&mut self, self_: Resource<OutputStream>) -> StreamResult<()> {
            super::authority::access(self, self_, (), |table, stream, ()| {
                wasi_streams::HostOutputStream::flush(table, stream)
            })
        }

        async fn blocking_flush(&mut self, self_: Resource<OutputStream>) -> StreamResult<()> {
            super::authority::blocking_access(self, self_, (), |table, stream, ()| {
                async_streams::HostOutputStream::blocking_flush(table, stream)
            })
            .await
        }

        fn subscribe(&mut self, self_: Resource<OutputStream>) -> WResult<Resource<Pollable>> {
            super::authority::access(
                self,
                Resource::new_borrow(self_.rep()),
                (),
                |table, stream, ()| wasi_streams::HostOutputStream::subscribe(table, stream),
            )
        }

        fn write_zeroes(&mut self, self_: Resource<OutputStream>, len: u64) -> StreamResult<()> {
            super::authority::access(
                self,
                self_,
                len,
                wasi_streams::HostOutputStream::write_zeroes,
            )
        }

        async fn blocking_write_zeroes_and_flush(
            &mut self,
            self_: Resource<OutputStream>,
            len: u64,
        ) -> StreamResult<()> {
            super::authority::blocking_access(
                self,
                self_,
                len,
                async_streams::HostOutputStream::blocking_write_zeroes_and_flush,
            )
            .await
        }

        fn splice(
            &mut self,
            self_: Resource<OutputStream>,
            src: Resource<InputStream>,
            len: u64,
        ) -> StreamResult<u64> {
            let started = Instant::now();
            let result = super::transfer::immediate(self, self_, src, len);
            let bytes = result.as_ref().copied().unwrap_or(0);
            let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
            audit_io(
                self,
                "astrid:io/streams/output-stream.splice",
                bytes,
                elapsed_ms,
                &result,
            );
            result
        }

        async fn blocking_splice(
            &mut self,
            self_: Resource<OutputStream>,
            src: Resource<InputStream>,
            len: u64,
        ) -> StreamResult<u64> {
            let started = Instant::now();
            let result = super::transfer::blocking(self, self_, src, len).await;
            let bytes = result.as_ref().copied().unwrap_or(0);
            let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
            audit_io(
                self,
                "astrid:io/streams/output-stream.blocking-splice",
                bytes,
                elapsed_ms,
                &result,
            );
            result
        }

        async fn drop(&mut self, rep: Resource<OutputStream>) -> WResult<()> {
            super::release::from_table(
                &mut self.resource_table,
                rep,
                async_streams::HostOutputStream::drop,
            )?
            .await
        }
    }
}

#[cfg(test)]
mod blocking_splice_tests;

#[cfg(test)]
mod splice_tests;

#[cfg(test)]
mod access_tests;

#[cfg(test)]
mod disposal_tests;
