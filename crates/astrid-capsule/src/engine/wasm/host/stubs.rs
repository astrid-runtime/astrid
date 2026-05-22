//! Sentinel `Pollable` / `InputStream` / `OutputStream` impls used as
//! placeholders by the resource methods whose full implementation is
//! still pending (the stream-half adapter + per-resource pollable
//! wiring planned in dedicated follow-up commits).
//!
//! These are not panics: the host pushes a real but inert resource
//! into the wasmtime table and returns the corresponding handle to
//! the guest. Calls behave predictably:
//!
//! - `AlwaysReadyPollable.ready()` resolves immediately. A guest's
//!   `poll`/`block` returns at once; the guest is expected to then
//!   call the underlying resource's `read` / `recv` / etc., which is
//!   either real (preferred) or a clean typed error.
//! - `ClosedInputStream.read()` returns `StreamError::Closed`. The
//!   guest sees EOF / closed-stream behaviour as if the source was
//!   already exhausted.
//! - `ClosedOutputStream.{check_write, write, ...}` return
//!   `StreamError::Closed`. The guest cannot write through these
//!   stub halves until the real adapter lands.
//!
//! Pairing always-ready pollables with closed-on-access streams is
//! the standard wasi pattern for "the source is finished" — capsules
//! that handle EOF cleanly behave correctly without any special
//! code path for our stub state.

use async_trait::async_trait;
use wasmtime::component::Resource;
use wasmtime_wasi::p2::{
    DynInputStream, DynOutputStream, DynPollable, InputStream, OutputStream, Pollable, StreamError,
    subscribe,
};

/// Local alias for `wasmtime-wasi-io`'s `StreamResult` so this file
/// doesn't pull a direct dependency on the lower-level crate.
type StreamResult<T> = std::result::Result<T, StreamError>;

use bytes::Bytes;

/// A pollable that resolves immediately. Used by `subscribe-*` methods
/// whose dedicated pollable adapter has not landed yet.
struct AlwaysReadyPollable;

#[async_trait]
impl Pollable for AlwaysReadyPollable {
    async fn ready(&mut self) {
        // Resolves immediately.
    }
}

/// Allocate an always-ready pollable in `table` and return the
/// resource handle the guest sees.
pub(super) fn always_ready_pollable(
    table: &mut wasmtime::component::ResourceTable,
) -> Resource<DynPollable> {
    // Fail-soft: if pushing or wrapping somehow fails, fall back to a
    // never-allocated sentinel rep. The guest sees a Closed-on-read /
    // never-firing-poll handle either way; this branch should never
    // trip on a healthy store.
    let stub = match table.push(AlwaysReadyPollable) {
        Ok(r) => r,
        Err(_) => return Resource::new_own(0),
    };
    subscribe(table, stub).unwrap_or_else(|_| Resource::new_own(0))
}

/// An input-stream sentinel that reports EOF on every read.
struct ClosedInputStream;

#[async_trait]
impl Pollable for ClosedInputStream {
    async fn ready(&mut self) {
        // Always ready: read will return Closed promptly.
    }
}

impl InputStream for ClosedInputStream {
    fn read(&mut self, _size: usize) -> StreamResult<Bytes> {
        Err(StreamError::Closed)
    }
}

/// Allocate a closed-on-read input-stream sentinel and return the
/// resource handle the guest sees.
pub(super) fn closed_input_stream(
    table: &mut wasmtime::component::ResourceTable,
) -> Resource<wasmtime_wasi::p2::bindings::sync::io::streams::InputStream> {
    let boxed: DynInputStream = Box::new(ClosedInputStream);
    let res = table.push(boxed).unwrap_or_else(|_| Resource::new_own(0));
    Resource::new_own(res.rep())
}

/// An output-stream sentinel that reports Closed on every operation.
struct ClosedOutputStream;

#[async_trait]
impl Pollable for ClosedOutputStream {
    async fn ready(&mut self) {
        // Always ready: write will return Closed promptly.
    }
}

#[async_trait]
impl OutputStream for ClosedOutputStream {
    fn write(&mut self, _bytes: Bytes) -> StreamResult<()> {
        Err(StreamError::Closed)
    }

    fn flush(&mut self) -> StreamResult<()> {
        Err(StreamError::Closed)
    }

    fn check_write(&mut self) -> StreamResult<usize> {
        Err(StreamError::Closed)
    }
}

/// Allocate a closed-on-write output-stream sentinel.
pub(super) fn closed_output_stream(
    table: &mut wasmtime::component::ResourceTable,
) -> Resource<wasmtime_wasi::p2::bindings::sync::io::streams::OutputStream> {
    let boxed: DynOutputStream = Box::new(ClosedOutputStream);
    let res = table.push(boxed).unwrap_or_else(|_| Resource::new_own(0));
    Resource::new_own(res.rep())
}
