//! Native splice sinks. The admitted request owns the lifecycle guards until the call returns.
use super::authority::Authority;
use super::splice::{Admitted, Mode, Request};
use crate::engine::wasm::bindings::astrid::io::streams::{InputStream, OutputStream};
use crate::engine::wasm::host::util;
use crate::engine::wasm::host_state::HostState;
use wasmtime::component::Resource;
use wasmtime_wasi::p2::StreamError;

fn admit(
    state: &HostState,
    mode: Mode,
    dst: Resource<OutputStream>,
    src: Resource<InputStream>,
    length: u64,
) -> Result<Admitted<Authority>, StreamError> {
    let request = Request {
        mode,
        destination: dst.rep(),
        source: src.rep(),
        length,
    };
    request.admit(|target| {
        let authority = Authority::capture(state)?;
        state
            .resource_table
            .get(&Resource::<OutputStream>::new_borrow(target.destination))?;
        state
            .resource_table
            .get(&Resource::<InputStream>::new_borrow(target.source))?;
        Ok(authority)
    })
}

pub(super) fn immediate(
    state: &mut HostState,
    dst: Resource<OutputStream>,
    src: Resource<InputStream>,
    len: u64,
) -> Result<u64, StreamError> {
    use wasmtime_wasi::p2::bindings::sync::io::streams::HostOutputStream;
    let operation = admit(state, Mode::Immediate, dst, src, len)?;
    let directory = &state.principal_directory;
    let cancel = state.effective_cancel_token();
    operation
        .start(
            Mode::Immediate,
            &mut state.resource_table,
            |guard, table, request| {
                guard.start(
                    directory,
                    &cancel,
                    table,
                    request,
                    (),
                    |table, target, ()| {
                        HostOutputStream::splice(
                            table,
                            Resource::new_borrow(target.destination),
                            Resource::new_borrow(target.source),
                            target.length,
                        )
                    },
                )?
            },
        )
        .ok_or(StreamError::Closed)?
}

pub(super) async fn blocking(
    state: &mut HostState,
    dst: Resource<OutputStream>,
    src: Resource<InputStream>,
    len: u64,
) -> Result<u64, StreamError> {
    let operation = admit(state, Mode::Blocking, dst, src, len)?;
    let directory = &state.principal_directory;
    let semaphore = &state.io_semaphore;
    let cancel = state.effective_cancel_token();
    let transfer = operation
        .start(
            Mode::Blocking,
            &mut state.resource_table,
            |guard, table, request| async move {
                let transfer = util::bounded_await_cancellable(semaphore, &cancel, async {
                    // Validate the opening binding after acquiring capacity. Keep the
                    // directory lock out of the asynchronous WASI read and write.
                    let work = guard.start(
                        directory,
                        &cancel,
                        table,
                        request,
                        (),
                        |table, target, ()| copy_chunk(table, target),
                    )?;
                    guard.while_bound(directory, &cancel, work).await
                });
                let result = match &guard.device {
                    Some(device) => device.while_live(transfer).await.flatten(),
                    None => transfer.await,
                }
                .ok_or(StreamError::Closed)?;
                guard.complete(directory, &cancel, result)
            },
        )
        .ok_or(StreamError::Closed)?;
    transfer.await
}

/// The first readiness permit covers the synchronous write after reading.
async fn copy_chunk(
    table: &mut wasmtime::component::ResourceTable,
    target: Request,
) -> Result<u64, StreamError> {
    use wasmtime_wasi::p2::{DynInputStream, DynOutputStream};

    let destination = Resource::<DynOutputStream>::new_borrow(target.destination);
    let source = Resource::<DynInputStream>::new_borrow(target.source);
    let writable = table.get_mut(&destination)?.write_ready().await?;
    let requested = super::splice::chunk_limit(target.length, writable);
    if requested == 0 {
        return Ok(0);
    }
    let bytes = table.get_mut(&source)?.blocking_read(requested).await?;
    let copied =
        u64::try_from(bytes.len()).map_err(|_| StreamError::trap("splice count exceeds u64"))?;
    if copied == 0 {
        return Ok(0);
    }
    // Preserve the chunk when the outer call future is dropped. Do not
    // suspend between consuming the source and using the destination permit.
    let output = table.get_mut(&destination)?;
    super::splice::write_chunk(requested, bytes.len(), bytes, |bytes| output.write(bytes))
        .ok_or_else(|| StreamError::trap("input stream exceeded authorized splice size"))??;
    match output.flush() {
        Ok(()) => {},
        Err(StreamError::Closed) => return Ok(copied),
        Err(error) => return Err(error),
    }
    match output.write_ready().await {
        Ok(_) | Err(StreamError::Closed) => Ok(copied),
        Err(error) => Err(error),
    }
}
