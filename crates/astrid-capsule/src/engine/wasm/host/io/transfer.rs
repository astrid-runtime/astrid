//! Native splice sinks. The admitted request owns the lifecycle guards until the call returns.
use super::splice::{Admitted, Mode, Request};
use crate::engine::wasm::bindings::astrid::io::streams::{InputStream, OutputStream};
use crate::engine::wasm::host::util;
use crate::engine::wasm::host_state::HostState;
use astrid_core::profile::device_sessions::DeviceSession;
use astrid_core::{PrincipalId, PrincipalUid};
use wasmtime::component::Resource;
use wasmtime_wasi::p2::StreamError;

struct Authority {
    principal: PrincipalId,
    owner: PrincipalUid,
    _invocation: Option<crate::engine::wasm::PrincipalInvocationGuard>,
    device: Option<DeviceSession>,
}

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
        let invocation = state
            .begin_host_operation()
            .map_err(|()| StreamError::Closed)?;
        let device = state
            .begin_device_operation()
            .map_err(|()| StreamError::Closed)?;
        let principal = state.effective_principal();
        let owner = state
            .principal_directory
            .bound_uid(
                &principal,
                state.invocation_storage_uid.or(state.runtime_owner_uid),
            )
            .map_err(|_| StreamError::Closed)?;
        state
            .resource_table
            .get(&Resource::<OutputStream>::new_borrow(target.destination))?;
        state
            .resource_table
            .get(&Resource::<InputStream>::new_borrow(target.source))?;
        Ok(Authority {
            principal,
            owner,
            _invocation: invocation,
            device,
        })
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
    operation
        .start(
            Mode::Immediate,
            &mut state.resource_table,
            |guard, table, request| {
                directory
                    .with_bound_input(&guard.principal, guard.owner, request, |target| {
                        if guard.device.as_ref().is_some_and(DeviceSession::is_retired) {
                            return Err(StreamError::Closed);
                        }
                        HostOutputStream::splice(
                            table,
                            Resource::new_borrow(target.destination),
                            Resource::new_borrow(target.source),
                            target.length,
                        )
                    })
                    .unwrap_or(Err(StreamError::Closed))
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
    use wasmtime_wasi::p2::bindings::io::streams::HostOutputStream;
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
                    let work = directory
                        .with_bound_input(&guard.principal, guard.owner, request, |target| {
                            HostOutputStream::blocking_splice(
                                table,
                                Resource::new_borrow(target.destination),
                                Resource::new_borrow(target.source),
                                target.length,
                            )
                        })
                        .map_err(|_| StreamError::Closed)?;
                    work.await
                });
                match &guard.device {
                    Some(device) => device.while_live(transfer).await.flatten(),
                    None => transfer.await,
                }
                .unwrap_or(Err(StreamError::Closed))
            },
        )
        .ok_or(StreamError::Closed)?;
    transfer.await
}
