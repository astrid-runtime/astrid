//! Caller lifetime and directory binding for resource-table stream operations.
use crate::engine::wasm::host_state::HostState;
use astrid_core::profile::device_sessions::DeviceSession;
use astrid_core::{PrincipalId, PrincipalUid};
use wasmtime::component::{Resource, ResourceTable};
use wasmtime_wasi::p2::StreamError;

pub(super) struct Authority {
    principal: PrincipalId,
    owner: PrincipalUid,
    _invocation: Option<crate::engine::wasm::PrincipalInvocationGuard>,
    pub(super) device: Option<DeviceSession>,
}

impl Authority {
    pub(super) fn capture(state: &HostState) -> Result<Self, StreamError> {
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
        Ok(Self {
            principal,
            owner,
            _invocation: invocation,
            device,
        })
    }

    pub(super) fn start<'a, S, A, R, F>(
        &self,
        directory: &astrid_storage::PrincipalDirectory,
        cancel: &tokio_util::sync::CancellationToken,
        table: &'a mut ResourceTable,
        operand: S,
        args: A,
        operation: F,
    ) -> Result<R, StreamError>
    where
        F: FnOnce(&'a mut ResourceTable, S, A) -> R,
    {
        directory
            .with_bound_input(
                &self.principal,
                self.owner,
                (operand, args, operation),
                |bound| {
                    super::dispatch::dispatch(
                        cancel.is_cancelled(),
                        self.device.as_ref().is_some_and(DeviceSession::is_retired),
                        table,
                        bound,
                    )
                },
            )
            .ok()
            .flatten()
            .ok_or(StreamError::Closed)
    }

    /// Hold the current binding while the backend takes one synchronous poll.
    /// Returning Pending releases the directory lock before the executor waits.
    pub(super) async fn while_bound<R>(
        &self,
        directory: &astrid_storage::PrincipalDirectory,
        cancel: &tokio_util::sync::CancellationToken,
        work: impl Future<Output = Result<R, StreamError>>,
    ) -> Result<R, StreamError> {
        use std::task::Poll;
        let mut work = std::pin::pin!(work);
        std::future::poll_fn(|cx| {
            directory
                .with_bound_input(&self.principal, self.owner, cx, |cx| {
                    super::dispatch::dispatch(
                        cancel.is_cancelled(),
                        self.device.as_ref().is_some_and(DeviceSession::is_retired),
                        work.as_mut(),
                        (cx, (), |future: std::pin::Pin<&mut _>, cx, ()| {
                            Future::poll(future, cx)
                        }),
                    )
                })
                .ok()
                .flatten()
                .unwrap_or(Poll::Ready(Err(StreamError::Closed)))
        })
        .await
    }

    pub(super) fn complete<R>(
        &self,
        directory: &astrid_storage::PrincipalDirectory,
        cancel: &tokio_util::sync::CancellationToken,
        result: Result<R, StreamError>,
    ) -> Result<R, StreamError> {
        directory
            .with_bound_input(&self.principal, self.owner, result, |result| {
                super::dispatch::disclose(
                    cancel.is_cancelled(),
                    self.device.as_ref().is_some_and(DeviceSession::is_retired),
                    result,
                )
                .unwrap_or(Err(StreamError::Closed))
            })
            .unwrap_or(Err(StreamError::Closed))
    }
}

/// Keep both lifetime guards and the current owner binding through a synchronous
/// table operation. The typed resource and its arguments travel together.
pub(super) fn access<S: 'static, A, R, E: From<StreamError>>(
    state: &mut HostState,
    stream: Resource<S>,
    args: A,
    operation: impl FnOnce(&mut ResourceTable, Resource<S>, A) -> Result<R, E>,
) -> Result<R, E> {
    let admission = Authority::capture(state)?;
    let cancel = state.effective_cancel_token();
    admission.start(
        &state.principal_directory,
        &cancel,
        &mut state.resource_table,
        stream,
        args,
        operation,
    )?
}

/// Check the current owner after capacity becomes available, then revalidate
/// before disclosing the result. The directory lock never spans a WASI wait.
pub(super) async fn blocking_access<'a, S: 'static, A, R, F>(
    state: &'a mut HostState,
    stream: Resource<S>,
    args: A,
    operation: impl FnOnce(&'a mut ResourceTable, Resource<S>, A) -> F,
) -> Result<R, StreamError>
where
    F: Future<Output = Result<R, StreamError>>,
{
    let admission = Authority::capture(state)?;
    let cancel = state.effective_cancel_token();
    let directory = &state.principal_directory;
    let table = &mut state.resource_table;
    let io = crate::engine::wasm::host::util::bounded_await_cancellable(
        &state.io_semaphore,
        &cancel,
        async {
            let work = admission.start(directory, &cancel, table, stream, args, operation)?;
            admission.while_bound(directory, &cancel, work).await
        },
    );
    let result = match &admission.device {
        Some(device) => device.while_live(io).await.flatten(),
        None => io.await,
    }
    .ok_or(StreamError::Closed)?;
    admission.complete(directory, &cancel, result)
}
