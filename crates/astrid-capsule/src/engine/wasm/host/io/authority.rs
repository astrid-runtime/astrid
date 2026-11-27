//! Caller lifetime and directory binding for resource-table stream operations.
use crate::engine::wasm::host_state::HostState;
use astrid_core::profile::device_sessions::DeviceSession;
use astrid_core::{PrincipalId, PrincipalUid};
use wasmtime::component::{Resource, ResourceTable};
use wasmtime_wasi::p2::StreamError;

pub(super) struct Authority {
    pub(super) principal: PrincipalId,
    pub(super) owner: PrincipalUid,
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
}

/// Keep both lifetime guards and the current owner binding through a synchronous
/// table operation. The typed resource and its arguments travel together.
pub(super) fn access<S: 'static, A, R>(
    state: &mut HostState,
    stream: Resource<S>,
    args: A,
    operation: impl FnOnce(&mut ResourceTable, Resource<S>, A) -> Result<R, StreamError>,
) -> Result<R, StreamError> {
    let admission = Authority::capture(state)?;
    let cancel = state.effective_cancel_token();
    let table = &mut state.resource_table;
    state
        .principal_directory
        .with_bound_input(
            &admission.principal,
            admission.owner,
            (stream, args, operation),
            |bound| {
                super::dispatch::dispatch(
                    cancel.is_cancelled(),
                    admission
                        .device
                        .as_ref()
                        .is_some_and(DeviceSession::is_retired),
                    table,
                    bound,
                )
                .unwrap_or(Err(StreamError::Closed))
            },
        )
        .unwrap_or(Err(StreamError::Closed))
}
