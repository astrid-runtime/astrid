//! Bridge the checked admission order to the current invocation and audit sink.
use super::super::{admit_spawn, authenticated_principal, record_process_denied, spawn_admission};
use super::{ErrorCode, PrincipalId};
use crate::context::ProcessStorageMount;
use crate::engine::wasm::{host::util, host_state::HostState};

struct NativeGate<'a>(&'a HostState);

impl spawn_admission::Gate<PrincipalId, ErrorCode, Option<ProcessStorageMount>> for NativeGate<'_> {
    fn principal(&mut self, command: &str) -> bool {
        self.0.principal_process_allows(command)
    }

    fn host(&mut self, capsule: &str, command: &str) -> Option<String> {
        let Some(gate) = self.0.security.as_ref() else {
            return Some("no security gate configured".to_owned());
        };
        util::bounded_block_on(
            &self.0.runtime_handle,
            &self.0.blocking_semaphore,
            gate.check_host_process(capsule, command),
        )
        .err()
    }

    fn owner(&mut self) -> Option<PrincipalId> {
        authenticated_principal(self.0)
    }

    fn cancelled(&mut self) -> bool {
        self.0.effective_cancel_token().is_cancelled()
    }

    fn audit(&mut self, command: &str) -> Option<ErrorCode> {
        admit_spawn(self.0, command).err()
    }
    fn prepare(
        &mut self,
        owner: &PrincipalId,
        command: &str,
    ) -> Result<Option<ProcessStorageMount>, ErrorCode> {
        super::super::prepare_process_storage_mount_for(
            self.0,
            "astrid:process/host.spawn-persistent",
            command,
            || owner.clone(),
        )
    }
}

pub(in super::super) fn admit_and_prepare(
    state: &HostState,
    command: &str,
    idle: Option<u64>,
) -> Result<(PrincipalId, Option<ProcessStorageMount>), ErrorCode> {
    use spawn_admission::Refusal;
    spawn_admission::authorize(
        &mut NativeGate(state),
        &state.capability_names,
        state.capsule_id.as_str(),
        command,
        idle,
    )
    .map_err(|refusal| {
        let reason = match refusal {
            Refusal::Principal => "restricted principal process policy denied executable",
            Refusal::Host(ref reason) => reason,
            Refusal::Persistence => "persistent exec requires the allow_persistent capability",
            Refusal::Unauthenticated => return ErrorCode::PersistUnsupported,
            Refusal::IdleTimeout => return ErrorCode::InvalidInput,
            Refusal::Cancelled => return ErrorCode::Cancelled,
            Refusal::Audit(error) | Refusal::Prepare(error) => return error,
        };
        record_process_denied(
            state,
            "astrid:process/host.spawn-persistent",
            command,
            reason,
        );
        ErrorCode::CapabilityDenied
    })
}
