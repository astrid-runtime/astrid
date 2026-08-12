//! Small state-derived helpers shared by the process host surfaces.

use crate::engine::wasm::bindings::astrid::process1_1_0::host::EnvVar;
use crate::engine::wasm::host_state::HostState;

/// Extract the call id from an authenticated tool invocation, when present.
pub(super) fn extract_call_id(state: &HostState) -> Option<String> {
    state.caller_context.as_ref().and_then(|message| {
        if let astrid_events::ipc::IpcPayload::ToolExecuteRequest { call_id, .. } = &message.payload
        {
            Some(call_id.clone())
        } else {
            None
        }
    })
}

/// Summarize environment keys for audit without recording their values.
pub(super) fn env_summary(env: &[EnvVar]) -> String {
    env.iter()
        .map(|entry| entry.key.as_str())
        .collect::<Vec<_>>()
        .join(",")
}

/// Return only an invocation-authenticated principal. Persistent processes
/// must not share the capsule-owner fallback namespace.
pub(super) fn authenticated_principal(
    state: &HostState,
) -> Option<astrid_core::principal::PrincipalId> {
    state
        .caller_context
        .as_ref()
        .and_then(|message| message.principal.as_deref())
        .and_then(|principal| astrid_core::principal::PrincipalId::new(principal).ok())
}

pub(super) fn process_sandbox_policy(state: &HostState) -> astrid_workspace::SandboxPolicy {
    state
        .process_sandbox_policy
        .unwrap_or_else(astrid_workspace::SandboxPolicy::from_env)
}
