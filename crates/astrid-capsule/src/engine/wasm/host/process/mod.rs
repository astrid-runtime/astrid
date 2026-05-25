//! `astrid:process@1.0.0` host implementation.
//!
//! Desktop-only package (the WIT header explicitly notes hermit-rs
//! unikernel targets do not provide it). The kernel here:
//!
//! - `spawn` — synchronous sandboxed exec with stdout/stderr capture.
//!   Full impl; ported from the legacy path.
//! - `spawn-background` — sandboxed exec returning
//!   `Resource<ProcessHandle>`. Stdout/stderr drain into 1 MiB-per-stream
//!   ring buffers via reader threads. Tracked by the per-capsule cap
//!   plus the per-principal profile sub-budget.
//! - `ProcessHandle.{read-logs, wait, kill, os-pid}` — full impls.
//! - `ProcessHandle.{write-stdin, close-stdin, signal, wait-with-output,
//!   subscribe-exit, subscribe-logs}` — stubbed pending dedicated
//!   follow-ups (stdin pipe storage + pollable wiring).
//!
//! `HostState.background_processes` is gone — the wasmtime resource
//! table is the canonical storage for `ManagedProcess`.

mod handle;
mod managed;
mod tracker;

use std::collections::VecDeque;
use std::process::Stdio;
use std::sync::{Arc, Mutex};

use tokio::process::Command as TokioCommand;
use tracing::warn;
use wasmtime::component::Resource;

use crate::engine::wasm::bindings::astrid::process::host::{
    self as process, EnvVar, ErrorCode, ExitInfo, ProcessHandle, ProcessResult, SpawnRequest,
};
use crate::engine::wasm::host::util;
use crate::engine::wasm::host_state::HostState;
use managed::{ManagedProcess, attach_pipes, configure_piped, prepare_sandboxed_command};

pub use tracker::ProcessTracker;
// Public so other crates (engine/init, hooks) can reference the type
// even though the field has moved off HostState.
pub use managed::ManagedProcess as PublicManagedProcess;

/// Per-capsule hard ceiling on concurrent background processes.
pub(crate) const MAX_BACKGROUND_PROCESSES: usize = 8;

/// Audit a process host fn invocation.
fn audit_process<T, E: std::fmt::Debug>(
    state: &HostState,
    op: &'static str,
    cmd: &str,
    result: &Result<T, E>,
) {
    let capsule_id = state.capsule_id.as_str();
    let principal = state.effective_principal();
    match result {
        Ok(_) => tracing::debug!(
            target: "astrid.audit.process",
            %capsule_id,
            %principal,
            fn = op,
            cmd,
            "audit",
        ),
        Err(e) => tracing::debug!(
            target: "astrid.audit.process",
            %capsule_id,
            %principal,
            fn = op,
            cmd,
            error = ?e,
            "audit",
        ),
    }
}

/// Extract the call_id from the caller's IPC context if it carried a
/// `ToolExecuteRequest` payload.
fn extract_call_id(state: &HostState) -> Option<String> {
    state.caller_context.as_ref().and_then(|msg| {
        if let astrid_events::ipc::IpcPayload::ToolExecuteRequest { call_id, .. } = &msg.payload {
            Some(call_id.clone())
        } else {
            None
        }
    })
}

/// Convert SpawnRequest's env list into the legacy String args style.
/// Currently env is ignored at exec time (the sandbox strips most vars);
/// retained for the audit log.
fn env_summary(env: &[EnvVar]) -> String {
    env.iter()
        .map(|e| e.key.as_str())
        .collect::<Vec<_>>()
        .join(",")
}

impl process::Host for HostState {
    fn spawn(&mut self, request: SpawnRequest) -> Result<ProcessResult, ErrorCode> {
        let workspace_root = self.workspace_root.clone();
        let security = self.security.clone();
        let capsule_id = self.capsule_id.as_str().to_owned();
        let handle = self.runtime_handle.clone();
        let semaphore = self.host_semaphore.clone();
        let cancel_token = self.cancel_token.clone();
        let process_tracker = self.process_tracker.clone();
        let call_id = extract_call_id(self);

        let cmd_for_audit = request.cmd.clone();
        let _env_for_audit = env_summary(&request.env);

        if let Some(sec) = security {
            let cmd = request.cmd.to_string();
            let check = util::bounded_block_on(&handle, &semaphore, async move {
                sec.check_host_process(&capsule_id, &cmd).await
            });
            if check.is_err() {
                let result: Result<ProcessResult, ErrorCode> = Err(ErrorCode::CapabilityDenied);
                audit_process(self, "astrid:process/host.spawn", &cmd_for_audit, &result);
                return result;
            }
        } else {
            let result: Result<ProcessResult, ErrorCode> = Err(ErrorCode::CapabilityDenied);
            audit_process(self, "astrid:process/host.spawn", &cmd_for_audit, &result);
            return result;
        }

        let mut sandboxed_cmd =
            prepare_sandboxed_command(&request.cmd, &request.args, &workspace_root)
                .map_err(|_| ErrorCode::InvalidInput)?;
        sandboxed_cmd.stdout(Stdio::piped());
        sandboxed_cmd.stderr(Stdio::piped());

        let child = sandboxed_cmd
            .spawn()
            .map_err(|e| ErrorCode::Unknown(format!("spawn failed: {e}")))?;
        let pid = child.id();
        process_tracker.register(pid, call_id);

        let output_result =
            util::bounded_block_on_cancellable(&handle, &semaphore, &cancel_token, async move {
                tokio::task::spawn_blocking(move || child.wait_with_output())
                    .await
                    .map_err(std::io::Error::other)
                    .and_then(|r| r)
            });

        let result: Result<ProcessResult, ErrorCode> = match output_result {
            Some(Ok(output)) => {
                process_tracker.unregister(pid);
                Ok(ProcessResult {
                    stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                    stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
                    exit: ExitInfo {
                        exit_code: output.status.code(),
                        signal: None,
                    },
                })
            },
            Some(Err(e)) => {
                process_tracker.unregister(pid);
                Err(ErrorCode::Unknown(format!("exec failed: {e}")))
            },
            None => {
                warn!(capsule_id = %self.capsule_id, pid, "process cancelled");
                #[cfg(unix)]
                if let Ok(raw) = i32::try_from(pid) {
                    let _ = nix::sys::signal::kill(
                        nix::unistd::Pid::from_raw(raw),
                        nix::sys::signal::Signal::SIGKILL,
                    );
                }
                process_tracker.unregister(pid);
                Err(ErrorCode::Cancelled)
            },
        };
        audit_process(self, "astrid:process/host.spawn", &cmd_for_audit, &result);
        result
    }

    fn spawn_background(
        &mut self,
        request: SpawnRequest,
    ) -> Result<Resource<ProcessHandle>, ErrorCode> {
        let principal = self.effective_principal();
        let profile_cap = usize::try_from(self.effective_profile().quotas.max_background_processes)
            .unwrap_or(MAX_BACKGROUND_PROCESSES);
        let effective_cap = profile_cap.min(MAX_BACKGROUND_PROCESSES);
        let by_principal = self
            .process_count_by_principal
            .get(&principal)
            .copied()
            .unwrap_or(0);
        if by_principal >= effective_cap || self.process_count_total >= MAX_BACKGROUND_PROCESSES {
            return Err(ErrorCode::Quota);
        }

        let workspace_root = self.workspace_root.clone();
        let security = self.security.clone();
        let capsule_id = self.capsule_id.as_str().to_owned();
        let handle = self.runtime_handle.clone();
        let semaphore = self.host_semaphore.clone();
        let cmd_for_audit = request.cmd.clone();

        if let Some(sec) = security {
            let cmd = request.cmd.to_string();
            let check = util::bounded_block_on(&handle, &semaphore, async move {
                sec.check_host_process(&capsule_id, &cmd).await
            });
            if check.is_err() {
                return Err(ErrorCode::CapabilityDenied);
            }
        } else {
            return Err(ErrorCode::CapabilityDenied);
        }

        // Re-check the cancellation token AFTER the (potentially
        // semaphore-bounded) capability check has run. The window
        // between gate clearance and `spawn()` is small but
        // non-zero — surfacing Cancelled here avoids fork+exec
        // immediately followed by tracker-less orphaning if the
        // capsule is being torn down right now.
        if self.cancel_token.is_cancelled() {
            return Err(ErrorCode::Cancelled);
        }

        let mut sandboxed_cmd =
            prepare_sandboxed_command(&request.cmd, &request.args, &workspace_root)
                .map_err(|_| ErrorCode::InvalidInput)?;
        configure_piped(&mut sandboxed_cmd);

        // Convert the prepared std::Command into a tokio::Command so the
        // spawned Child supports async wait(&mut self) without ownership
        // transfer (Gemini #752 finding — the previous std::Child path
        // stranded the handle inside spawn_blocking on timeout).
        // `kill_on_drop(true)` ensures the tokio runtime reaps the
        // zombie if `ManagedProcess` is dropped before the child exits.
        let mut tokio_cmd = TokioCommand::from(sandboxed_cmd);
        tokio_cmd.kill_on_drop(true);

        let command_str = format!("{} {}", request.cmd, request.args.join(" "));
        let child = tokio_cmd
            .spawn()
            .map_err(|e| ErrorCode::Unknown(format!("spawn-background failed: {e}")))?;

        let stdout_buf: Arc<Mutex<VecDeque<u8>>> = Arc::new(Mutex::new(VecDeque::new()));
        let stderr_buf: Arc<Mutex<VecDeque<u8>>> = Arc::new(Mutex::new(VecDeque::new()));
        let mut managed = ManagedProcess {
            child: Some(child),
            stdout_buf: Arc::clone(&stdout_buf),
            stderr_buf: Arc::clone(&stderr_buf),
            command: command_str,
            creator: principal.clone(),
        };

        let pid = managed
            .child
            .as_ref()
            .and_then(tokio::process::Child::id)
            .unwrap_or(0);
        attach_pipes(&mut managed, &handle);

        // Register with the cancellation tracker so a
        // `tool.v1.request.cancel` event reaches the background
        // child. spawn-background does not currently propagate a
        // call_id (no caller_context payload to extract from in the
        // common case), so the entry is registered with None — which
        // makes it eligible for the "conservative fallback" branch of
        // `cancel_by_call_ids` (cancelled by any matching event).
        self.process_tracker.register(pid, None);

        let res = self
            .resource_table
            .push(managed)
            .map_err(|e| ErrorCode::Unknown(format!("resource table: {e}")))?;
        self.process_count_total += 1;
        *self
            .process_count_by_principal
            .entry(principal)
            .or_insert(0) += 1;
        let result: Result<Resource<ProcessHandle>, ErrorCode> = Ok(Resource::new_own(res.rep()));
        audit_process(
            self,
            "astrid:process/host.spawn-background",
            &cmd_for_audit,
            &result,
        );
        result
    }
}
