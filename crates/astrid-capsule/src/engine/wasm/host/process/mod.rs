//! `astrid:process@1.1.0` host implementation (the `@1.0.0` shims live in
//! `compat.rs`).
//!
//! Both frozen contract versions are served off one implementation. This
//! module implements the `@1.1.0` `Host` / `HostProcessHandle` traits — the
//! SUPERSET, carrying the per-spawn read-only `file-injection` surface. The
//! `@1.0.0` traits are thin delegating shims in `compat.rs` that spawn with an
//! empty injection list; see that module for the version-bridging rationale.
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

mod audit;
mod compat;
mod handle;
mod inject;
mod managed;
mod persistent;
mod tracker;

use std::collections::VecDeque;
use std::process::Stdio;
use std::sync::{Arc, Mutex};

use tokio::process::Command as TokioCommand;
use tracing::warn;
use wasmtime::component::Resource;

use crate::engine::wasm::bindings::astrid::process1_1_0::host::{
    self as process, EnvVar, ErrorCode, ExitInfo, LogChunk, LogCursor, LogStream, ProcessHandle,
    ProcessInfo, ProcessResult, ProcessSignal, ReadLogsResult, SpawnRequest,
};
use crate::engine::wasm::host::util;
use crate::engine::wasm::host_state::HostState;
use managed::{ManagedProcess, attach_pipes, configure_piped, prepare_sandboxed_command};

pub(crate) use audit::{
    audit_process, audit_process_id, audit_process_injections, audit_spawn_result,
    record_process_denied,
};
pub use persistent::PersistentProcessRegistry;
pub use tracker::ProcessTracker;
// Public so other crates (engine/init, hooks) can reference the type
// even though the field has moved off HostState.
pub use managed::ManagedProcess as PublicManagedProcess;

/// Per-capsule hard ceiling on concurrent background processes.
pub(crate) const MAX_BACKGROUND_PROCESSES: usize = 8;

/// Per-spawn stdin prelude cap (the WIT: `spawn-request.stdin` "Capped at
/// 4 MiB per spawn"). Oversized preludes are rejected with `too-large`.
const MAX_SPAWN_STDIN_BYTES: usize = 4 * 1024 * 1024;

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

/// The AUTHENTICATED calling principal, or `None` when the call resolves to
/// the capsule-owner fallback (no caller in scope). `spawn-persistent`
/// refuses the fallback: a persistent id MUST be scoped to a real principal,
/// or unauthenticated paths would share one `default` namespace that
/// `list-processes` would enumerate across tenants.
fn authenticated_principal(state: &HostState) -> Option<astrid_core::principal::PrincipalId> {
    state
        .caller_context
        .as_ref()
        .and_then(|m| m.principal.as_deref())
        .and_then(|p| astrid_core::principal::PrincipalId::new(p).ok())
}

/// Build the sandboxed `Child` for a persistent spawn: stdout/stderr piped,
/// stdin piped only when a prelude or `keep-stdin-open` needs it, own process
/// group (so signals reach descendants), `kill_on_drop` as the reap backstop.
fn build_persistent_child(
    request: &SpawnRequest,
    workspace_root: &std::path::Path,
    want_stdin: bool,
    injections: &[astrid_workspace::RoInjection],
    inject_env: &[(String, String)],
) -> Result<tokio::process::Child, ErrorCode> {
    let mut sandboxed = prepare_sandboxed_command(
        &request.cmd,
        &request.args,
        workspace_root,
        injections,
        inject_env,
    )
    .map_err(|_| ErrorCode::InvalidInput)?;
    // `configure_piped` sets the process group + stdout/stderr pipes.
    configure_piped(&mut sandboxed);
    if want_stdin {
        sandboxed.stdin(Stdio::piped());
    } else {
        sandboxed.stdin(Stdio::null());
    }
    let mut tokio_cmd = TokioCommand::from(sandboxed);
    tokio_cmd.kill_on_drop(true);
    tokio_cmd
        .spawn()
        .map_err(|e| ErrorCode::Unknown(format!("spawn-persistent failed: {e}")))
}

impl process::Host for HostState {
    fn spawn(&mut self, request: SpawnRequest) -> Result<ProcessResult, ErrorCode> {
        let workspace_root = self.workspace_root.clone();
        let security = self.security.clone();
        let capsule_id = self.capsule_id.as_str().to_owned();
        let handle = self.runtime_handle.clone();
        let semaphore = self.blocking_semaphore.clone();
        let cancel_token = self.effective_cancel_token();
        let process_tracker = self.process_tracker.clone();
        let call_id = extract_call_id(self);

        let cmd_for_audit = request.cmd.clone();
        let _env_for_audit = env_summary(&request.env);

        if let Some(sec) = security {
            let cmd = request.cmd.to_string();
            let check = util::bounded_block_on(&handle, &semaphore, async move {
                sec.check_host_process(&capsule_id, &cmd).await
            });
            if let Err(reason) = check {
                // Gate-denied spawn: record the denial as `Denied` (exactly
                // once) and fail closed before any exec.
                record_process_denied(self, "astrid:process/host.spawn", &cmd_for_audit, &reason);
                return Err(ErrorCode::CapabilityDenied);
            }
        } else {
            // No security gate configured → spawn is denied fail-closed.
            record_process_denied(
                self,
                "astrid:process/host.spawn",
                &cmd_for_audit,
                "no security gate configured",
            );
            return Err(ErrorCode::CapabilityDenied);
        }

        // Snapshot + verify any read-only file injections before building the
        // command. `_injection_guard` is held to the end of this fn so the
        // host-owned snapshot lives for the child's lifetime and is cleaned up
        // after the child has run.
        let prepared = match inject::prepare_injections(&request.file_injections) {
            Ok(p) => p,
            Err(e) => {
                let result: Result<ProcessResult, ErrorCode> = Err(e);
                audit_process(self, "astrid:process/host.spawn", &cmd_for_audit, &result);
                return result;
            },
        };
        let injection_audit = prepared.audit;
        let injection_env = prepared.env;
        let _injection_guard = prepared.guard;

        let mut sandboxed_cmd = match prepare_sandboxed_command(
            &request.cmd,
            &request.args,
            &workspace_root,
            &prepared.sandbox,
            &injection_env,
        ) {
            Ok(cmd) => cmd,
            Err(_) => {
                // Sandbox construction failed before exec — audit the attempt as
                // Failed instead of returning silently via `?`.
                let result: Result<ProcessResult, ErrorCode> = Err(ErrorCode::InvalidInput);
                audit_spawn_result(
                    self,
                    "astrid:process/host.spawn",
                    &cmd_for_audit,
                    &injection_audit,
                    &result,
                );
                return result;
            },
        };
        sandboxed_cmd.stdout(Stdio::piped());
        sandboxed_cmd.stderr(Stdio::piped());

        let child = match sandboxed_cmd.spawn() {
            Ok(child) => child,
            Err(e) => {
                // Fork/exec failed — audit the attempt as Failed before
                // returning.
                let result: Result<ProcessResult, ErrorCode> =
                    Err(ErrorCode::Unknown(format!("spawn failed: {e}")));
                audit_spawn_result(
                    self,
                    "astrid:process/host.spawn",
                    &cmd_for_audit,
                    &injection_audit,
                    &result,
                );
                return result;
            },
        };
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
        audit_spawn_result(
            self,
            "astrid:process/host.spawn",
            &cmd_for_audit,
            &injection_audit,
            &result,
        );
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
        // The per-principal concurrent cap is SHARED with the persistent tier:
        // count this principal's live persistent processes too, so mixing the
        // two tiers cannot exceed the cap.
        let persistent_live = self.persistent_processes.live_count(&principal);
        if by_principal + persistent_live >= effective_cap
            || self.process_count_total >= MAX_BACKGROUND_PROCESSES
        {
            return Err(ErrorCode::Quota);
        }

        let workspace_root = self.workspace_root.clone();
        let security = self.security.clone();
        let capsule_id = self.capsule_id.as_str().to_owned();
        let handle = self.runtime_handle.clone();
        let semaphore = self.blocking_semaphore.clone();
        let cmd_for_audit = request.cmd.clone();

        if let Some(sec) = security {
            let cmd = request.cmd.to_string();
            let check = util::bounded_block_on(&handle, &semaphore, async move {
                sec.check_host_process(&capsule_id, &cmd).await
            });
            if let Err(reason) = check {
                record_process_denied(
                    self,
                    "astrid:process/host.spawn-background",
                    &cmd_for_audit,
                    &reason,
                );
                return Err(ErrorCode::CapabilityDenied);
            }
        } else {
            record_process_denied(
                self,
                "astrid:process/host.spawn-background",
                &cmd_for_audit,
                "no security gate configured",
            );
            return Err(ErrorCode::CapabilityDenied);
        }

        // Re-check the cancellation token AFTER the (potentially
        // semaphore-bounded) capability check has run. The window
        // between gate clearance and `spawn()` is small but
        // non-zero — surfacing Cancelled here avoids fork+exec
        // immediately followed by tracker-less orphaning if the
        // capsule is being torn down right now.
        if self.effective_cancel_token().is_cancelled() {
            return Err(ErrorCode::Cancelled);
        }

        // Snapshot + verify any read-only file injections. The guard is stored
        // on the `ManagedProcess` below so it lives as long as the handle and
        // cleans up the host-owned snapshot dir when it drops.
        let prepared = match inject::prepare_injections(&request.file_injections) {
            Ok(p) => p,
            Err(e) => {
                let result: Result<Resource<ProcessHandle>, ErrorCode> = Err(e);
                audit_process(
                    self,
                    "astrid:process/host.spawn-background",
                    &cmd_for_audit,
                    &result,
                );
                return result;
            },
        };
        let injection_audit = prepared.audit;
        let injection_env = prepared.env;

        let mut sandboxed_cmd = match prepare_sandboxed_command(
            &request.cmd,
            &request.args,
            &workspace_root,
            &prepared.sandbox,
            &injection_env,
        ) {
            Ok(cmd) => cmd,
            Err(_) => {
                // Sandbox construction failed before exec — audit the attempt as
                // Failed instead of returning silently via `?`.
                let result: Result<Resource<ProcessHandle>, ErrorCode> =
                    Err(ErrorCode::InvalidInput);
                audit_spawn_result(
                    self,
                    "astrid:process/host.spawn-background",
                    &cmd_for_audit,
                    &injection_audit,
                    &result,
                );
                return result;
            },
        };
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
        let child = match tokio_cmd.spawn() {
            Ok(child) => child,
            Err(e) => {
                // Fork/exec failed — audit the attempt as Failed before
                // returning.
                let result: Result<Resource<ProcessHandle>, ErrorCode> =
                    Err(ErrorCode::Unknown(format!("spawn-background failed: {e}")));
                audit_spawn_result(
                    self,
                    "astrid:process/host.spawn-background",
                    &cmd_for_audit,
                    &injection_audit,
                    &result,
                );
                return result;
            },
        };

        let stdout_buf: Arc<Mutex<VecDeque<u8>>> = Arc::new(Mutex::new(VecDeque::new()));
        let stderr_buf: Arc<Mutex<VecDeque<u8>>> = Arc::new(Mutex::new(VecDeque::new()));
        let mut managed = ManagedProcess {
            child: Some(child),
            stdout_buf: Arc::clone(&stdout_buf),
            stderr_buf: Arc::clone(&stderr_buf),
            command: command_str,
            creator: principal.clone(),
            injection_guard: Some(prepared.guard),
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

        let res = match self.resource_table.push(managed) {
            Ok(res) => res,
            Err(e) => {
                // The child has ALREADY forked (and is registered/kill-on-drop
                // via `managed`, which drops here). The spawn genuinely happened,
                // so audit it as a Failed spawn rather than returning with no
                // trace of the exec.
                let result: Result<Resource<ProcessHandle>, ErrorCode> =
                    Err(ErrorCode::Unknown(format!("resource table: {e}")));
                audit_spawn_result(
                    self,
                    "astrid:process/host.spawn-background",
                    &cmd_for_audit,
                    &injection_audit,
                    &result,
                );
                return result;
            },
        };
        self.process_count_total += 1;
        *self
            .process_count_by_principal
            .entry(principal)
            .or_insert(0) += 1;
        let result: Result<Resource<ProcessHandle>, ErrorCode> = Ok(Resource::new_own(res.rep()));
        audit_spawn_result(
            self,
            "astrid:process/host.spawn-background",
            &cmd_for_audit,
            &injection_audit,
            &result,
        );
        result
    }

    // ================================================================
    // PERSISTENT TIER — `astrid:process@1.0.0`.
    //
    // Backed by the host-owned `PersistentProcessRegistry`
    // (`self.persistent_processes`), shared across the capsule's pooled
    // instances so an id survives instance reset. Every id-keyed op
    // re-resolves the live `(principal, capsule)` and checks it against the
    // recorded creator inside the registry; unknown / wrong-owner /
    // wrong-capsule / reaped collapse to `no-such-process` with no oracle.
    //
    // Still deferred (and honest about it): `attach` (resource-handle
    // materialisation), `watch` / `unwatch` (host-published lifecycle events
    // — an OPEN publish-authority question in RFC host_abi; `status` + bounded
    // `wait` is the working alternative), and the `(NOT YET ...)` items the
    // WIT itself flags (resource-limit enforcement, cpu/mem stats, pollables).
    // ================================================================

    fn spawn_persistent(&mut self, request: SpawnRequest) -> Result<String, ErrorCode> {
        let cmd_for_audit = request.cmd.clone();
        let handle = self.runtime_handle.clone();
        let semaphore = self.blocking_semaphore.clone();

        // Capability gate FIRST — a capsule lacking `host_process` gets
        // `capability-denied` (consistent with `spawn` / `spawn-background`
        // and the WIT "Security-gated" header), BEFORE any persistence-
        // feasibility checks. Otherwise an ungranted capsule with no caller in
        // scope would observe `persist-unsupported` instead of the capability
        // error.
        let Some(sec) = self.security.clone() else {
            record_process_denied(
                self,
                "astrid:process/host.spawn-persistent",
                &cmd_for_audit,
                "no security gate configured",
            );
            return Err(ErrorCode::CapabilityDenied);
        };
        {
            let cmd = request.cmd.to_string();
            let cid = self.capsule_id.as_str().to_owned();
            let check = util::bounded_block_on(&handle, &semaphore, async move {
                sec.check_host_process(&cid, &cmd).await
            });
            if let Err(reason) = check {
                record_process_denied(
                    self,
                    "astrid:process/host.spawn-persistent",
                    &cmd_for_audit,
                    &reason,
                );
                return Err(ErrorCode::CapabilityDenied);
            }
        }

        // Persistent exec is an operator sub-grant ON TOP of `host_process`:
        // the capsule must also declare `allow_persistent` to spawn a child
        // that OUTLIVES the instance. `host_process` alone keeps only the
        // ephemeral `spawn` / `spawn-background`. Manifest-derived, so it's the
        // same capability set `enumerate-capabilities` reports.
        if !self
            .capability_names
            .iter()
            .any(|c| c == "allow_persistent")
        {
            record_process_denied(
                self,
                "astrid:process/host.spawn-persistent",
                &cmd_for_audit,
                "persistent exec requires the allow_persistent capability",
            );
            return Err(ErrorCode::CapabilityDenied);
        }

        // Persistence feasibility: refuse the owner-fallback principal — a
        // persistent id must be scoped to an authenticated principal, else
        // unauthenticated paths would share a `default` namespace that
        // `list-processes` enumerates.
        let Some(principal) = authenticated_principal(self) else {
            return Err(ErrorCode::PersistUnsupported);
        };
        // `some(0)` idle timeout is rejected per the WIT.
        if request.idle_timeout_ms == Some(0) {
            return Err(ErrorCode::InvalidInput);
        }
        if self.effective_cancel_token().is_cancelled() {
            return Err(ErrorCode::Cancelled);
        }

        // Snapshot + verify any read-only file injections. The guard is threaded
        // into the registry entry below so it lives as long as the persistent
        // process and is cleaned up by `reap_entry` (which consumes the entry by
        // value) on every reap path.
        let prepared = match inject::prepare_injections(&request.file_injections) {
            Ok(p) => p,
            Err(e) => {
                let result: Result<String, ErrorCode> = Err(e);
                audit_process(
                    self,
                    "astrid:process/host.spawn-persistent",
                    &cmd_for_audit,
                    &result,
                );
                return result;
            },
        };

        let capsule_id_arc: Arc<str> = Arc::from(self.capsule_id.as_str());
        let workspace_root = self.workspace_root.clone();
        // Per-principal concurrent cap, SHARED with `spawn-background`: subtract
        // this instance's live ephemeral handles so the registry's own check
        // (`registry-live < effective`) bounds the COMBINED count to the cap.
        let concurrent_cap =
            usize::try_from(self.effective_profile().quotas.max_background_processes)
                .unwrap_or(MAX_BACKGROUND_PROCESSES)
                .min(MAX_BACKGROUND_PROCESSES);
        let ephemeral_used = self
            .process_count_by_principal
            .get(&principal)
            .copied()
            .unwrap_or(0);
        let effective_cap = concurrent_cap.saturating_sub(ephemeral_used);

        // Reject an oversized stdin prelude BEFORE spawning (avoids orphaning).
        if request
            .stdin
            .as_ref()
            .is_some_and(|s| s.len() > MAX_SPAWN_STDIN_BYTES)
        {
            let result: Result<String, ErrorCode> = Err(ErrorCode::TooLarge);
            audit_process(
                self,
                "astrid:process/host.spawn-persistent",
                &cmd_for_audit,
                &result,
            );
            return result;
        }

        let want_stdin = request.keep_stdin_open.unwrap_or(false) || request.stdin.is_some();
        let mut child = match build_persistent_child(
            &request,
            &workspace_root,
            want_stdin,
            &prepared.sandbox,
            &prepared.env,
        ) {
            Ok(c) => c,
            Err(e) => {
                let result: Result<String, ErrorCode> = Err(e);
                audit_process(
                    self,
                    "astrid:process/host.spawn-persistent",
                    &cmd_for_audit,
                    &result,
                );
                return result;
            },
        };
        // Reject a missing/zero pid: `killpg(0)` / `kill(0)` would target the
        // daemon's OWN process group. A reaped child surfaces `None`; drop it
        // (kill_on_drop reaps) and fail rather than store an unsignalable entry.
        let Some(os_pid) = child.id().filter(|&p| p != 0) else {
            let result: Result<String, ErrorCode> = Err(ErrorCode::Unknown(
                "spawn-persistent: child has no usable pid".to_string(),
            ));
            audit_process(
                self,
                "astrid:process/host.spawn-persistent",
                &cmd_for_audit,
                &result,
            );
            return result;
        };
        let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
            return Err(ErrorCode::Unknown(
                "spawn-persistent: missing stdio pipes".to_string(),
            ));
        };
        let mut stdin = child.stdin.take();

        // Write the optional stdin prelude; on failure, fail the spawn (the
        // child drops on return → kill_on_drop reaps the orphan). Retain the
        // pipe ONLY when the guest asked to keep stdin open.
        if let (Some(prelude), Some(pipe)) = (request.stdin.clone(), stdin.take()) {
            let (pipe, write_res) = util::bounded_block_on(&handle, &semaphore, async move {
                use tokio::io::AsyncWriteExt as _;
                let mut pipe = pipe;
                let r = pipe.write_all(&prelude).await;
                (pipe, r)
            });
            if write_res.is_err() {
                let result: Result<String, ErrorCode> = Err(ErrorCode::Unknown(
                    "spawn-persistent: stdin prelude write failed".to_string(),
                ));
                audit_process(
                    self,
                    "astrid:process/host.spawn-persistent",
                    &cmd_for_audit,
                    &result,
                );
                return result;
            }
            stdin = Some(pipe);
        }
        let stdin_for_registry = if request.keep_stdin_open.unwrap_or(false) {
            stdin
        } else {
            None
        };

        let command = format!("{} {}", request.cmd, request.args.join(" "));
        let injection_audit = prepared.audit;
        let result = self.persistent_processes.spawn(persistent::SpawnParams {
            creator: principal,
            capsule_id: capsule_id_arc,
            command,
            os_pid,
            child,
            stdout,
            stderr,
            stdin: stdin_for_registry,
            concurrent_cap: effective_cap,
            label: request.label.clone(),
            overflow: request.overflow,
            log_ring_bytes: request.log_ring_bytes,
            max_lifetime_ms: request.max_lifetime_ms,
            idle_timeout_ms: request.idle_timeout_ms,
            exit_retention_ms: request.exit_retention_ms,
            injection_guard: Some(prepared.guard),
        });
        if !injection_audit.is_empty() {
            audit_process_injections(
                self,
                "astrid:process/host.spawn-persistent",
                &cmd_for_audit,
                &injection_audit,
                &result,
            );
            return result;
        }
        audit_process(
            self,
            "astrid:process/host.spawn-persistent",
            &cmd_for_audit,
            &result,
        );
        result
    }

    fn attach(&mut self, id: String) -> Result<Resource<ProcessHandle>, ErrorCode> {
        // Deferred: materialising a `process-handle` resource over a registry
        // entry needs dual-typed dispatch in the resource table. The id-keyed
        // free functions below ARE the documented `attach(id)?.method()`
        // equivalents, so the persistent tier is fully usable without it.
        let result: Result<Resource<ProcessHandle>, ErrorCode> = Err(ErrorCode::Unknown(
            "attach: resource-handle materialisation pending — use the id-keyed ops".to_string(),
        ));
        audit_process_id(self, "astrid:process/host.attach", &id, &result);
        result
    }

    fn list_processes(
        &mut self,
        label_filter: Option<String>,
    ) -> Result<Vec<ProcessInfo>, ErrorCode> {
        let principal = self.effective_principal();
        let capsule_id = self.capsule_id.as_str().to_owned();
        let result =
            Ok(self
                .persistent_processes
                .list(&principal, &capsule_id, label_filter.as_deref()));
        // Not id-keyed: audit the op + (non-secret) label filter, no id.
        audit_process(
            self,
            "astrid:process/host.list-processes",
            label_filter.as_deref().unwrap_or("*"),
            &result,
        );
        result
    }

    fn status(&mut self, id: String) -> Result<ProcessInfo, ErrorCode> {
        let principal = self.effective_principal();
        let capsule_id = self.capsule_id.as_str().to_owned();
        let result = self
            .persistent_processes
            .status(&id, &principal, &capsule_id);
        audit_process_id(self, "astrid:process/host.status", &id, &result);
        result
    }

    fn status_many(&mut self, ids: Vec<String>) -> Result<Vec<ProcessInfo>, ErrorCode> {
        let principal = self.effective_principal();
        let capsule_id = self.capsule_id.as_str().to_owned();
        let result = Ok(self
            .persistent_processes
            .status_many(&ids, &principal, &capsule_id));
        audit_process(
            self,
            "astrid:process/host.status-many",
            &format!("{} ids", ids.len()),
            &result,
        );
        result
    }

    fn read_logs(&mut self, id: String) -> Result<ReadLogsResult, ErrorCode> {
        let principal = self.effective_principal();
        let capsule_id = self.capsule_id.as_str().to_owned();
        let result = self
            .persistent_processes
            .read_logs(&id, &principal, &capsule_id);
        audit_process_id(self, "astrid:process/host.read-logs", &id, &result);
        result
    }

    fn read_since(
        &mut self,
        id: String,
        which_stream: LogStream,
        cursor: LogCursor,
        max_bytes: u32,
    ) -> Result<LogChunk, ErrorCode> {
        let principal = self.effective_principal();
        let capsule_id = self.capsule_id.as_str().to_owned();
        let result = self.persistent_processes.read_since(
            &id,
            &principal,
            &capsule_id,
            which_stream,
            &cursor,
            max_bytes,
        );
        audit_process_id(self, "astrid:process/host.read-since", &id, &result);
        result
    }

    fn write_stdin(&mut self, id: String, data: Vec<u8>) -> Result<u32, ErrorCode> {
        let principal = self.effective_principal();
        let capsule_id = self.capsule_id.as_str().to_owned();
        let handle = self.runtime_handle.clone();
        let semaphore = self.io_semaphore.clone();
        let registry = self.persistent_processes.clone();
        let id_for_audit = id.clone();
        let result = util::bounded_block_on(&handle, &semaphore, async move {
            registry
                .write_stdin(&id, &principal, &capsule_id, &data)
                .await
        });
        audit_process_id(
            self,
            "astrid:process/host.write-stdin",
            &id_for_audit,
            &result,
        );
        result
    }

    fn close_stdin(&mut self, id: String) -> Result<(), ErrorCode> {
        let principal = self.effective_principal();
        let capsule_id = self.capsule_id.as_str().to_owned();
        let result = self
            .persistent_processes
            .close_stdin(&id, &principal, &capsule_id);
        audit_process_id(self, "astrid:process/host.close-stdin", &id, &result);
        result
    }

    fn signal(&mut self, id: String, sig: ProcessSignal) -> Result<(), ErrorCode> {
        let principal = self.effective_principal();
        let capsule_id = self.capsule_id.as_str().to_owned();
        let result = self
            .persistent_processes
            .signal(&id, &principal, &capsule_id, sig);
        audit_process_id(self, "astrid:process/host.signal", &id, &result);
        result
    }

    fn wait(&mut self, id: String, timeout_ms: u64) -> Result<ExitInfo, ErrorCode> {
        let principal = self.effective_principal();
        let capsule_id = self.capsule_id.as_str().to_owned();
        let handle = self.runtime_handle.clone();
        let semaphore = self.blocking_semaphore.clone();
        let cancel = self.effective_cancel_token();
        let registry = self.persistent_processes.clone();
        let timeout = std::time::Duration::from_millis(timeout_ms);
        let id_for_audit = id.clone();
        let result = util::bounded_block_on_cancellable(&handle, &semaphore, &cancel, async move {
            registry.wait(&id, &principal, &capsule_id, timeout).await
        })
        .unwrap_or(Err(ErrorCode::Cancelled));
        audit_process_id(self, "astrid:process/host.wait", &id_for_audit, &result);
        result
    }

    fn stop(&mut self, id: String, grace_ms: Option<u64>) -> Result<ExitInfo, ErrorCode> {
        let principal = self.effective_principal();
        let capsule_id = self.capsule_id.as_str().to_owned();
        let handle = self.runtime_handle.clone();
        let semaphore = self.blocking_semaphore.clone();
        let cancel = self.effective_cancel_token();
        let registry = self.persistent_processes.clone();
        let grace = grace_ms.map(std::time::Duration::from_millis);
        let id_for_audit = id.clone();
        let result = util::bounded_block_on_cancellable(&handle, &semaphore, &cancel, async move {
            registry.stop(&id, &principal, &capsule_id, grace).await
        })
        .unwrap_or(Err(ErrorCode::Cancelled));
        audit_process_id(self, "astrid:process/host.stop", &id_for_audit, &result);
        result
    }

    fn release_process(&mut self, id: String) -> Result<(), ErrorCode> {
        let principal = self.effective_principal();
        let capsule_id = self.capsule_id.as_str().to_owned();
        let result = self
            .persistent_processes
            .release(&id, &principal, &capsule_id);
        audit_process_id(self, "astrid:process/host.release-process", &id, &result);
        result
    }

    fn watch(&mut self, id: String, _suffix: Option<String>) -> Result<(), ErrorCode> {
        // Deferred by design: host-published lifecycle events raise an OPEN
        // publish-authority question (manifest `[publish]` vs kernel-authored
        // topic class) tracked in RFC host_abi. `status` + bounded `wait` is
        // the working polling alternative until that resolves.
        let result: Result<(), ErrorCode> = Err(ErrorCode::Unknown(
            "watch: host lifecycle events deferred (publish-authority — RFC host_abi)".to_string(),
        ));
        audit_process_id(self, "astrid:process/host.watch", &id, &result);
        result
    }

    fn unwatch(&mut self, id: String) -> Result<(), ErrorCode> {
        // Idempotent: nothing is armed while `watch` is deferred.
        let result: Result<(), ErrorCode> = Ok(());
        audit_process_id(self, "astrid:process/host.unwatch", &id, &result);
        result
    }
}
