//! Shared `astrid:process@1.1.0` host implementation. The frozen `@1.0.0`
//! surface delegates through `compat.rs`; the resource table remains the
//! canonical storage for ephemeral process handles.

mod audit;
mod compat;
mod context;
mod handle;
mod inject;
mod managed;
mod persistent;
mod platform;
mod support;
mod tracker;

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use tracing::warn;
use wasmtime::component::Resource;

use crate::engine::wasm::bindings::astrid::process1_1_0::host::{
    self as process, ErrorCode, ExitInfo, LogChunk, LogCursor, LogStream, ProcessHandle,
    ProcessInfo, ProcessResult, ProcessSignal, ReadLogsResult, SpawnRequest,
};
use crate::engine::wasm::host::util;
use crate::engine::wasm::host_state::HostState;
use context::prepare_spawn_context;
use managed::{
    ForegroundProcess, ManagedProcess, PrepareCommandError, SandboxInputs, attach_pipes,
    build_persistent_child, configure_piped, prepare_sandboxed_command, write_background_stdin,
};
use support::{authenticated_principal, env_summary, extract_call_id, process_sandbox_policy};

pub(crate) use audit::{
    audit_process, audit_process_id, audit_process_injections, audit_process_signal,
    audit_spawn_result, record_process_denied,
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

        if request
            .stdin
            .as_ref()
            .is_some_and(|stdin| stdin.len() > MAX_SPAWN_STDIN_BYTES)
        {
            let result: Result<ProcessResult, ErrorCode> = Err(ErrorCode::TooLarge);
            audit_process(self, "astrid:process/host.spawn", &cmd_for_audit, &result);
            return result;
        }

        let spawn_context = match prepare_spawn_context(self, &request) {
            Ok(context) => context,
            Err(error) => {
                let result: Result<ProcessResult, ErrorCode> = Err(error);
                audit_process(self, "astrid:process/host.spawn", &cmd_for_audit, &result);
                return result;
            },
        };

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
            &spawn_context,
            SandboxInputs {
                workspace_root: &workspace_root,
                injections: &prepared.sandbox,
                inject_env: &injection_env,
                extra_masks: &self.spawn_mask_paths,
                policy: process_sandbox_policy(self),
            },
        ) {
            Ok(cmd) => cmd,
            Err(PrepareCommandError::SandboxDenied(reason)) => {
                record_process_denied(self, "astrid:process/host.spawn", &cmd_for_audit, &reason);
                return Err(ErrorCode::CapabilityDenied);
            },
            Err(PrepareCommandError::Invalid) => {
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
        configure_piped(&mut sandboxed_cmd);
        sandboxed_cmd.stdin(if request.stdin.is_some() {
            std::process::Stdio::piped()
        } else {
            std::process::Stdio::null()
        });

        let mut tokio_cmd = tokio::process::Command::from(sandboxed_cmd);
        tokio_cmd.kill_on_drop(true);
        let child = match tokio_cmd.spawn() {
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
        let foreground = match ForegroundProcess::new(child) {
            Ok(process) => process,
            Err(error) => {
                let result: Result<ProcessResult, ErrorCode> =
                    Err(ErrorCode::Unknown(format!("spawn failed: {error}")));
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
        let pid = foreground.pid();
        let tree = foreground.tree();
        process_tracker.register_tree(&tree, call_id);

        let stdin_prelude = request.stdin.unwrap_or_default();
        let output_result =
            util::bounded_block_on_cancellable(&handle, &semaphore, &cancel_token, async move {
                let mut foreground = foreground;
                foreground.write_stdin_prelude(&stdin_prelude).await?;
                foreground.wait_with_output().await
            });

        let result: Result<ProcessResult, ErrorCode> = match output_result {
            Some(Ok(output)) => {
                process_tracker.unregister_tree(&tree);
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
                process_tracker.unregister_tree(&tree);
                Err(ErrorCode::Unknown(format!("exec failed: {e}")))
            },
            None => {
                warn!(capsule_id = %self.capsule_id, pid, "process cancelled");
                process_tracker.unregister_tree(&tree);
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
        let cancel_token = self.effective_cancel_token();
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

        if request
            .stdin
            .as_ref()
            .is_some_and(|stdin| stdin.len() > MAX_SPAWN_STDIN_BYTES)
        {
            let result: Result<Resource<ProcessHandle>, ErrorCode> = Err(ErrorCode::TooLarge);
            audit_process(
                self,
                "astrid:process/host.spawn-background",
                &cmd_for_audit,
                &result,
            );
            return result;
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

        let spawn_context = match prepare_spawn_context(self, &request) {
            Ok(context) => context,
            Err(error) => {
                let result: Result<Resource<ProcessHandle>, ErrorCode> = Err(error);
                audit_process(
                    self,
                    "astrid:process/host.spawn-background",
                    &cmd_for_audit,
                    &result,
                );
                return result;
            },
        };

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
            &spawn_context,
            SandboxInputs {
                workspace_root: &workspace_root,
                injections: &prepared.sandbox,
                inject_env: &injection_env,
                extra_masks: &self.spawn_mask_paths,
                policy: process_sandbox_policy(self),
            },
        ) {
            Ok(cmd) => cmd,
            Err(PrepareCommandError::SandboxDenied(reason)) => {
                record_process_denied(
                    self,
                    "astrid:process/host.spawn-background",
                    &cmd_for_audit,
                    &reason,
                );
                return Err(ErrorCode::CapabilityDenied);
            },
            Err(PrepareCommandError::Invalid) => {
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
        sandboxed_cmd.stdin(if request.stdin.is_some() {
            std::process::Stdio::piped()
        } else {
            std::process::Stdio::null()
        });

        // Convert the prepared std::Command into a tokio::Command so the
        // spawned Child supports async wait(&mut self) without ownership
        // transfer (Gemini #752 finding — the previous std::Child path
        // stranded the handle inside spawn_blocking on timeout).
        // `kill_on_drop(true)` ensures the tokio runtime reaps the
        // zombie if `ManagedProcess` is dropped before the child exits.
        let mut tokio_cmd = tokio::process::Command::from(sandboxed_cmd);
        tokio_cmd.kill_on_drop(true);

        let mut child = match tokio_cmd.spawn() {
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
        let tree = match platform::ProcessTree::attach(&child) {
            Ok(tree) => tree,
            Err(error) => {
                let _ = child.start_kill();
                let result: Result<Resource<ProcessHandle>, ErrorCode> = Err(ErrorCode::Unknown(
                    format!("spawn-background ownership failed: {error}"),
                ));
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

        if let Err(error) = write_background_stdin(
            &handle,
            &semaphore,
            &cancel_token,
            &mut child,
            request.stdin,
        ) {
            let result: Result<Resource<ProcessHandle>, ErrorCode> =
                match tree.terminate(platform::Termination::Force) {
                    Ok(()) => Err(error),
                    Err(termination_error) => Err(ErrorCode::Unknown(format!(
                        "spawn-background input failed ({error:?}); tree cleanup failed: \
                         {termination_error:?}"
                    ))),
                };
            audit_spawn_result(
                self,
                "astrid:process/host.spawn-background",
                &cmd_for_audit,
                &injection_audit,
                &result,
            );
            return result;
        }

        let stdout_buf: Arc<Mutex<VecDeque<u8>>> = Arc::new(Mutex::new(VecDeque::new()));
        let stderr_buf: Arc<Mutex<VecDeque<u8>>> = Arc::new(Mutex::new(VecDeque::new()));
        let mut managed = ManagedProcess {
            child: Some(child),
            tree: Arc::clone(&tree),
            stdout_buf: Arc::clone(&stdout_buf),
            stderr_buf: Arc::clone(&stderr_buf),
            audit_descriptor: cmd_for_audit.clone(),
            creator: principal.clone(),
            injection_guard: Some(prepared.guard),
        };

        attach_pipes(&mut managed, &handle);

        // Register with the cancellation tracker so a
        // `tool.v1.request.cancel` event reaches the background
        // child. spawn-background does not currently propagate a
        // call_id (no caller_context payload to extract from in the
        // common case), so the entry is registered with None — which
        // makes it eligible for the "conservative fallback" branch of
        // `cancel_by_call_ids` (cancelled by any matching event).
        let res = match self.resource_table.push(managed) {
            Ok(res) => res,
            Err(e) => {
                // The child has already forked. Tracker registration deliberately
                // happens only after this insertion, so there is no stale tracker
                // entry to unregister; `managed` drops here and the explicit tree
                // termination covers descendants. Audit the real failed spawn.
                let cleanup = tree.terminate(platform::Termination::Force);
                let result: Result<Resource<ProcessHandle>, ErrorCode> =
                    Err(ErrorCode::Unknown(match cleanup {
                        Ok(()) => format!("resource table: {e}"),
                        Err(error) => {
                            format!("resource table: {e}; tree cleanup failed: {error:?}")
                        },
                    }));
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
        self.process_tracker.register_tree(&tree, None);
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

    // Persistent entries live in the host-owned registry shared by pooled
    // instances. Every id operation rechecks the principal and capsule owner;
    // unknown, wrong-owner, and reaped entries share one no-such-process result.

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

        let spawn_context = match prepare_spawn_context(self, &request) {
            Ok(context) => context,
            Err(error) => {
                let result: Result<String, ErrorCode> = Err(error);
                audit_process(
                    self,
                    "astrid:process/host.spawn-persistent",
                    &cmd_for_audit,
                    &result,
                );
                return result;
            },
        };

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
        let (mut child, tree) = match build_persistent_child(
            &request,
            &spawn_context,
            want_stdin,
            SandboxInputs {
                workspace_root: &workspace_root,
                injections: &prepared.sandbox,
                inject_env: &prepared.env,
                extra_masks: &self.spawn_mask_paths,
                policy: process_sandbox_policy(self),
            },
        ) {
            Ok(c) => c,
            Err(ErrorCode::CapabilityDenied) => {
                record_process_denied(
                    self,
                    "astrid:process/host.spawn-persistent",
                    &cmd_for_audit,
                    "native process sandbox is unavailable under required policy",
                );
                return Err(ErrorCode::CapabilityDenied);
            },
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
        let os_pid = tree.pid();
        let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
            tree.terminate(platform::Termination::Force)?;
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
                let result: Result<String, ErrorCode> =
                    match tree.terminate(platform::Termination::Force) {
                        Ok(()) => Err(ErrorCode::Unknown(
                            "spawn-persistent: stdin prelude write failed".to_string(),
                        )),
                        Err(error) => Err(ErrorCode::Unknown(format!(
                            "spawn-persistent: stdin prelude write failed; tree cleanup failed: \
                             {error:?}"
                        ))),
                    };
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
            tree,
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
        let id_hash = blake3::hash(id.as_bytes()).to_hex();
        let descriptor = format!("persistent:{}", &id_hash[..16]);
        if !platform::signal_supported(sig) {
            let result = Err(ErrorCode::CapabilityDenied);
            audit_process_signal(self, &descriptor, sig, &result);
            return result;
        }
        let principal = self.effective_principal();
        let capsule_id = self.capsule_id.as_str().to_owned();
        let result = self
            .persistent_processes
            .signal(&id, &principal, &capsule_id, sig);
        audit_process_signal(self, &descriptor, sig, &result);
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
