//! `HostProcessHandle` impl — methods on the `Resource<ProcessHandle>`.
//!
//! Live: `read-logs`, `wait`, `kill`, `signal`, `os-pid`.
//! Stubbed (return Unknown / CapabilityDenied): `write-stdin`,
//! `close-stdin`, `wait-with-output`, `subscribe-exit`, `subscribe-logs`.
//! These need:
//! - stdin pipe storage in ManagedProcess (write-stdin / close-stdin)
//! - pollable wiring (subscribe-*)
//! - wait_with_output requires re-architecting around the streaming
//!   reader tasks (the captured output is already drained piecemeal
//!   into the ring buffer; reassembling a one-shot final output across
//!   the wait/drain race is non-trivial)
//!
//! These are tracked for follow-up commits.

use wasmtime::component::Resource;
use wasmtime_wasi::p2::DynPollable;

use super::managed::{ManagedProcess, drain_buffer, kill_and_reap};
use crate::engine::wasm::bindings::astrid::process1_1_0::host::{
    ErrorCode, ExitInfo, HostProcessHandle, KillResult, ProcessHandle, ProcessResult,
    ProcessSignal, ReadLogsResult,
};
use crate::engine::wasm::host_state::HostState;

impl HostProcessHandle for HostState {
    fn read_logs(&mut self, self_: Resource<ProcessHandle>) -> Result<ReadLogsResult, ErrorCode> {
        let proc = self
            .resource_table
            .get_mut::<ManagedProcess>(&Resource::new_borrow(self_.rep()))
            .map_err(|_| ErrorCode::Closed)?;

        // `tokio::process::Child::try_wait` is non-blocking and
        // returns the exit status if the child has exited. Same
        // semantics as std::process::Child::try_wait.
        let mut exited = false;
        let (running, exit_code) = if let Some(child) = proc.child.as_mut() {
            match child.try_wait() {
                Ok(Some(status)) => {
                    #[cfg(windows)]
                    proc.tree.terminate(super::platform::Termination::Force)?;
                    exited = true;
                    proc.child.take();
                    (false, status.code())
                },
                Ok(None) => (true, None),
                Err(_) => {
                    #[cfg(windows)]
                    proc.tree.terminate(super::platform::Termination::Force)?;
                    exited = true;
                    proc.child.take();
                    (false, Some(-1))
                },
            }
        } else {
            (false, None)
        };
        if exited {
            self.process_tracker.unregister_tree(&proc.tree);
        }

        let stdout = drain_buffer(&proc.stdout_buf);
        let stderr = drain_buffer(&proc.stderr_buf);

        Ok(ReadLogsResult {
            stdout,
            stderr,
            running,
            exit: if running {
                None
            } else {
                Some(ExitInfo {
                    exit_code,
                    signal: None,
                })
            },
        })
    }

    fn write_stdin(
        &mut self,
        _self_: Resource<ProcessHandle>,
        _data: Vec<u8>,
    ) -> Result<u32, ErrorCode> {
        Err(ErrorCode::Unknown(
            "ProcessHandle.write-stdin: stdin pipe storage port pending".to_string(),
        ))
    }

    fn close_stdin(&mut self, _self_: Resource<ProcessHandle>) -> Result<(), ErrorCode> {
        Err(ErrorCode::Unknown(
            "ProcessHandle.close-stdin: stdin pipe storage port pending".to_string(),
        ))
    }

    fn signal(
        &mut self,
        self_: Resource<ProcessHandle>,
        sig: ProcessSignal,
    ) -> Result<(), ErrorCode> {
        if !super::platform::signal_supported(sig) {
            let result = Err(ErrorCode::CapabilityDenied);
            super::audit::audit_process_signal(self, "process-handle", sig, &result);
            return result;
        }
        let (command, result) = match self
            .resource_table
            .get::<ManagedProcess>(&Resource::new_borrow(self_.rep()))
        {
            Ok(proc) => {
                // `tokio::process::Child::id()` returns `None` once the
                // child has exited and been reaped.
                let result = proc
                    .child
                    .as_ref()
                    .and_then(tokio::process::Child::id)
                    .ok_or(ErrorCode::Closed)
                    .and_then(|_| super::platform::signal_root_process(&proc.tree, sig));
                (proc.audit_descriptor.clone(), result)
            },
            Err(_) => ("closed-process-handle".to_string(), Err(ErrorCode::Closed)),
        };
        super::audit::audit_process_signal(self, &command, sig, &result);
        result
    }

    fn kill(&mut self, self_: Resource<ProcessHandle>) -> Result<KillResult, ErrorCode> {
        let proc = self
            .resource_table
            .get_mut::<ManagedProcess>(&Resource::new_borrow(self_.rep()))
            .map_err(|_| ErrorCode::Closed)?;
        let (killed, exit_code) = match proc.child.take() {
            Some(mut child) => kill_and_reap(&mut child, &proc.tree)?,
            None => {
                proc.tree.terminate(super::platform::Termination::Force)?;
                (false, None)
            },
        };
        self.process_tracker.unregister_tree(&proc.tree);
        let stdout = drain_buffer(&proc.stdout_buf);
        let stderr = drain_buffer(&proc.stderr_buf);
        Ok(KillResult {
            killed,
            exit: Some(ExitInfo {
                exit_code,
                signal: None,
            }),
            stdout,
            stderr,
        })
    }

    fn wait(
        &mut self,
        self_: Resource<ProcessHandle>,
        timeout_ms: Option<u64>,
    ) -> Result<ExitInfo, ErrorCode> {
        let rt = self.runtime_handle.clone();
        let sem = self.blocking_semaphore.clone();
        let tok = self.effective_cancel_token();
        // Borrow the child from the resource table directly — no
        // `take()`. `tokio::process::Child::wait` is `&mut self`, so
        // we race it against the timeout without ever transferring
        // ownership. On timeout / cancel the child stays in the slot
        // and `kill` / `read-logs` / Drop continue to work; the
        // previous std::Child + spawn_blocking pattern stranded the
        // handle inside the blocking task (Gemini #752 finding).
        let proc = self
            .resource_table
            .get_mut::<ManagedProcess>(&Resource::new_borrow(self_.rep()))
            .map_err(|_| ErrorCode::Closed)?;
        let child = match proc.child.as_mut() {
            Some(c) => c,
            None => return Err(ErrorCode::Closed),
        };
        let result = crate::engine::wasm::host::util::bounded_block_on_cancellable(
            &rt,
            &sem,
            &tok,
            async move {
                match timeout_ms {
                    Some(ms) => match tokio::time::timeout(
                        std::time::Duration::from_millis(ms),
                        child.wait(),
                    )
                    .await
                    {
                        Ok(Ok(status)) => Ok(status.code()),
                        Ok(Err(e)) => Err(ErrorCode::Unknown(format!("wait: {e}"))),
                        Err(_) => Err(ErrorCode::WaitTimeout),
                    },
                    None => match child.wait().await {
                        Ok(status) => Ok(status.code()),
                        Err(e) => Err(ErrorCode::Unknown(format!("wait: {e}"))),
                    },
                }
            },
        );

        // On a successful wait, the child has been reaped — clear the
        // slot so a subsequent `wait` doesn't observe a stale Child
        // that the OS no longer knows about.
        let succeeded = matches!(result, Some(Ok(_)));
        if succeeded {
            #[cfg(windows)]
            proc.tree.terminate(super::platform::Termination::Force)?;
            proc.child.take();
            self.process_tracker.unregister_tree(&proc.tree);
        }

        match result {
            Some(Ok(code)) => Ok(ExitInfo {
                exit_code: code,
                signal: None,
            }),
            Some(Err(e)) => Err(e),
            None => Err(ErrorCode::Cancelled),
        }
    }

    fn wait_with_output(
        &mut self,
        _self_: Resource<ProcessHandle>,
        _timeout_ms: Option<u64>,
    ) -> Result<ProcessResult, ErrorCode> {
        Err(ErrorCode::Unknown(
            "ProcessHandle.wait-with-output: atomic drain port pending".to_string(),
        ))
    }

    fn os_pid(&mut self, self_: Resource<ProcessHandle>) -> Result<u32, ErrorCode> {
        let proc = self
            .resource_table
            .get::<ManagedProcess>(&Resource::new_borrow(self_.rep()))
            .map_err(|_| ErrorCode::Closed)?;
        proc.child
            .as_ref()
            .and_then(tokio::process::Child::id)
            .ok_or(ErrorCode::Closed)
    }

    fn subscribe_exit(&mut self, _self_: Resource<ProcessHandle>) -> Resource<DynPollable> {
        // Real wiring (sourced from try_wait readiness on the child)
        // lands with the pollable commit. Always-ready sentinel until
        // then — guests poll, then `wait` blocks on the actual exit.
        super::super::stubs::always_ready_pollable(&mut self.resource_table)
    }

    fn subscribe_logs(&mut self, _self_: Resource<ProcessHandle>) -> Resource<DynPollable> {
        // Same pattern — guests poll, then `read-logs` drains whatever
        // the reader task has buffered (or returns empty if nothing
        // is available yet, which is honest non-blocking semantics).
        super::super::stubs::always_ready_pollable(&mut self.resource_table)
    }

    fn drop(&mut self, rep: Resource<ProcessHandle>) -> wasmtime::Result<()> {
        // Pull the entry out of the table first so the cancellation
        // tracker can be updated *before* `ManagedProcess::Drop` kills
        // the child — otherwise a `tool.v1.request.cancel` event
        // landing simultaneously would chase a freshly-reused PID.
        if let Ok(managed) = self
            .resource_table
            .delete::<ManagedProcess>(Resource::new_own(rep.rep()))
        {
            self.process_tracker.unregister_tree(&managed.tree);
            self.process_count_total = self.process_count_total.saturating_sub(1);
            if let Some(count) = self.process_count_by_principal.get_mut(&managed.creator) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    self.process_count_by_principal.remove(&managed.creator);
                }
            }
            // Dropping `managed` here kills and reaps any still-live
            // child via `Drop for ManagedProcess`.
            drop(managed);
        }
        Ok(())
    }
}
