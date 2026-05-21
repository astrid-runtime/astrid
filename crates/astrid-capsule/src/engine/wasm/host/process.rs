//! `astrid:process@1.0.0` host implementation.
//!
//! STUB SHELL — trait shape matches the new WIT but all methods return
//! `todo!()`. The previous 971-line implementation (sandbox-exec/bwrap
//! wrappers, ManagedProcess tracking, log streaming) ports back in a
//! follow-up commit alongside the ProcessHandle resource integration.

use std::collections::HashSet;
use std::sync::Mutex;

use wasmtime::component::Resource;
use wasmtime_wasi::p2::DynPollable;

use crate::engine::wasm::bindings::astrid::process::host::{
    self as process, ErrorCode, ExitInfo, HostProcessHandle, KillResult, ProcessHandle,
    ProcessResult, ProcessSignal, ReadLogsResult, SpawnRequest,
};
use crate::engine::wasm::host_state::HostState;

/// A managed background process placeholder.
#[derive(Debug)]
pub struct ManagedProcess {
    // Intentionally empty — fields restored when full impl ports back.
}

impl Drop for ManagedProcess {
    fn drop(&mut self) {}
}

/// Cancellation tracker for child PIDs.
#[derive(Debug, Default)]
pub struct ProcessTracker {
    pids: Mutex<HashSet<u32>>,
}

impl ProcessTracker {
    /// Construct a fresh tracker.
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, pid: u32) {
        let _ = self.pids.lock().map(|mut s| s.insert(pid));
    }

    pub fn unregister(&self, pid: u32) {
        let _ = self.pids.lock().map(|mut s| s.remove(&pid));
    }

    pub fn cancel_all(&self) {
        // No-op until full impl ports back.
    }

    /// Cancel processes matched by the given call IDs.
    ///
    /// Restored stub for call-site compatibility; real cancellation
    /// returns when the spawn host fns port back. The runtime handle
    /// argument is preserved so the real impl can spawn termination
    /// tasks on the right executor.
    pub fn cancel_by_call_ids(&self, _ids: &[String], _rt: &tokio::runtime::Handle) -> Vec<u32> {
        Vec::new()
    }
}

impl process::Host for HostState {
    fn spawn(&mut self, _request: SpawnRequest) -> Result<ProcessResult, ErrorCode> {
        todo!("process.spawn: sandbox-exec / bwrap port pending")
    }

    fn spawn_background(
        &mut self,
        _request: SpawnRequest,
    ) -> Result<Resource<ProcessHandle>, ErrorCode> {
        todo!("process.spawn_background: ProcessHandle resource port pending")
    }
}

impl HostProcessHandle for HostState {
    fn read_logs(&mut self, _self_: Resource<ProcessHandle>) -> Result<ReadLogsResult, ErrorCode> {
        todo!("ProcessHandle.read_logs: ring-buffer port pending")
    }

    fn write_stdin(
        &mut self,
        _self_: Resource<ProcessHandle>,
        _data: Vec<u8>,
    ) -> Result<u32, ErrorCode> {
        todo!("ProcessHandle.write_stdin: stdin pipe port pending")
    }

    fn close_stdin(&mut self, _self_: Resource<ProcessHandle>) -> Result<(), ErrorCode> {
        todo!("ProcessHandle.close_stdin: pipe close pending")
    }

    fn signal(
        &mut self,
        _self_: Resource<ProcessHandle>,
        _sig: ProcessSignal,
    ) -> Result<(), ErrorCode> {
        todo!("ProcessHandle.signal: signal dispatch pending")
    }

    fn kill(&mut self, _self_: Resource<ProcessHandle>) -> Result<KillResult, ErrorCode> {
        todo!("ProcessHandle.kill: SIGKILL + drain pending")
    }

    fn wait(
        &mut self,
        _self_: Resource<ProcessHandle>,
        _timeout_ms: Option<u64>,
    ) -> Result<ExitInfo, ErrorCode> {
        todo!("ProcessHandle.wait: child reap pending")
    }

    fn wait_with_output(
        &mut self,
        _self_: Resource<ProcessHandle>,
        _timeout_ms: Option<u64>,
    ) -> Result<ProcessResult, ErrorCode> {
        todo!("ProcessHandle.wait_with_output: atomic drain pending")
    }

    fn os_pid(&mut self, _self_: Resource<ProcessHandle>) -> Result<u32, ErrorCode> {
        todo!("ProcessHandle.os_pid: PID accessor pending")
    }

    fn subscribe_exit(&mut self, _self_: Resource<ProcessHandle>) -> Resource<DynPollable> {
        todo!("ProcessHandle.subscribe_exit: pollable pending")
    }

    fn subscribe_logs(&mut self, _self_: Resource<ProcessHandle>) -> Resource<DynPollable> {
        todo!("ProcessHandle.subscribe_logs: pollable pending")
    }

    fn drop(&mut self, _rep: Resource<ProcessHandle>) -> wasmtime::Result<()> {
        Ok(())
    }
}
