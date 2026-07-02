//! `astrid:process@1.0.0` compatibility shims.
//!
//! Both contract versions are backed by ONE implementation. The real backend
//! lives in `mod.rs` / `handle.rs` behind the `@1.1.0` trait impls (aliased
//! `v11` here); `@1.1.0` is the SUPERSET — it carries the per-spawn read-only
//! `file-injection` surface (#881) that `@1.0.0` never had.
//!
//! The `@1.0.0` `Host` / `HostProcessHandle` impls below are THIN SHIMS: every
//! method converts the `@1.0.0` record/enum shapes to their `@1.1.0` twins,
//! delegates to the `@1.1.0` impl, and converts the result back. `spawn`,
//! `spawn-background`, and `spawn-persistent` build a `@1.1.0` `spawn-request`
//! with an EMPTY `file-injections` list — so on the `@1.0.0` path spawn behaves
//! exactly as spawn-with-no-injections, reproducing the published behaviour. No
//! spawn logic is duplicated; audit / capability / quota paths are shared and
//! version-agnostic (they run inside the `@1.1.0` impl).
//!
//! Why this exists: the injection extension originally landed in-place on the
//! frozen `astrid:process@1.0.0` WIT (wit#15), which structurally broke every
//! capsule built against the published contract — the component-model linker
//! matches package versions by structure, so a capsule importing the old
//! `spawn-request` shape no longer found a matching host implementation
//! (#1107). Restoring `@1.0.0` to its published shape and re-homing the
//! extension on an additive `@1.1.0` (wit#19) lets old and new capsules coexist
//! off the same linker.
//!
//! Resource bridging: `process-handle` is a host-owned resource stored in the
//! shared resource table as a concrete `ManagedProcess`, keyed by rep. The
//! `@1.0.0` and `@1.1.0` `ProcessHandle` marker types are distinct zero-sized
//! bindgen structs over the SAME rep space, so `Resource::new_*` re-tags a
//! handle between versions for free (same pattern as `http`'s `HttpStream`).

use wasmtime::component::Resource;
use wasmtime_wasi::p2::DynPollable;

use crate::engine::wasm::bindings::astrid::process1_0_0::host as v10;
use crate::engine::wasm::bindings::astrid::process1_1_0::host as v11;
use crate::engine::wasm::host_state::HostState;

// ── @1.1.0 ⇄ @1.0.0 type bridging ──────────────────────────────────────
//
// The two contract versions generate DISTINCT Rust types for every shared
// shape. Only `spawn-request` differs structurally (`@1.1.0` adds
// `file-injections`); the rest are field-for-field identical but nominally
// separate, so each still needs an explicit boundary conversion.

/// Map a `@1.1.0` `error-code` back to the `@1.0.0` arm set. The arms are
/// identical between versions (the injection extension added no error-code),
/// so this is a total 1:1 mapping — no wildcard, so a future `@1.1.0`-only arm
/// forces a compile error here rather than a silent mis-map.
pub(super) fn err_v11_to_v10(e: v11::ErrorCode) -> v10::ErrorCode {
    match e {
        v11::ErrorCode::CapabilityDenied => v10::ErrorCode::CapabilityDenied,
        v11::ErrorCode::InvalidInput => v10::ErrorCode::InvalidInput,
        v11::ErrorCode::BoundaryEscape => v10::ErrorCode::BoundaryEscape,
        v11::ErrorCode::Quota => v10::ErrorCode::Quota,
        v11::ErrorCode::TooLarge => v10::ErrorCode::TooLarge,
        v11::ErrorCode::Closed => v10::ErrorCode::Closed,
        v11::ErrorCode::Cancelled => v10::ErrorCode::Cancelled,
        v11::ErrorCode::WaitTimeout => v10::ErrorCode::WaitTimeout,
        v11::ErrorCode::NoSuchProcess => v10::ErrorCode::NoSuchProcess,
        v11::ErrorCode::RegistryFull => v10::ErrorCode::RegistryFull,
        v11::ErrorCode::PersistUnsupported => v10::ErrorCode::PersistUnsupported,
        v11::ErrorCode::Unknown(s) => v10::ErrorCode::Unknown(s),
    }
}

fn exit_v11_to_v10(e: v11::ExitInfo) -> v10::ExitInfo {
    v10::ExitInfo {
        exit_code: e.exit_code,
        signal: e.signal,
    }
}

fn process_result_v11_to_v10(r: v11::ProcessResult) -> v10::ProcessResult {
    v10::ProcessResult {
        stdout: r.stdout,
        stderr: r.stderr,
        exit: exit_v11_to_v10(r.exit),
    }
}

fn read_logs_v11_to_v10(r: v11::ReadLogsResult) -> v10::ReadLogsResult {
    v10::ReadLogsResult {
        stdout: r.stdout,
        stderr: r.stderr,
        running: r.running,
        exit: r.exit.map(exit_v11_to_v10),
    }
}

fn kill_result_v11_to_v10(r: v11::KillResult) -> v10::KillResult {
    v10::KillResult {
        killed: r.killed,
        exit: r.exit.map(exit_v11_to_v10),
        stdout: r.stdout,
        stderr: r.stderr,
    }
}

fn phase_v11_to_v10(p: v11::ProcessPhase) -> v10::ProcessPhase {
    match p {
        v11::ProcessPhase::Starting => v10::ProcessPhase::Starting,
        v11::ProcessPhase::Running => v10::ProcessPhase::Running,
        v11::ProcessPhase::Exited => v10::ProcessPhase::Exited,
    }
}

fn process_info_v11_to_v10(i: v11::ProcessInfo) -> v10::ProcessInfo {
    v10::ProcessInfo {
        id: i.id,
        label: i.label,
        command: i.command,
        os_pid: i.os_pid,
        phase: phase_v11_to_v10(i.phase),
        exit: i.exit.map(exit_v11_to_v10),
        age_ms: i.age_ms,
        idle_ms: i.idle_ms,
        buffered_bytes: i.buffered_bytes,
        bytes_dropped: i.bytes_dropped,
        stdin_open: i.stdin_open,
        cpu_ms: i.cpu_ms,
        mem_bytes_peak: i.mem_bytes_peak,
    }
}

fn cursor_v11_to_v10(c: v11::LogCursor) -> v10::LogCursor {
    v10::LogCursor { token: c.token }
}

fn cursor_v10_to_v11(c: v10::LogCursor) -> v11::LogCursor {
    v11::LogCursor { token: c.token }
}

fn log_chunk_v11_to_v10(c: v11::LogChunk) -> v10::LogChunk {
    v10::LogChunk {
        data: c.data,
        next: cursor_v11_to_v10(c.next),
        bytes_dropped: c.bytes_dropped,
        drained_eof: c.drained_eof,
    }
}

fn log_stream_v10_to_v11(s: v10::LogStream) -> v11::LogStream {
    match s {
        v10::LogStream::Stdout => v11::LogStream::Stdout,
        v10::LogStream::Stderr => v11::LogStream::Stderr,
    }
}

fn signal_v10_to_v11(s: v10::ProcessSignal) -> v11::ProcessSignal {
    match s {
        v10::ProcessSignal::Term => v11::ProcessSignal::Term,
        v10::ProcessSignal::Hup => v11::ProcessSignal::Hup,
        v10::ProcessSignal::Usr1 => v11::ProcessSignal::Usr1,
        v10::ProcessSignal::Usr2 => v11::ProcessSignal::Usr2,
        v10::ProcessSignal::Int => v11::ProcessSignal::Int,
        v10::ProcessSignal::Stop => v11::ProcessSignal::Stop,
        v10::ProcessSignal::Cont => v11::ProcessSignal::Cont,
    }
}

fn env_var_v10_to_v11(e: v10::EnvVar) -> v11::EnvVar {
    v11::EnvVar {
        key: e.key,
        value: e.value,
    }
}

fn overflow_v10_to_v11(o: v10::OverflowPolicy) -> v11::OverflowPolicy {
    match o {
        v10::OverflowPolicy::DropOldest => v11::OverflowPolicy::DropOldest,
        v10::OverflowPolicy::Backpressure => v11::OverflowPolicy::Backpressure,
    }
}

fn resource_limits_v10_to_v11(l: v10::ResourceLimits) -> v11::ResourceLimits {
    v11::ResourceLimits {
        max_memory_bytes: l.max_memory_bytes,
        max_cpu_secs: l.max_cpu_secs,
        max_pids: l.max_pids,
        max_open_files: l.max_open_files,
    }
}

/// Map a `@1.0.0` `spawn-request` to `@1.1.0` with an EMPTY `file-injections`
/// list. Empty injections == the published `@1.0.0` behaviour: the host
/// snapshots/binds nothing extra into the child's sandbox.
fn spawn_request_v10_to_v11(r: v10::SpawnRequest) -> v11::SpawnRequest {
    v11::SpawnRequest {
        cmd: r.cmd,
        args: r.args,
        stdin: r.stdin,
        env: r.env.into_iter().map(env_var_v10_to_v11).collect(),
        cwd: r.cwd,
        limits: r.limits.map(resource_limits_v10_to_v11),
        label: r.label,
        keep_stdin_open: r.keep_stdin_open,
        overflow: r.overflow.map(overflow_v10_to_v11),
        log_ring_bytes: r.log_ring_bytes,
        max_lifetime_ms: r.max_lifetime_ms,
        idle_timeout_ms: r.idle_timeout_ms,
        exit_retention_ms: r.exit_retention_ms,
        // `@1.0.0` has no injection surface: the child sees exactly what its
        // args / env / cwd / stdin dictate, nothing host-injected.
        file_injections: Vec::new(),
    }
}

/// Re-tag a `@1.0.0` handle as the `@1.1.0` marker over the SAME rep. Both
/// index one `ManagedProcess` in the shared resource table, so this is a
/// zero-cost nominal re-tag, not a table operation.
fn handle_v10_to_v11(h: &Resource<v10::ProcessHandle>) -> Resource<v11::ProcessHandle> {
    Resource::new_borrow(h.rep())
}

// ── @1.0.0 host impl (thin shims over the @1.1.0 backend) ───────────────

impl v10::Host for HostState {
    fn spawn(&mut self, request: v10::SpawnRequest) -> Result<v10::ProcessResult, v10::ErrorCode> {
        v11::Host::spawn(self, spawn_request_v10_to_v11(request))
            .map(process_result_v11_to_v10)
            .map_err(err_v11_to_v10)
    }

    fn spawn_background(
        &mut self,
        request: v10::SpawnRequest,
    ) -> Result<Resource<v10::ProcessHandle>, v10::ErrorCode> {
        match v11::Host::spawn_background(self, spawn_request_v10_to_v11(request)) {
            Ok(h) => Ok(Resource::new_own(h.rep())),
            Err(e) => Err(err_v11_to_v10(e)),
        }
    }

    fn spawn_persistent(&mut self, request: v10::SpawnRequest) -> Result<String, v10::ErrorCode> {
        v11::Host::spawn_persistent(self, spawn_request_v10_to_v11(request)).map_err(err_v11_to_v10)
    }

    fn attach(&mut self, id: String) -> Result<Resource<v10::ProcessHandle>, v10::ErrorCode> {
        match v11::Host::attach(self, id) {
            Ok(h) => Ok(Resource::new_own(h.rep())),
            Err(e) => Err(err_v11_to_v10(e)),
        }
    }

    fn list_processes(
        &mut self,
        label_filter: Option<String>,
    ) -> Result<Vec<v10::ProcessInfo>, v10::ErrorCode> {
        v11::Host::list_processes(self, label_filter)
            .map(|v| v.into_iter().map(process_info_v11_to_v10).collect())
            .map_err(err_v11_to_v10)
    }

    fn status(&mut self, id: String) -> Result<v10::ProcessInfo, v10::ErrorCode> {
        v11::Host::status(self, id)
            .map(process_info_v11_to_v10)
            .map_err(err_v11_to_v10)
    }

    fn status_many(&mut self, ids: Vec<String>) -> Result<Vec<v10::ProcessInfo>, v10::ErrorCode> {
        v11::Host::status_many(self, ids)
            .map(|v| v.into_iter().map(process_info_v11_to_v10).collect())
            .map_err(err_v11_to_v10)
    }

    fn read_logs(&mut self, id: String) -> Result<v10::ReadLogsResult, v10::ErrorCode> {
        v11::Host::read_logs(self, id)
            .map(read_logs_v11_to_v10)
            .map_err(err_v11_to_v10)
    }

    fn read_since(
        &mut self,
        id: String,
        which_stream: v10::LogStream,
        cursor: v10::LogCursor,
        max_bytes: u32,
    ) -> Result<v10::LogChunk, v10::ErrorCode> {
        v11::Host::read_since(
            self,
            id,
            log_stream_v10_to_v11(which_stream),
            cursor_v10_to_v11(cursor),
            max_bytes,
        )
        .map(log_chunk_v11_to_v10)
        .map_err(err_v11_to_v10)
    }

    fn write_stdin(&mut self, id: String, data: Vec<u8>) -> Result<u32, v10::ErrorCode> {
        v11::Host::write_stdin(self, id, data).map_err(err_v11_to_v10)
    }

    fn close_stdin(&mut self, id: String) -> Result<(), v10::ErrorCode> {
        v11::Host::close_stdin(self, id).map_err(err_v11_to_v10)
    }

    fn signal(&mut self, id: String, sig: v10::ProcessSignal) -> Result<(), v10::ErrorCode> {
        v11::Host::signal(self, id, signal_v10_to_v11(sig)).map_err(err_v11_to_v10)
    }

    fn wait(&mut self, id: String, timeout_ms: u64) -> Result<v10::ExitInfo, v10::ErrorCode> {
        v11::Host::wait(self, id, timeout_ms)
            .map(exit_v11_to_v10)
            .map_err(err_v11_to_v10)
    }

    fn stop(&mut self, id: String, grace_ms: Option<u64>) -> Result<v10::ExitInfo, v10::ErrorCode> {
        v11::Host::stop(self, id, grace_ms)
            .map(exit_v11_to_v10)
            .map_err(err_v11_to_v10)
    }

    fn release_process(&mut self, id: String) -> Result<(), v10::ErrorCode> {
        v11::Host::release_process(self, id).map_err(err_v11_to_v10)
    }

    fn watch(&mut self, id: String, suffix: Option<String>) -> Result<(), v10::ErrorCode> {
        v11::Host::watch(self, id, suffix).map_err(err_v11_to_v10)
    }

    fn unwatch(&mut self, id: String) -> Result<(), v10::ErrorCode> {
        v11::Host::unwatch(self, id).map_err(err_v11_to_v10)
    }
}

impl v10::HostProcessHandle for HostState {
    fn read_logs(
        &mut self,
        self_: Resource<v10::ProcessHandle>,
    ) -> Result<v10::ReadLogsResult, v10::ErrorCode> {
        v11::HostProcessHandle::read_logs(self, handle_v10_to_v11(&self_))
            .map(read_logs_v11_to_v10)
            .map_err(err_v11_to_v10)
    }

    fn write_stdin(
        &mut self,
        self_: Resource<v10::ProcessHandle>,
        data: Vec<u8>,
    ) -> Result<u32, v10::ErrorCode> {
        v11::HostProcessHandle::write_stdin(self, handle_v10_to_v11(&self_), data)
            .map_err(err_v11_to_v10)
    }

    fn close_stdin(&mut self, self_: Resource<v10::ProcessHandle>) -> Result<(), v10::ErrorCode> {
        v11::HostProcessHandle::close_stdin(self, handle_v10_to_v11(&self_)).map_err(err_v11_to_v10)
    }

    fn signal(
        &mut self,
        self_: Resource<v10::ProcessHandle>,
        sig: v10::ProcessSignal,
    ) -> Result<(), v10::ErrorCode> {
        v11::HostProcessHandle::signal(self, handle_v10_to_v11(&self_), signal_v10_to_v11(sig))
            .map_err(err_v11_to_v10)
    }

    fn kill(
        &mut self,
        self_: Resource<v10::ProcessHandle>,
    ) -> Result<v10::KillResult, v10::ErrorCode> {
        v11::HostProcessHandle::kill(self, handle_v10_to_v11(&self_))
            .map(kill_result_v11_to_v10)
            .map_err(err_v11_to_v10)
    }

    fn wait(
        &mut self,
        self_: Resource<v10::ProcessHandle>,
        timeout_ms: Option<u64>,
    ) -> Result<v10::ExitInfo, v10::ErrorCode> {
        v11::HostProcessHandle::wait(self, handle_v10_to_v11(&self_), timeout_ms)
            .map(exit_v11_to_v10)
            .map_err(err_v11_to_v10)
    }

    fn wait_with_output(
        &mut self,
        self_: Resource<v10::ProcessHandle>,
        timeout_ms: Option<u64>,
    ) -> Result<v10::ProcessResult, v10::ErrorCode> {
        v11::HostProcessHandle::wait_with_output(self, handle_v10_to_v11(&self_), timeout_ms)
            .map(process_result_v11_to_v10)
            .map_err(err_v11_to_v10)
    }

    fn os_pid(&mut self, self_: Resource<v10::ProcessHandle>) -> Result<u32, v10::ErrorCode> {
        v11::HostProcessHandle::os_pid(self, handle_v10_to_v11(&self_)).map_err(err_v11_to_v10)
    }

    fn subscribe_exit(&mut self, self_: Resource<v10::ProcessHandle>) -> Resource<DynPollable> {
        v11::HostProcessHandle::subscribe_exit(self, handle_v10_to_v11(&self_))
    }

    fn subscribe_logs(&mut self, self_: Resource<v10::ProcessHandle>) -> Resource<DynPollable> {
        v11::HostProcessHandle::subscribe_logs(self, handle_v10_to_v11(&self_))
    }

    fn drop(&mut self, rep: Resource<v10::ProcessHandle>) -> wasmtime::Result<()> {
        // Own re-tag: the `@1.1.0` drop consumes the handle and deletes the
        // backing `ManagedProcess` from the shared table by rep.
        v11::HostProcessHandle::drop(self, Resource::new_own(rep.rep()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every `@1.1.0` error arm maps to the identically-named `@1.0.0` arm.
    /// The two arm sets are equal (injection added no error-code), so this is
    /// a faithful 1:1 — mirrors http's `v11_error_maps_to_v10_arm_set`.
    #[test]
    fn err_v11_to_v10_is_total_and_identity() {
        use v10::ErrorCode as A;
        use v11::ErrorCode as B;
        assert!(matches!(
            err_v11_to_v10(B::CapabilityDenied),
            A::CapabilityDenied
        ));
        assert!(matches!(err_v11_to_v10(B::InvalidInput), A::InvalidInput));
        assert!(matches!(
            err_v11_to_v10(B::BoundaryEscape),
            A::BoundaryEscape
        ));
        assert!(matches!(err_v11_to_v10(B::Quota), A::Quota));
        assert!(matches!(err_v11_to_v10(B::TooLarge), A::TooLarge));
        assert!(matches!(err_v11_to_v10(B::Closed), A::Closed));
        assert!(matches!(err_v11_to_v10(B::Cancelled), A::Cancelled));
        assert!(matches!(err_v11_to_v10(B::WaitTimeout), A::WaitTimeout));
        assert!(matches!(err_v11_to_v10(B::NoSuchProcess), A::NoSuchProcess));
        assert!(matches!(err_v11_to_v10(B::RegistryFull), A::RegistryFull));
        assert!(matches!(
            err_v11_to_v10(B::PersistUnsupported),
            A::PersistUnsupported
        ));
        match err_v11_to_v10(B::Unknown("boom".into())) {
            A::Unknown(s) => assert_eq!(s, "boom"),
            other => panic!("Unknown did not round-trip: {other:?}"),
        }
    }

    /// A `@1.0.0` spawn becomes a `@1.1.0` spawn-with-NO-injections, with every
    /// other field carried through byte-for-byte. This is the core compat
    /// invariant: old capsules get exactly their published spawn semantics.
    #[test]
    fn v10_spawn_request_becomes_v11_with_empty_injections() {
        let req = v10::SpawnRequest {
            cmd: "echo".into(),
            args: vec!["hi".into(), "there".into()],
            stdin: Some(vec![1, 2, 3]),
            env: vec![v10::EnvVar {
                key: "K".into(),
                value: "V".into(),
            }],
            cwd: Some("sub/dir".into()),
            limits: Some(v10::ResourceLimits {
                max_memory_bytes: Some(1024),
                max_cpu_secs: Some(5),
                max_pids: Some(8),
                max_open_files: Some(64),
            }),
            label: Some("job".into()),
            keep_stdin_open: Some(true),
            overflow: Some(v10::OverflowPolicy::Backpressure),
            log_ring_bytes: Some(4096),
            max_lifetime_ms: Some(60_000),
            idle_timeout_ms: Some(30_000),
            exit_retention_ms: Some(15_000),
        };

        let out = spawn_request_v10_to_v11(req);

        assert!(
            out.file_injections.is_empty(),
            "@1.0.0 spawn must inject nothing"
        );
        assert_eq!(out.cmd, "echo");
        assert_eq!(out.args, vec!["hi".to_string(), "there".to_string()]);
        assert_eq!(out.stdin, Some(vec![1, 2, 3]));
        assert_eq!(out.env.len(), 1);
        assert_eq!(out.env[0].key, "K");
        assert_eq!(out.env[0].value, "V");
        assert_eq!(out.cwd.as_deref(), Some("sub/dir"));
        let limits = out.limits.expect("limits preserved");
        assert_eq!(limits.max_memory_bytes, Some(1024));
        assert_eq!(limits.max_cpu_secs, Some(5));
        assert_eq!(limits.max_pids, Some(8));
        assert_eq!(limits.max_open_files, Some(64));
        assert_eq!(out.label.as_deref(), Some("job"));
        assert_eq!(out.keep_stdin_open, Some(true));
        assert!(matches!(
            out.overflow,
            Some(v11::OverflowPolicy::Backpressure)
        ));
        assert_eq!(out.log_ring_bytes, Some(4096));
        assert_eq!(out.max_lifetime_ms, Some(60_000));
        assert_eq!(out.idle_timeout_ms, Some(30_000));
        assert_eq!(out.exit_retention_ms, Some(15_000));
    }

    /// A fully-populated `@1.1.0` `process-info` round-trips to `@1.0.0` with
    /// every field and the phase enum preserved.
    #[test]
    fn process_info_round_trips_v11_to_v10() {
        let info = v11::ProcessInfo {
            id: "abc".into(),
            label: "svc".into(),
            command: "sleep 1".into(),
            os_pid: Some(4321),
            phase: v11::ProcessPhase::Running,
            exit: Some(v11::ExitInfo {
                exit_code: Some(0),
                signal: None,
            }),
            age_ms: 100,
            idle_ms: 10,
            buffered_bytes: 2048,
            bytes_dropped: 3,
            stdin_open: true,
            cpu_ms: Some(7),
            mem_bytes_peak: Some(9999),
        };

        let out = process_info_v11_to_v10(info);
        assert_eq!(out.id, "abc");
        assert_eq!(out.label, "svc");
        assert_eq!(out.command, "sleep 1");
        assert_eq!(out.os_pid, Some(4321));
        assert!(matches!(out.phase, v10::ProcessPhase::Running));
        let exit = out.exit.expect("exit preserved");
        assert_eq!(exit.exit_code, Some(0));
        assert_eq!(exit.signal, None);
        assert_eq!(out.age_ms, 100);
        assert_eq!(out.idle_ms, 10);
        assert_eq!(out.buffered_bytes, 2048);
        assert_eq!(out.bytes_dropped, 3);
        assert!(out.stdin_open);
        assert_eq!(out.cpu_ms, Some(7));
        assert_eq!(out.mem_bytes_peak, Some(9999));
    }

    /// Input enums map 1:1 across the version boundary.
    #[test]
    fn signal_and_log_stream_map_across_versions() {
        assert!(matches!(
            signal_v10_to_v11(v10::ProcessSignal::Term),
            v11::ProcessSignal::Term
        ));
        assert!(matches!(
            signal_v10_to_v11(v10::ProcessSignal::Cont),
            v11::ProcessSignal::Cont
        ));
        assert!(matches!(
            log_stream_v10_to_v11(v10::LogStream::Stderr),
            v11::LogStream::Stderr
        ));
    }

    /// A minimal component that imports `astrid:process/host@{version}` and
    /// depends on the `release-process` function (whose signature is identical
    /// across both contract versions). A NON-EMPTY import forces the wasmtime
    /// linker to actually provide the named+versioned instance — an EMPTY
    /// `(instance)` import is trivially satisfiable and would not discriminate.
    fn process_import_component(version: &str) -> String {
        format!(
            r#"(component
              (import "astrid:process/host@{version}" (instance
                (type $error-code (variant
                  (case "capability-denied") (case "invalid-input")
                  (case "boundary-escape") (case "quota") (case "too-large")
                  (case "closed") (case "cancelled") (case "wait-timeout")
                  (case "no-such-process") (case "registry-full")
                  (case "persist-unsupported") (case "unknown" string)))
                (export "error-code" (type $ec (eq $error-code)))
                (type $rel (func (param "id" string) (result (result (error $ec)))))
                (export "release-process" (func (type $rel))))))"#
        )
    }

    /// Negative control: a component importing a `process` version the kernel
    /// does NOT serve fails to link. This is what proves the two positive
    /// assertions below actually exercise registration (rather than passing
    /// vacuously) — the component-model linker matches by exact package+version.
    #[test]
    fn unknown_process_version_is_not_served() {
        let engine = crate::engine::wasm::build_wasmtime_engine().unwrap();
        let mut linker = wasmtime::component::Linker::<HostState>::new(&engine);
        crate::engine::wasm::configure_kernel_linker(&mut linker).unwrap();
        let component =
            wasmtime::component::Component::new(&engine, process_import_component("9.9.9"))
                .unwrap();
        let res = linker.instantiate_pre(&component).map(|_| ());
        assert!(res.is_err(), "unserved version must NOT link: {res:?}");
    }

    /// The regression guard: the kernel linker resolves BOTH the restored
    /// `astrid:process/host@1.0.0` AND the additive `@1.1.0`. Before the
    /// dual-version fix a capsule built against either published shape hit
    /// "a matching implementation was not found in the linker" (#1107).
    #[test]
    fn both_process_versions_resolve_in_kernel_linker() {
        let engine = crate::engine::wasm::build_wasmtime_engine().unwrap();
        let mut linker = wasmtime::component::Linker::<HostState>::new(&engine);
        crate::engine::wasm::configure_kernel_linker(&mut linker).unwrap();
        for v in ["1.0.0", "1.1.0"] {
            let component =
                wasmtime::component::Component::new(&engine, process_import_component(v)).unwrap();
            let res = linker.instantiate_pre(&component).map(|_| ());
            assert!(
                res.is_ok(),
                "process@{v} must resolve in the linker: {res:?}"
            );
        }
    }

    /// `log-chunk` (with its nested cursor) round-trips back to `@1.0.0`.
    #[test]
    fn log_chunk_round_trips_v11_to_v10() {
        let chunk = v11::LogChunk {
            data: vec![9, 8, 7],
            next: v11::LogCursor {
                token: Some("cur".into()),
            },
            bytes_dropped: 42,
            drained_eof: true,
        };
        let out = log_chunk_v11_to_v10(chunk);
        assert_eq!(out.data, vec![9, 8, 7]);
        assert_eq!(out.next.token.as_deref(), Some("cur"));
        assert_eq!(out.bytes_dropped, 42);
        assert!(out.drained_eof);
    }
}
