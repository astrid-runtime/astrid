//! `ManagedProcess` — a host-side wrapper around a spawned child that
//! drains stdout/stderr into bounded ring buffers and reaps the child
//! on Drop.

use std::collections::VecDeque;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

use astrid_workspace::SandboxCommand;
use tokio::io::AsyncReadExt;

/// Maximum bytes buffered per stream (stdout or stderr).
pub(super) const MAX_BUFFER_BYTES: usize = 1024 * 1024;

/// A background process managed by the host on behalf of a WASM capsule.
///
/// `child` is a [`tokio::process::Child`] rather than the synchronous
/// stdlib variant because `wait()` takes `&mut self` rather than
/// consuming the child by value — so `ProcessHandle.wait` with a
/// timeout can race `child.wait()` against `tokio::time::timeout`
/// without losing ownership when the timeout fires. The std variant
/// requires moving the child into a `spawn_blocking` task, which
/// strands the handle if the wait times out (Gemini #752 finding).
pub struct ManagedProcess {
    pub(super) child: Option<tokio::process::Child>,
    pub(super) stdout_buf: Arc<Mutex<VecDeque<u8>>>,
    pub(super) stderr_buf: Arc<Mutex<VecDeque<u8>>>,
    /// The full command string (cmd + args), kept for diagnostic /
    /// audit purposes and surfaced when an operator queries spawn
    /// telemetry. Not read by the host functions themselves yet —
    /// `#[allow(dead_code)]` until the diagnostics surface lands.
    #[allow(dead_code)]
    pub(super) command: String,
    pub(super) creator: astrid_core::principal::PrincipalId,
    /// Cleanup guard for any read-only file injections wired into this child's
    /// sandbox. Lives as long as the handle: on Linux it keeps the ro-bind
    /// snapshot source alive for the child's lifetime and removes the scratch
    /// dir on drop; on macOS it unlinks the materialized target files on drop.
    /// `None` when the spawn had no injections. Cleaned by the struct's own
    /// drop — no logic needed in `ManagedProcess::Drop`.
    #[allow(dead_code)] // Held purely for its Drop; never read after spawn.
    pub(super) injection_guard: Option<super::inject::InjectionGuard>,
}

/// Synchronously kill a child process group on Unix and start the kill
/// on the child itself. Returns the exit code if reaping was possible
/// in the brief window before this call returns.
///
/// `tokio::process::Child::kill()` is async, but `Drop` and the kill
/// host-fn need a sync path. `start_kill` sends SIGKILL and returns
/// immediately; the kernel's `kill_on_drop(true)` flag on the spawning
/// Command ensures the tokio runtime reaps the zombie when the Child
/// is dropped.
pub(super) fn kill_and_reap(child: &mut tokio::process::Child) -> Option<i32> {
    #[cfg(unix)]
    {
        if let Some(raw_pid) = child.id() {
            let pid = nix::unistd::Pid::from_raw(i32::try_from(raw_pid).unwrap_or(i32::MAX));
            let _ = nix::sys::signal::killpg(pid, nix::sys::signal::Signal::SIGKILL);
        }
    }
    let _ = child.start_kill();
    // Best-effort sync drain of the exit status. `try_wait` is
    // non-blocking; if the SIGKILL hasn't been observed by the OS yet
    // this returns Ok(None) and we surface `None` for the exit code.
    child.try_wait().ok().flatten().and_then(|s| s.code())
}

impl Drop for ManagedProcess {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            kill_and_reap(&mut child);
        }
    }
}

/// Drain a buffer into a lossy UTF-8 string.
pub(super) fn drain_buffer(buf: &Mutex<VecDeque<u8>>) -> String {
    let mut locked = buf.lock().unwrap_or_else(|e| e.into_inner());
    let bytes: Vec<u8> = locked.drain(..).collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Spawn a tokio task that drains an async pipe into a bounded ring
/// buffer. The task exits on EOF or read error; both are normal
/// terminal conditions when the child closes its stdio.
pub(super) fn spawn_reader_task<R>(
    runtime: &tokio::runtime::Handle,
    mut pipe: R,
    buffer: Arc<Mutex<VecDeque<u8>>>,
) where
    R: AsyncReadExt + Unpin + Send + 'static,
{
    runtime.spawn(async move {
        let mut chunk = vec![0u8; 4096];
        loop {
            match pipe.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => {
                    let mut locked = buffer.lock().unwrap_or_else(|e| e.into_inner());
                    locked.extend(&chunk[..n]);
                    let excess = locked.len().saturating_sub(MAX_BUFFER_BYTES);
                    if excess > 0 {
                        locked.drain(..excess);
                    }
                },
                Err(_) => break,
            }
        }
    });
}

/// Prepare a sandboxed command. Shared between spawn and spawn-background.
///
/// `injections` exposes host-verified, read-only files inside the child's
/// sandbox (see [`InjectionGuard`](super::inject)); pass `&[]` for none.
/// `context` contains the validated working directory, guest environment, and
/// authorized process paths; `inject_env` sets
/// host-controlled vars on the child (the `env-pointer`
/// placements point an agent at its injected file); pass `&[]` for none. These
/// are set by the HOST authoritatively — not via the guest `spawn-request.env`.
/// `extra_masks` are the copy-on-write dirs the sandbox must hide from the
/// child (the caller passes `HostState.spawn_mask_paths`); pass `&[]` for none.
pub(super) fn prepare_sandboxed_command(
    cmd: &str,
    args: &[String],
    workspace_root: &std::path::Path,
    context: &super::context::PreparedSpawnContext,
    injections: &[astrid_workspace::RoInjection],
    inject_env: &[(String, String)],
    extra_masks: &[std::path::PathBuf],
) -> Result<Command, String> {
    let mut inner_cmd = Command::new(cmd);
    let str_args: Vec<&str> = args.iter().map(String::as_str).collect();
    inner_cmd.args(&str_args);
    // `cwd` has already been resolved and boundary-checked by the process host.
    // It normally points into the writable CoW workspace; a capability-gated
    // `home://` request can instead target the invoking principal's home.
    inner_cmd.current_dir(&context.cwd);
    inner_cmd.env_clear();
    for (key, value) in &context.env {
        inner_cmd.env(key, value);
    }
    for (k, v) in inject_env {
        inner_cmd.env(k, v);
    }

    SandboxCommand::wrap_with_process_paths(
        &inner_cmd,
        workspace_root,
        injections,
        extra_masks,
        &context.read_paths,
        &context.write_paths,
        true,
    )
    .map_err(|e| format!("failed to wrap command in sandbox: {e}"))
}

/// Wire a freshly-spawned child's stdout / stderr into tokio reader
/// tasks that drain into the supplied buffers.
pub(super) fn attach_pipes(managed: &mut ManagedProcess, runtime: &tokio::runtime::Handle) {
    if let Some(child) = managed.child.as_mut() {
        if let Some(stdout) = child.stdout.take() {
            spawn_reader_task(runtime, stdout, Arc::clone(&managed.stdout_buf));
        }
        if let Some(stderr) = child.stderr.take() {
            spawn_reader_task(runtime, stderr, Arc::clone(&managed.stderr_buf));
        }
    }
}

/// Configure stdio + process-group on a std command. Caller converts
/// to a `tokio::process::Command` afterwards.
pub(super) fn configure_piped(sandboxed_cmd: &mut Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        sandboxed_cmd.process_group(0);
    }
    sandboxed_cmd.stdout(Stdio::piped());
    sandboxed_cmd.stderr(Stdio::piped());
}
