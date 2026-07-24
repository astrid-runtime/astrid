//! `ManagedProcess` — a host-side wrapper around a spawned child that
//! drains stdout/stderr into bounded ring buffers and reaps the child
//! on Drop.

use std::collections::{BTreeMap, VecDeque};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

use astrid_workspace::SandboxCommand;
use tokio::io::AsyncReadExt;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use crate::engine::wasm::bindings::astrid::process1_1_0::host::{ErrorCode, SpawnRequest};

pub(super) enum PrepareCommandError {
    Invalid,
    SandboxDenied(String),
}

#[derive(Clone, Copy)]
pub(super) struct SandboxInputs<'a> {
    pub(super) workspace_root: &'a std::path::Path,
    pub(super) injections: &'a [astrid_workspace::RoInjection],
    pub(super) inject_env: &'a [(String, String)],
    pub(super) extra_masks: &'a [std::path::PathBuf],
    pub(super) policy: astrid_workspace::SandboxPolicy,
}

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
    pub(super) tree: Arc<super::platform::ProcessTree>,
    pub(super) stdout_buf: Arc<Mutex<VecDeque<u8>>>,
    pub(super) stderr_buf: Arc<Mutex<VecDeque<u8>>>,
    /// Bounded audit descriptor for lifecycle operations. This is the
    /// executable only: arguments may contain secrets and must never be
    /// persisted by the signed signal-audit path.
    pub(super) audit_descriptor: String,
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

/// Foreground child owner that terminates the whole process tree before the
/// Tokio child handle drops when the wait future is cancelled.
pub(super) struct ForegroundProcess {
    child: tokio::process::Child,
    tree: Arc<super::platform::ProcessTree>,
    armed: bool,
}

impl ForegroundProcess {
    pub(super) fn new(mut child: tokio::process::Child) -> Result<Self, std::io::Error> {
        let tree = match super::platform::ProcessTree::attach(&child) {
            Ok(tree) => tree,
            Err(error) => {
                let _ = child.start_kill();
                return Err(error);
            },
        };
        Ok(Self {
            child,
            tree,
            armed: true,
        })
    }

    pub(super) fn pid(&self) -> u32 {
        self.tree.pid()
    }

    pub(super) fn tree(&self) -> Arc<super::platform::ProcessTree> {
        Arc::clone(&self.tree)
    }

    pub(super) async fn write_stdin_prelude(&mut self, prelude: &[u8]) -> std::io::Result<()> {
        use tokio::io::AsyncWriteExt as _;

        let Some(mut stdin) = self.child.stdin.take() else {
            return if prelude.is_empty() {
                Ok(())
            } else {
                Err(std::io::Error::other("child stdin was not piped"))
            };
        };
        stdin.write_all(prelude).await?;
        stdin.shutdown().await
    }

    /// Wait for exit while draining both pipes concurrently.
    ///
    /// This borrows the child instead of moving it into
    /// `Child::wait_with_output`, so cancellation drops `Self` first and its
    /// `Drop` implementation can terminate descendants before Tokio drops the
    /// root handle.
    pub(super) async fn wait_with_output(mut self) -> std::io::Result<std::process::Output> {
        let mut stdout = self
            .child
            .stdout
            .take()
            .ok_or_else(|| std::io::Error::other("child stdout was not piped"))?;
        let mut stderr = self
            .child
            .stderr
            .take()
            .ok_or_else(|| std::io::Error::other("child stderr was not piped"))?;
        let mut stdout_bytes = Vec::new();
        let mut stderr_bytes = Vec::new();

        #[cfg(windows)]
        let wait_for_root = {
            let tree = Arc::clone(&self.tree);
            let child = &mut self.child;
            async move {
                let status = child.wait().await?;
                // Descendants may inherit the root's stdout/stderr handles.
                // Terminate the Job as soon as the root exits, before waiting
                // for EOF, or pipe draining can wait forever on a descendant.
                tree.terminate(super::platform::Termination::Force)
                    .map_err(|error| std::io::Error::other(format!("{error:?}")))?;
                Ok::<_, std::io::Error>(status)
            }
        };
        #[cfg(not(windows))]
        let wait_for_root = self.child.wait();

        let (status, _, _) = tokio::try_join!(
            wait_for_root,
            stdout.read_to_end(&mut stdout_bytes),
            stderr.read_to_end(&mut stderr_bytes),
        )?;
        self.armed = false;
        Ok(std::process::Output {
            status,
            stdout: stdout_bytes,
            stderr: stderr_bytes,
        })
    }
}

impl Drop for ForegroundProcess {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        #[cfg(windows)]
        {
            let _ = self.tree.terminate(super::platform::Termination::Force);
            let _ = self.child.start_kill();
        }
        #[cfg(not(windows))]
        {
            let _ = kill_and_reap(&mut self.child, &self.tree);
        }
        let _ = self.child.try_wait();
    }
}

/// Synchronously apply the platform's established kill contract.
///
/// Unix retains its process-group SIGKILL plus root `start_kill` behavior.
/// Windows terminates the owned Job Object and derives `killed` from that
/// operation without racing a second root-only kill.
pub(super) fn kill_and_reap(
    child: &mut tokio::process::Child,
    tree: &super::platform::ProcessTree,
) -> Result<(bool, Option<i32>), ErrorCode> {
    #[cfg(unix)]
    {
        let _ = tree;
        // Preserve the established Unix contract: kill the spawned process
        // group best-effort, then request root termination. Handle.kill reports
        // true whenever it still owned a Child slot, exactly as before.
        if let Some(raw_pid) = child.id() {
            let pid = nix::unistd::Pid::from_raw(i32::try_from(raw_pid).unwrap_or(i32::MAX));
            let _ = nix::sys::signal::killpg(pid, nix::sys::signal::Signal::SIGKILL);
        }
        let _ = child.start_kill();
        Ok((
            true,
            child
                .try_wait()
                .ok()
                .flatten()
                .and_then(|status| status.code()),
        ))
    }
    #[cfg(windows)]
    {
        if let Some(status) = child.try_wait().ok().flatten() {
            // Root already exited: terminate any descendants retained by the
            // Job, but do not claim that this call killed the root process.
            tree.terminate(super::platform::Termination::Force)?;
            return Ok((false, status.code()));
        }
        // TerminateJobObject is the owned tree operation. Its success—not a
        // racy second start_kill on the root—establishes killed=true.
        tree.terminate(super::platform::Termination::Force)?;
        return Ok((
            true,
            child
                .try_wait()
                .ok()
                .flatten()
                .and_then(|status| status.code()),
        ));
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = tree;
        child
            .start_kill()
            .map_err(|error| ErrorCode::Unknown(format!("terminate root process: {error}")))?;
        Ok((
            true,
            child
                .try_wait()
                .ok()
                .flatten()
                .and_then(|status| status.code()),
        ))
    }
}

impl Drop for ManagedProcess {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take()
            && let Err(error) = kill_and_reap(&mut child, &self.tree)
        {
            tracing::warn!(
                pid = self.tree.pid(),
                ?error,
                "failed to terminate managed process tree on drop"
            );
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
    context: &super::context::PreparedSpawnContext,
    sandbox: SandboxInputs<'_>,
) -> Result<Command, PrepareCommandError> {
    let program = resolve_program(cmd, &context.cwd, &context.env)
        .map_err(|_| PrepareCommandError::Invalid)?;
    let mut inner_cmd = Command::new(program);
    let str_args: Vec<&str> = args.iter().map(String::as_str).collect();
    inner_cmd.args(&str_args);
    // `cwd` has already been resolved and boundary-checked by the process host.
    // It normally points into the writable CoW workspace; a capability-gated
    // `home://` request can instead target the invoking principal's home.
    inner_cmd.current_dir(&context.cwd);
    inner_cmd.env_clear();
    let mut child_env = BTreeMap::new();
    for (key, value) in &context.env {
        child_env.insert(key.clone(), value.clone());
    }
    for (k, v) in sandbox.inject_env {
        let key = super::context::canonical_env_key(k);
        if child_env.insert(key, v.clone()).is_some() {
            return Err(PrepareCommandError::Invalid);
        }
    }
    for (key, value) in child_env {
        inner_cmd.env(key, value);
    }

    SandboxCommand::wrap_with_process_paths_and_policy(
        &inner_cmd,
        sandbox.workspace_root,
        sandbox.injections,
        sandbox.extra_masks,
        &context.read_paths,
        &context.write_paths,
        true,
        sandbox.policy,
    )
    .map_err(|error| {
        let message = format!("failed to wrap command in sandbox: {error}");
        if error.kind() == std::io::ErrorKind::PermissionDenied {
            PrepareCommandError::SandboxDenied(message)
        } else {
            let _ = message;
            PrepareCommandError::Invalid
        }
    })
}

/// Build the sandboxed child for a persistent spawn.
pub(super) fn build_persistent_child(
    request: &SpawnRequest,
    context: &super::context::PreparedSpawnContext,
    want_stdin: bool,
    sandbox: SandboxInputs<'_>,
) -> Result<(tokio::process::Child, Arc<super::platform::ProcessTree>), ErrorCode> {
    let mut sandboxed = prepare_sandboxed_command(&request.cmd, &request.args, context, sandbox)
        .map_err(|error| match error {
            PrepareCommandError::SandboxDenied(_) => ErrorCode::CapabilityDenied,
            PrepareCommandError::Invalid => ErrorCode::InvalidInput,
        })?;
    configure_piped(&mut sandboxed);
    sandboxed.stdin(if want_stdin {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    let mut command = tokio::process::Command::from(sandboxed);
    command.kill_on_drop(true);
    let mut child = command
        .spawn()
        .map_err(|error| ErrorCode::Unknown(format!("spawn-persistent failed: {error}")))?;
    let tree = super::platform::ProcessTree::attach(&child).map_err(|error| {
        let _ = child.start_kill();
        ErrorCode::Unknown(format!("spawn-persistent ownership failed: {error}"))
    })?;
    Ok((child, tree))
}

/// Deliver and close a background spawn's optional stdin prelude.
pub(super) fn write_background_stdin(
    runtime: &tokio::runtime::Handle,
    semaphore: &Semaphore,
    cancel: &CancellationToken,
    child: &mut tokio::process::Child,
    prelude: Option<Vec<u8>>,
) -> Result<(), ErrorCode> {
    let Some(prelude) = prelude else {
        return Ok(());
    };
    let mut stdin = child.stdin.take().ok_or_else(|| {
        ErrorCode::Unknown("spawn-background: child stdin was not piped".to_string())
    })?;
    crate::engine::wasm::host::util::bounded_block_on_cancellable(
        runtime,
        semaphore,
        cancel,
        async move {
            use tokio::io::AsyncWriteExt as _;
            stdin.write_all(&prelude).await
        },
    )
    .ok_or(ErrorCode::Cancelled)?
    .map_err(|error| {
        ErrorCode::Unknown(format!(
            "spawn-background: stdin prelude write failed: {error}"
        ))
    })
}

#[cfg(not(windows))]
fn resolve_program(
    command: &str,
    _cwd: &std::path::Path,
    _env: &[(String, String)],
) -> Result<std::ffi::OsString, String> {
    if command.contains('\0') {
        return Err("process command contains a null byte".to_string());
    }
    Ok(command.into())
}

/// Resolve a Windows program once before `CreateProcessW`.
///
/// Bare program names search only absolute PATH entries. Explicit relative
/// paths resolve beneath the already-authorized child CWD. Batch files are
/// refused because Windows can only execute them by inserting `cmd.exe`.
#[cfg(windows)]
fn resolve_program(
    command: &str,
    cwd: &std::path::Path,
    env: &[(String, String)],
) -> Result<std::ffi::OsString, String> {
    use std::ffi::OsStr;
    use std::path::{Component, Path};

    if command.is_empty() || command.contains('\0') {
        return Err("process command is empty or contains a null byte".to_string());
    }
    let requested = Path::new(command);
    let has_path = requested.is_absolute()
        || requested.components().count() != 1
        || requested
            .components()
            .any(|component| !matches!(component, Component::Normal(_)));

    let candidate = if has_path {
        let candidate = if requested.is_absolute() {
            requested.to_path_buf()
        } else {
            cwd.join(requested)
        };
        resolve_windows_candidate(candidate)?
    } else {
        let path = env_value(env, "PATH")
            .ok_or_else(|| "PATH is not set while resolving process command".to_string())?;
        let extensions = windows_executable_extensions(env);
        let mut found = None;
        for directory in std::env::split_paths(&path).filter(|path| path.is_absolute()) {
            for candidate in windows_candidates(&directory, requested, &extensions) {
                if candidate.is_file() {
                    found = Some(resolve_windows_candidate(candidate)?);
                    break;
                }
            }
            if found.is_some() {
                break;
            }
        }
        found.ok_or_else(|| {
            format!("process command not found in absolute PATH entries: {command}")
        })?
    };

    let extension = candidate
        .extension()
        .and_then(OsStr::to_str)
        .unwrap_or_default();
    if extension.eq_ignore_ascii_case("cmd") || extension.eq_ignore_ascii_case("bat") {
        return Err("batch files require an explicit cmd.exe invocation".to_string());
    }
    Ok(candidate.into_os_string())
}

#[cfg(windows)]
fn resolve_windows_candidate(path: std::path::PathBuf) -> Result<std::path::PathBuf, String> {
    let canonical = path.canonicalize().map_err(|error| {
        format!(
            "cannot resolve process executable {}: {error}",
            path.display()
        )
    })?;
    if !canonical.is_file() {
        return Err(format!(
            "process executable is not a file: {}",
            canonical.display()
        ));
    }
    Ok(canonical)
}

#[cfg(windows)]
fn env_value<'a>(env: &'a [(String, String)], key: &str) -> Option<&'a std::ffi::OsStr> {
    env.iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(key))
        .map(|(_, value)| std::ffi::OsStr::new(value))
}

#[cfg(windows)]
fn windows_executable_extensions(env: &[(String, String)]) -> Vec<String> {
    env_value(env, "PATHEXT")
        .map(|value| {
            value
                .to_string_lossy()
                .split(';')
                .filter(|extension| !extension.is_empty())
                .map(|extension| {
                    if extension.starts_with('.') {
                        extension.to_string()
                    } else {
                        format!(".{extension}")
                    }
                })
                .collect()
        })
        .filter(|extensions: &Vec<String>| !extensions.is_empty())
        .unwrap_or_else(|| vec![".COM".into(), ".EXE".into()])
}

#[cfg(windows)]
fn windows_candidates(
    directory: &std::path::Path,
    requested: &std::path::Path,
    extensions: &[String],
) -> Vec<std::path::PathBuf> {
    if requested.extension().is_some() {
        return vec![directory.join(requested)];
    }
    extensions
        .iter()
        .map(|extension| {
            let mut file_name = requested.as_os_str().to_os_string();
            file_name.push(extension);
            directory.join(file_name)
        })
        .collect()
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
    super::platform::configure_process_group(sandboxed_cmd);
    sandboxed_cmd.stdout(Stdio::piped());
    sandboxed_cmd.stderr(Stdio::piped());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn windows_program_resolution_is_explicit_and_rejects_batch_files() {
        let temp = tempfile::tempdir().expect("temp");
        let executable = temp.path().join("astrid-probe.exe");
        std::fs::copy(
            std::env::current_exe().expect("current test executable"),
            &executable,
        )
        .expect("copy probe executable");
        let batch = temp.path().join("astrid-probe.cmd");
        std::fs::write(&batch, b"@exit /b 0\r\n").expect("write batch file");
        let env = vec![
            (
                "Path".to_string(),
                temp.path().to_string_lossy().into_owned(),
            ),
            ("PathExt".to_string(), ".EXE;.CMD".to_string()),
        ];

        assert_eq!(
            resolve_program("astrid-probe", temp.path(), &env).expect("resolve bare executable"),
            executable
                .canonicalize()
                .expect("canonical executable")
                .into_os_string()
        );
        assert!(resolve_program(batch.to_string_lossy().as_ref(), temp.path(), &env).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn windows_prepared_command_preserves_empty_unicode_and_quoted_arguments() {
        let executable = std::env::current_exe().expect("current test executable");
        let workspace = tempfile::tempdir().expect("workspace");
        let context = super::super::context::PreparedSpawnContext {
            cwd: workspace.path().to_path_buf(),
            env: Vec::new(),
            read_paths: Vec::new(),
            write_paths: Vec::new(),
        };
        let args = vec![
            String::new(),
            "snow-\u{2603}".to_string(),
            "quote\"inside".to_string(),
            "trailing\\".to_string(),
        ];
        let command = prepare_sandboxed_command(
            executable.to_string_lossy().as_ref(),
            &args,
            &context,
            SandboxInputs {
                workspace_root: workspace.path(),
                injections: &[],
                inject_env: &[],
                extra_masks: &[],
                policy: astrid_workspace::SandboxPolicy::Off,
            },
        )
        .expect("prepare native command");

        assert_eq!(
            command
                .get_args()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect::<Vec<_>>(),
            args
        );
    }

    #[cfg(windows)]
    #[tokio::test(flavor = "multi_thread")]
    async fn windows_kill_reports_already_exited_process_as_not_killed() {
        let mut command = Command::new(std::env::current_exe().expect("current test executable"));
        command
            .arg("astrid_test_filter_that_does_not_exist")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        super::super::platform::configure_process_group(&mut command);
        let mut command = tokio::process::Command::from(command);
        command.kill_on_drop(true);
        let mut child = command.spawn().expect("spawn short-lived child");
        let tree =
            super::super::platform::ProcessTree::attach(&child).expect("attach process tree");
        let status = child.wait().await.expect("child exit");

        let (killed, exit_code) = kill_and_reap(&mut child, &tree).expect("idempotent cleanup");
        assert!(!killed, "an already-exited process was reported as killed");
        assert_eq!(exit_code, status.code());
    }

    #[cfg(windows)]
    #[tokio::test(flavor = "multi_thread")]
    async fn windows_kill_propagates_process_tree_termination_failure() {
        let temp = tempfile::tempdir().expect("temp");
        let mut command = Command::new(std::env::current_exe().expect("current test executable"));
        command
            .arg("windows_process_probe_child")
            .arg("--nocapture")
            .env("ASTRID_WINDOWS_PROCESS_PROBE", "tree-leaf")
            .env("ASTRID_HEARTBEAT", temp.path().join("heartbeat"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        super::super::platform::configure_process_group(&mut command);
        let mut command = tokio::process::Command::from(command);
        command.kill_on_drop(true);
        let mut child = command.spawn().expect("spawn long-lived child");
        let tree =
            super::super::platform::ProcessTree::attach(&child).expect("attach process tree");

        tree.inject_termination_failure(true);
        assert!(kill_and_reap(&mut child, &tree).is_err());
        tree.inject_termination_failure(false);
        let _ = kill_and_reap(&mut child, &tree).expect("cleanup process tree");
    }

    #[cfg(windows)]
    #[tokio::test(flavor = "multi_thread")]
    async fn windows_foreground_root_exit_closes_inherited_descendant_pipes() {
        let temp = tempfile::tempdir().expect("temp");
        let mut command = Command::new(std::env::current_exe().expect("current test executable"));
        command
            .arg("windows_process_probe_child")
            .arg("--nocapture")
            .env(
                "ASTRID_WINDOWS_PROCESS_PROBE",
                "tree-root-exit-inherit-stdio",
            )
            .env("ASTRID_HEARTBEAT", temp.path().join("heartbeat"))
            .env("ASTRID_LEAF_PID", temp.path().join("leaf-pid"))
            .stdin(Stdio::null());
        configure_piped(&mut command);
        let mut command = tokio::process::Command::from(command);
        command.kill_on_drop(true);
        let child = command.spawn().expect("spawn inherited-pipe root");
        let process = ForegroundProcess::new(child).expect("own suspended process");

        let output = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            process.wait_with_output(),
        )
        .await
        .expect("foreground output deadlocked on inherited descendant pipes")
        .expect("wait for foreground output");
        assert_eq!(output.status.code(), Some(0));
        assert!(
            temp.path().join("leaf-pid").is_file(),
            "root did not create inherited-pipe descendant"
        );
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread")]
    async fn foreground_stdio_and_exit_are_preserved() {
        let mut command = Command::new("sh");
        command
            .args([
                "-c",
                "IFS= read -r line; printf 'out:%s' \"$line\"; printf 'err:%s' \"$line\" >&2; exit 23",
            ])
            .stdin(Stdio::piped());
        configure_piped(&mut command);
        let mut command = tokio::process::Command::from(command);
        command.kill_on_drop(true);
        let child = command.spawn().expect("spawn child");
        let mut process = ForegroundProcess::new(child).expect("foreground owner");
        process
            .write_stdin_prelude(b"hello world\n")
            .await
            .expect("write stdin");
        let output = process.wait_with_output().await.expect("wait with output");

        assert_eq!(output.status.code(), Some(23));
        assert_eq!(output.stdout, b"out:hello world");
        assert_eq!(output.stderr, b"err:hello world");
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread")]
    async fn unix_successful_foreground_wait_does_not_force_descendant_group() {
        let temp = tempfile::tempdir().expect("temp");
        let pid_file = temp.path().join("descendant-pid");
        let mut command = Command::new("sh");
        command
            .args([
                "-c",
                "sleep 60 </dev/null >/dev/null 2>&1 & printf '%s' \"$!\" > \"$1\"; exit 0",
                "astrid-test",
            ])
            .arg(&pid_file)
            .stdin(Stdio::null());
        configure_piped(&mut command);
        let mut command = tokio::process::Command::from(command);
        command.kill_on_drop(true);
        let child = command.spawn().expect("spawn process tree");
        let process = ForegroundProcess::new(child).expect("foreground owner");
        let output = process.wait_with_output().await.expect("root wait");
        assert_eq!(output.status.code(), Some(0));

        let descendant: i32 = std::fs::read_to_string(&pid_file)
            .expect("descendant pid")
            .parse()
            .expect("decimal pid");
        let descendant = nix::unistd::Pid::from_raw(descendant);
        assert!(
            nix::sys::signal::kill(descendant, None).is_ok(),
            "successful Unix root wait unexpectedly killed its process group"
        );
        let _ = nix::sys::signal::kill(descendant, nix::sys::signal::Signal::SIGKILL);
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread")]
    async fn unix_public_signal_targets_root_not_process_group() {
        use std::time::{Duration, Instant};

        let temp = tempfile::tempdir().expect("temp");
        let pid_file = temp.path().join("descendant-pid");
        let mut command = Command::new("sh");
        command
            .args([
                "-c",
                "trap 'exit 0' TERM; sleep 60 & printf '%s' \"$!\" > \"$1\"; wait",
                "astrid-test",
            ])
            .arg(&pid_file)
            .stdin(Stdio::null());
        configure_piped(&mut command);
        let mut command = tokio::process::Command::from(command);
        command.kill_on_drop(true);
        let mut child = command.spawn().expect("spawn process tree");
        let tree =
            super::super::platform::ProcessTree::attach(&child).expect("attach process identity");
        let deadline = Instant::now() + Duration::from_secs(10);
        while !pid_file.is_file() && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let descendant: i32 = std::fs::read_to_string(&pid_file)
            .expect("descendant pid")
            .parse()
            .expect("decimal pid");
        let descendant = nix::unistd::Pid::from_raw(descendant);

        super::super::platform::signal_root_process(
            &tree,
            crate::engine::wasm::bindings::astrid::process1_1_0::host::ProcessSignal::Term,
        )
        .expect("signal root");
        if tokio::time::timeout(Duration::from_secs(5), child.wait())
            .await
            .is_err()
        {
            let _ = tree.terminate(super::super::platform::Termination::Force);
            panic!("Unix root did not exit after TERM");
        }
        assert!(
            nix::sys::signal::kill(descendant, None).is_ok(),
            "public Unix signal unexpectedly targeted the process group"
        );
        let _ = nix::sys::signal::kill(descendant, nix::sys::signal::Signal::SIGKILL);
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread")]
    async fn cancelling_foreground_wait_terminates_descendant_group() {
        use std::time::{Duration, Instant};

        let temp = tempfile::tempdir().expect("temp");
        let pid_file = temp.path().join("descendant-pid");
        let mut command = Command::new("sh");
        command
            .args([
                "-c",
                "sleep 60 & child=$!; printf '%s' \"$child\" > \"$1\"; wait",
                "astrid-test",
            ])
            .arg(&pid_file)
            .stdin(Stdio::null());
        configure_piped(&mut command);
        let mut command = tokio::process::Command::from(command);
        command.kill_on_drop(true);
        let child = command.spawn().expect("spawn process tree");
        let process = ForegroundProcess::new(child).expect("foreground owner");
        let wait = tokio::spawn(process.wait_with_output());

        let deadline = Instant::now() + Duration::from_secs(10);
        while !pid_file.is_file() && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        let descendant_pid: i32 = std::fs::read_to_string(&pid_file)
            .expect("descendant pid file")
            .parse()
            .expect("decimal descendant pid");

        wait.abort();
        let _ = wait.await;

        let descendant = nix::unistd::Pid::from_raw(descendant_pid);
        let deadline = Instant::now() + Duration::from_secs(10);
        while nix::sys::signal::kill(descendant, None).is_ok() && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(
            nix::sys::signal::kill(descendant, None).is_err(),
            "descendant remained alive after foreground cancellation"
        );
    }
}
