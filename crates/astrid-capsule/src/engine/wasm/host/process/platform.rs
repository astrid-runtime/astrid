//! Platform process creation and termination primitives.
//!
//! Commands always use `std::process::Command`; every guest argument remains a
//! distinct OS argument and Astrid never inserts a shell. Windows process trees
//! are owned by a kernel Job Object configured with `KILL_ON_JOB_CLOSE`.

// The Windows backend is a narrow, reviewed FFI boundary over owned handles.
// Keep unsafe prohibited throughout the rest of astrid-capsule.
#![allow(unsafe_code)]

use std::sync::Arc;
#[cfg(windows)]
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::engine::wasm::bindings::astrid::process1_1_0::host::{ErrorCode, ProcessSignal};

#[derive(Clone, Copy)]
pub(super) enum Termination {
    Graceful,
    Force,
}

static NEXT_PROCESS_IDENTITY: AtomicU64 = AtomicU64::new(1);

/// Stable ownership token for one spawned process tree.
pub(super) struct ProcessTree {
    pid: u32,
    identity: u64,
    #[cfg(windows)]
    job: std::os::windows::io::OwnedHandle,
    #[cfg(windows)]
    terminated: AtomicBool,
    #[cfg(all(test, windows))]
    fail_termination: AtomicBool,
}

impl std::fmt::Debug for ProcessTree {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProcessTree")
            .field("pid", &self.pid)
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

impl ProcessTree {
    pub(super) fn attach(child: &tokio::process::Child) -> std::io::Result<Arc<Self>> {
        Self::attach_inner(child, false)
    }

    fn attach_inner(
        child: &tokio::process::Child,
        inject_assignment_failure: bool,
    ) -> std::io::Result<Arc<Self>> {
        let pid = child
            .id()
            .filter(|pid| *pid != 0)
            .ok_or_else(|| std::io::Error::other("spawned child has no usable pid"))?;
        let identity = NEXT_PROCESS_IDENTITY.fetch_add(1, Ordering::Relaxed);

        #[cfg(windows)]
        {
            Ok(Arc::new(Self {
                pid,
                identity,
                job: create_assign_and_resume_job(child, inject_assignment_failure)?,
                terminated: AtomicBool::new(false),
                #[cfg(test)]
                fail_termination: AtomicBool::new(false),
            }))
        }
        #[cfg(not(windows))]
        {
            let _ = inject_assignment_failure;
            Ok(Arc::new(Self { pid, identity }))
        }
    }

    #[cfg(all(test, windows))]
    pub(super) fn inject_assignment_failure(
        child: &tokio::process::Child,
    ) -> std::io::Result<Arc<Self>> {
        Self::attach_inner(child, true)
    }

    pub(super) fn pid(&self) -> u32 {
        self.pid
    }

    pub(super) fn identity(&self) -> u64 {
        self.identity
    }

    /// Terminate the owned tree. Repeated successful calls are idempotent.
    pub(super) fn terminate(&self, termination: Termination) -> Result<(), ErrorCode> {
        #[cfg(all(test, windows))]
        if self.fail_termination.load(Ordering::Acquire) {
            return Err(ErrorCode::Unknown(
                "injected process-tree termination failure".to_string(),
            ));
        }
        #[cfg(unix)]
        {
            let signal = match termination {
                Termination::Graceful => nix::sys::signal::Signal::SIGTERM,
                Termination::Force => nix::sys::signal::Signal::SIGKILL,
            };
            terminate_unix_process_group(self.pid, signal)
        }
        #[cfg(windows)]
        {
            let _ = termination;
            if self.terminated.load(Ordering::Acquire) {
                return Ok(());
            }
            terminate_windows_job(&self.job).map_err(|error| {
                ErrorCode::Unknown(format!("terminate Windows process job: {error}"))
            })?;
            self.terminated.store(true, Ordering::Release);
            Ok(())
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = termination;
            Err(ErrorCode::CapabilityDenied)
        }
    }

    #[cfg(all(test, windows))]
    pub(super) fn inject_termination_failure(&self, fail: bool) {
        self.fail_termination.store(fail, Ordering::Release);
    }
}

pub(super) fn configure_process_group(command: &mut std::process::Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        command.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        use windows_sys::Win32::System::Threading::{CREATE_NEW_PROCESS_GROUP, CREATE_SUSPENDED};
        // The primary thread MUST remain suspended until ProcessTree::attach
        // assigns the process to its kill-on-close Job Object. This closes the
        // post-spawn escape window in which child code could create an
        // unowned descendant before Job membership existed.
        command.creation_flags(CREATE_NEW_PROCESS_GROUP | CREATE_SUSPENDED);
    }
}

/// Windows has no faithful equivalents for POSIX HUP/USR/INT/STOP/CONT.
pub(super) fn signal_supported(signal: ProcessSignal) -> bool {
    #[cfg(windows)]
    {
        matches!(signal, ProcessSignal::Term)
    }
    #[cfg(not(windows))]
    {
        let _ = signal;
        true
    }
}

pub(super) fn signal_process_tree(
    tree: &ProcessTree,
    signal: ProcessSignal,
) -> Result<(), ErrorCode> {
    #[cfg(unix)]
    {
        let signal = match signal {
            ProcessSignal::Term => nix::sys::signal::Signal::SIGTERM,
            ProcessSignal::Hup => nix::sys::signal::Signal::SIGHUP,
            ProcessSignal::Usr1 => nix::sys::signal::Signal::SIGUSR1,
            ProcessSignal::Usr2 => nix::sys::signal::Signal::SIGUSR2,
            ProcessSignal::Int => nix::sys::signal::Signal::SIGINT,
            ProcessSignal::Stop => nix::sys::signal::Signal::SIGSTOP,
            ProcessSignal::Cont => nix::sys::signal::Signal::SIGCONT,
        };
        signal_unix_process_group(tree.pid, signal)
    }
    #[cfg(windows)]
    {
        match signal {
            ProcessSignal::Term => tree.terminate(Termination::Graceful),
            ProcessSignal::Hup
            | ProcessSignal::Usr1
            | ProcessSignal::Usr2
            | ProcessSignal::Int
            | ProcessSignal::Stop
            | ProcessSignal::Cont => Err(ErrorCode::CapabilityDenied),
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (tree, signal);
        Err(ErrorCode::CapabilityDenied)
    }
}

/// Signal only the root process on Unix, preserving the public handle
/// semantics that predate Windows tree ownership. Windows TERM necessarily
/// targets the owned Job because it has no faithful POSIX root signal.
pub(super) fn signal_root_process(
    tree: &ProcessTree,
    signal: ProcessSignal,
) -> Result<(), ErrorCode> {
    #[cfg(unix)]
    {
        let signal = match signal {
            ProcessSignal::Term => nix::sys::signal::Signal::SIGTERM,
            ProcessSignal::Hup => nix::sys::signal::Signal::SIGHUP,
            ProcessSignal::Usr1 => nix::sys::signal::Signal::SIGUSR1,
            ProcessSignal::Usr2 => nix::sys::signal::Signal::SIGUSR2,
            ProcessSignal::Int => nix::sys::signal::Signal::SIGINT,
            ProcessSignal::Stop => nix::sys::signal::Signal::SIGSTOP,
            ProcessSignal::Cont => nix::sys::signal::Signal::SIGCONT,
        };
        let raw = i32::try_from(tree.pid).map_err(|_| ErrorCode::InvalidInput)?;
        nix::sys::signal::kill(nix::unistd::Pid::from_raw(raw), signal)
            .map_err(|error| ErrorCode::Unknown(format!("kill({signal:?}): {error}")))
    }
    #[cfg(windows)]
    {
        signal_process_tree(tree, signal)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (tree, signal);
        Err(ErrorCode::CapabilityDenied)
    }
}

#[cfg(unix)]
fn signal_unix_process_group(pid: u32, signal: nix::sys::signal::Signal) -> Result<(), ErrorCode> {
    let raw = i32::try_from(pid).map_err(|_| ErrorCode::InvalidInput)?;
    let target = nix::unistd::Pid::from_raw(raw);
    if nix::sys::signal::killpg(target, signal).is_err() {
        nix::sys::signal::kill(target, signal)
            .map_err(|error| ErrorCode::Unknown(format!("signal {signal:?}: {error}")))?;
    }
    Ok(())
}

#[cfg(unix)]
fn terminate_unix_process_group(
    pid: u32,
    signal: nix::sys::signal::Signal,
) -> Result<(), ErrorCode> {
    let raw = i32::try_from(pid).map_err(|_| ErrorCode::InvalidInput)?;
    let target = nix::unistd::Pid::from_raw(raw);
    if nix::sys::signal::killpg(target, signal).is_ok() {
        return Ok(());
    }
    match nix::sys::signal::kill(target, signal) {
        Ok(()) | Err(nix::errno::Errno::ESRCH) => Ok(()),
        Err(error) => Err(ErrorCode::Unknown(format!("signal {signal:?}: {error}"))),
    }
}

#[cfg(windows)]
fn create_assign_and_resume_job(
    child: &tokio::process::Child,
    inject_assignment_failure: bool,
) -> std::io::Result<std::os::windows::io::OwnedHandle> {
    use std::ffi::c_void;
    use std::mem::size_of;
    use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
        SetInformationJobObject,
    };
    let child_handle = child
        .raw_handle()
        .ok_or_else(|| std::io::Error::other("spawned child has no process handle"))?;

    // SAFETY: null attributes/name request a private unnamed Job Object.
    let raw_job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    if raw_job.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: CreateJobObjectW returned a new owned handle.
    let job = unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(raw_job.cast()) };
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    // SAFETY: job is valid and `limits` matches the information class.
    let configured = unsafe {
        SetInformationJobObject(
            job.as_raw_handle().cast(),
            JobObjectExtendedLimitInformation,
            (&raw const limits).cast::<c_void>(),
            u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())
                .expect("job limit structure fits u32"),
        )
    };
    if configured == 0 {
        return Err(std::io::Error::last_os_error());
    }
    if inject_assignment_failure {
        return Err(std::io::Error::other(
            "injected Job Object assignment failure",
        ));
    }
    // SAFETY: both handles are borrowed and valid for the duration of the call.
    let assigned =
        unsafe { AssignProcessToJobObject(job.as_raw_handle().cast(), child_handle.cast()) };
    if assigned == 0 {
        return Err(std::io::Error::last_os_error());
    }
    resume_suspended_process_threads(child.id().ok_or_else(|| {
        std::io::Error::other("assigned child lost its process id before resume")
    })?)?;
    Ok(job)
}

#[cfg(windows)]
fn resume_suspended_process_threads(pid: u32) -> std::io::Result<()> {
    use std::mem::size_of;
    use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _};
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
    };
    use windows_sys::Win32::System::Threading::{OpenThread, ResumeThread, THREAD_SUSPEND_RESUME};

    // Collect every thread handle before resuming any. A CREATE_SUSPENDED
    // process normally has exactly its primary thread, but collecting first
    // preserves the all-or-kill property if Windows adds a loader thread.
    // SAFETY: fixed flags and process id 0 request a system thread snapshot.
    let raw_snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if raw_snapshot == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: the snapshot call returned a newly owned, non-sentinel handle.
    let snapshot =
        unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(raw_snapshot.cast()) };
    let mut entry = THREADENTRY32 {
        dwSize: u32::try_from(size_of::<THREADENTRY32>()).expect("thread entry structure fits u32"),
        ..THREADENTRY32::default()
    };
    let mut threads = Vec::new();
    // SAFETY: snapshot and entry are valid for the enumeration calls.
    let mut present =
        unsafe { Thread32First(snapshot.as_raw_handle().cast(), &raw mut entry) } != 0;
    while present {
        if entry.th32OwnerProcessID == pid {
            // SAFETY: thread id came from the live snapshot; the returned
            // handle, when non-null, is newly owned.
            let raw_thread = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID) };
            if raw_thread.is_null() {
                return Err(std::io::Error::last_os_error());
            }
            // SAFETY: OpenThread returned a new owned handle.
            threads.push(unsafe {
                std::os::windows::io::OwnedHandle::from_raw_handle(raw_thread.cast())
            });
        }
        // SAFETY: same valid snapshot/entry pair; false means enumeration end.
        present = unsafe { Thread32Next(snapshot.as_raw_handle().cast(), &raw mut entry) } != 0;
    }
    if threads.is_empty() {
        return Err(std::io::Error::other(
            "suspended child has no enumerable threads",
        ));
    }

    for thread in threads {
        // SAFETY: each handle was opened with THREAD_SUSPEND_RESUME.
        let previous = unsafe { ResumeThread(thread.as_raw_handle().cast()) };
        if previous == u32::MAX {
            return Err(std::io::Error::last_os_error());
        }
        if previous != 1 {
            return Err(std::io::Error::other(format!(
                "unexpected suspended-thread count {previous} while starting owned child"
            )));
        }
    }
    Ok(())
}

#[cfg(windows)]
fn terminate_windows_job(job: &std::os::windows::io::OwnedHandle) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::System::JobObjects::TerminateJobObject;

    // SAFETY: `job` owns a valid Job Object handle for this call.
    if unsafe { TerminateJobObject(job.as_raw_handle().cast(), 1) } == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[cfg(windows)]
    use std::process::Command;

    #[cfg(windows)]
    use super::*;

    #[cfg(windows)]
    #[tokio::test(flavor = "multi_thread")]
    async fn unsupported_windows_signals_fail_closed() {
        use std::process::Stdio;

        let executable = std::env::current_exe().expect("current test executable");
        let temp = tempfile::tempdir().expect("temp");
        let heartbeat = temp.path().join("heartbeat");
        let mut command = std::process::Command::new(executable);
        command
            .arg("windows_process_probe_child")
            .arg("--nocapture")
            .env("ASTRID_WINDOWS_PROCESS_PROBE", "tree-leaf")
            .env("ASTRID_HEARTBEAT", heartbeat)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        configure_process_group(&mut command);
        let mut command = tokio::process::Command::from(command);
        command.kill_on_drop(true);
        let mut child = command.spawn().expect("spawn signal probe");
        let tree = ProcessTree::attach(&child).expect("attach process tree");
        for signal in [
            ProcessSignal::Hup,
            ProcessSignal::Usr1,
            ProcessSignal::Usr2,
            ProcessSignal::Int,
            ProcessSignal::Stop,
            ProcessSignal::Cont,
        ] {
            assert!(matches!(
                signal_process_tree(&tree, signal),
                Err(ErrorCode::CapabilityDenied)
            ));
        }
        tree.terminate(Termination::Force).expect("terminate probe");
        let _ = child.start_kill();
    }

    #[cfg(windows)]
    #[test]
    #[allow(clippy::zombie_processes)]
    fn windows_process_probe_child() {
        use std::io::{Read as _, Write as _};
        use std::process::Stdio;
        use std::time::Duration;

        let mode = std::env::var("ASTRID_WINDOWS_PROCESS_PROBE").unwrap_or_default();
        match mode.as_str() {
            "touch" => {
                std::fs::write(
                    std::env::var_os("ASTRID_SENTINEL").expect("sentinel path"),
                    b"executed",
                )
                .expect("write sentinel");
            },
            "host-stdio" => {
                assert_eq!(
                    std::env::current_dir().expect("child cwd"),
                    std::path::PathBuf::from(
                        std::env::var_os("ASTRID_EXPECTED_CWD").expect("expected cwd")
                    )
                );
                assert_eq!(
                    std::env::var("ASTRID_WINDOWS_EDGE").as_deref(),
                    Ok("unicode-\u{2603}-quote\"-slash\\")
                );
                let mut input = String::new();
                std::io::stdin()
                    .read_to_string(&mut input)
                    .expect("read stdin");
                assert_eq!(input, "host stdin \u{2603} \" \\");
                std::io::stdout()
                    .write_all(b"host-stdout")
                    .expect("write stdout");
                std::io::stderr()
                    .write_all(b"host-stderr")
                    .expect("write stderr");
                std::process::exit(37);
            },
            "stdio" => {
                let skip_values = std::env::args_os()
                    .collect::<Vec<_>>()
                    .windows(2)
                    .filter(|pair| pair[0] == "--skip")
                    .map(|pair| pair[1].to_string_lossy().into_owned())
                    .collect::<Vec<_>>();
                assert_eq!(
                    skip_values,
                    [
                        "argument with spaces",
                        "quote\"inside",
                        "trailing\\",
                        "slashes\\\\\\\"quote",
                    ]
                );
                assert_eq!(
                    std::env::var("ASTRID_WINDOWS_EDGE").as_deref(),
                    Ok("value with spaces \" and trailing\\")
                );
                assert!(std::env::var_os("ASTRID_HOST_SECRET").is_none());
                assert_eq!(
                    std::env::current_dir().expect("child cwd"),
                    std::path::PathBuf::from(
                        std::env::var_os("ASTRID_EXPECTED_CWD").expect("expected cwd")
                    )
                );

                let mut input = String::new();
                std::io::stdin()
                    .read_to_string(&mut input)
                    .expect("read stdin");
                assert_eq!(input, "stdin with spaces \" and slash\\");
                std::io::stdout()
                    .write_all(b"astrid-stdout")
                    .expect("write stdout");
                std::io::stderr()
                    .write_all(b"astrid-stderr")
                    .expect("write stderr");
                std::process::exit(37);
            },
            "tree-root" => {
                let executable = std::env::current_exe().expect("current test executable");
                let heartbeat = std::env::var_os("ASTRID_HEARTBEAT").expect("heartbeat path");
                let mut child = Command::new(executable);
                child
                    .arg("windows_process_probe_child")
                    .arg("--nocapture")
                    .env("ASTRID_WINDOWS_PROCESS_PROBE", "tree-leaf")
                    .env("ASTRID_HEARTBEAT", heartbeat)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null());
                let child = child.spawn().expect("spawn tree leaf");
                std::fs::write(
                    std::env::var_os("ASTRID_LEAF_PID").expect("leaf pid path"),
                    child.id().to_string(),
                )
                .expect("write leaf pid");
                loop {
                    std::thread::sleep(Duration::from_secs(60));
                }
            },
            "tree-root-immediate" => {
                let executable = std::env::current_exe().expect("current test executable");
                Command::new(executable)
                    .arg("windows_process_probe_child")
                    .arg("--nocapture")
                    .env("ASTRID_WINDOWS_PROCESS_PROBE", "tree-leaf")
                    .env(
                        "ASTRID_HEARTBEAT",
                        std::env::var_os("ASTRID_HEARTBEAT").expect("heartbeat path"),
                    )
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .expect("spawn immediate tree leaf");
                loop {
                    std::thread::sleep(Duration::from_secs(60));
                }
            },
            "tree-root-exit" => {
                let executable = std::env::current_exe().expect("current test executable");
                let heartbeat = std::env::var_os("ASTRID_HEARTBEAT").expect("heartbeat path");
                let mut child = std::process::Command::new(executable);
                child
                    .arg("windows_process_probe_child")
                    .arg("--nocapture")
                    .env("ASTRID_WINDOWS_PROCESS_PROBE", "tree-leaf")
                    .env("ASTRID_HEARTBEAT", heartbeat)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null());
                child.spawn().expect("spawn tree leaf");
                std::thread::sleep(Duration::from_millis(250));
            },
            "tree-root-exit-inherit-stdio" => {
                let executable = std::env::current_exe().expect("current test executable");
                let child = Command::new(executable)
                    .arg("windows_process_probe_child")
                    .arg("--nocapture")
                    .env("ASTRID_WINDOWS_PROCESS_PROBE", "tree-leaf")
                    .env(
                        "ASTRID_HEARTBEAT",
                        std::env::var_os("ASTRID_HEARTBEAT").expect("heartbeat path"),
                    )
                    .spawn()
                    .expect("spawn inherited-stdio leaf");
                std::fs::write(
                    std::env::var_os("ASTRID_LEAF_PID").expect("leaf pid path"),
                    child.id().to_string(),
                )
                .expect("write inherited-stdio leaf pid");
            },
            "tree-leaf" => {
                let heartbeat = std::path::PathBuf::from(
                    std::env::var_os("ASTRID_HEARTBEAT").expect("heartbeat path"),
                );
                let mut counter = 0u64;
                loop {
                    counter = counter.wrapping_add(1);
                    std::fs::write(&heartbeat, counter.to_string()).expect("write heartbeat");
                    std::thread::sleep(Duration::from_millis(25));
                }
            },
            _ => {},
        }
    }

    #[cfg(windows)]
    #[tokio::test(flavor = "multi_thread")]
    async fn windows_native_args_env_cwd_stdio_and_exit_are_deterministic() {
        use std::process::Stdio;
        use tokio::io::AsyncWriteExt as _;

        let executable = std::env::current_exe().expect("current test executable");
        let cwd = tempfile::tempdir().expect("temp cwd");
        let mut command = Command::new(executable);
        command
            .arg("windows_process_probe_child")
            .arg("--nocapture")
            .arg("--skip")
            .arg("argument with spaces")
            .arg("--skip")
            .arg("quote\"inside")
            .arg("--skip")
            .arg("trailing\\")
            .arg("--skip")
            .arg("slashes\\\\\\\"quote")
            .current_dir(cwd.path())
            .env("ASTRID_HOST_SECRET", "must-not-leak")
            .env_clear()
            .env(
                "SystemRoot",
                std::env::var_os("SystemRoot").expect("SystemRoot"),
            )
            .env("ASTRID_WINDOWS_PROCESS_PROBE", "stdio")
            .env("ASTRID_WINDOWS_EDGE", "value with spaces \" and trailing\\")
            .env("ASTRID_EXPECTED_CWD", cwd.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        configure_process_group(&mut command);

        let mut command = tokio::process::Command::from(command);
        command.kill_on_drop(true);
        let mut child = command.spawn().expect("spawn suspended probe");
        let _tree = ProcessTree::attach(&child).expect("assign Job before resume");
        child
            .stdin
            .take()
            .expect("piped stdin")
            .write_all(b"stdin with spaces \" and slash\\")
            .await
            .expect("write probe stdin");
        let output = child.wait_with_output().await.expect("wait probe");
        assert_eq!(output.status.code(), Some(37));
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("astrid-stdout"),
            "stdout was {}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("astrid-stderr"),
            "stderr was {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(windows)]
    #[tokio::test(flavor = "multi_thread")]
    async fn windows_forced_cancellation_terminates_descendants() {
        use std::process::Stdio;
        use std::time::{Duration, Instant};

        let executable = std::env::current_exe().expect("current test executable");
        let temp = tempfile::tempdir().expect("temp dir");
        let heartbeat = temp.path().join("heartbeat");
        let leaf_pid = temp.path().join("leaf-pid");
        let mut command = Command::new(executable);
        command
            .arg("windows_process_probe_child")
            .arg("--nocapture")
            .env("ASTRID_WINDOWS_PROCESS_PROBE", "tree-root")
            .env("ASTRID_HEARTBEAT", &heartbeat)
            .env("ASTRID_LEAF_PID", &leaf_pid)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        configure_process_group(&mut command);
        let mut command = tokio::process::Command::from(command);
        command.kill_on_drop(true);
        let mut root = command.spawn().expect("spawn tree root");
        let tree = ProcessTree::attach(&root).expect("attach process tree");

        wait_for_file(&heartbeat, Duration::from_secs(10));
        wait_for_file(&leaf_pid, Duration::from_secs(10));
        tree.terminate(Termination::Force)
            .expect("terminate process tree");
        tree.terminate(Termination::Force)
            .expect("repeat termination is idempotent");
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if root.try_wait().expect("poll root").is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        assert!(root.try_wait().expect("final root poll").is_some());

        std::thread::sleep(Duration::from_millis(250));
        let first = std::fs::read_to_string(&heartbeat).expect("first heartbeat");
        std::thread::sleep(Duration::from_millis(250));
        let second = std::fs::read_to_string(&heartbeat).expect("second heartbeat");
        assert_eq!(
            first, second,
            "descendant kept running after tree cancellation"
        );

        fn wait_for_file(path: &std::path::Path, timeout: Duration) {
            let deadline = Instant::now() + timeout;
            while Instant::now() < deadline {
                if path.is_file() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            panic!("timed out waiting for {}", path.display());
        }
    }

    #[cfg(windows)]
    #[tokio::test(flavor = "multi_thread")]
    async fn windows_job_owns_zero_sleep_immediate_descendant() {
        use std::process::Stdio;
        use std::time::Duration;

        let executable = std::env::current_exe().expect("current test executable");
        let temp = tempfile::tempdir().expect("temp dir");
        let heartbeat = temp.path().join("immediate-heartbeat");
        let mut command = Command::new(executable);
        command
            .arg("windows_process_probe_child")
            .arg("--nocapture")
            .env("ASTRID_WINDOWS_PROCESS_PROBE", "tree-root-immediate")
            .env("ASTRID_HEARTBEAT", &heartbeat)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        configure_process_group(&mut command);
        let mut command = tokio::process::Command::from(command);
        command.kill_on_drop(true);
        let mut root = command.spawn().expect("spawn suspended immediate root");
        let tree = ProcessTree::attach(&root).expect("assign Job before resume");

        wait_for_file(&heartbeat, Duration::from_secs(10));
        tree.terminate(Termination::Force)
            .expect("terminate owned immediate tree");
        root.wait().await.expect("reap immediate root");
        std::thread::sleep(Duration::from_millis(150));
        let stopped = std::fs::read_to_string(&heartbeat).expect("stopped heartbeat");
        std::thread::sleep(Duration::from_millis(250));
        assert_eq!(
            stopped,
            std::fs::read_to_string(&heartbeat).expect("final heartbeat"),
            "zero-sleep descendant escaped Job ownership"
        );

        fn wait_for_file(path: &std::path::Path, timeout: Duration) {
            let deadline = std::time::Instant::now() + timeout;
            while std::time::Instant::now() < deadline {
                if path.is_file() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            panic!("timed out waiting for {}", path.display());
        }
    }

    #[cfg(windows)]
    #[tokio::test(flavor = "multi_thread")]
    async fn windows_assignment_failure_never_runs_child_code() {
        use std::process::Stdio;

        let executable = std::env::current_exe().expect("current test executable");
        let temp = tempfile::tempdir().expect("temp dir");
        let heartbeat = temp.path().join("must-not-start");
        let mut command = Command::new(executable);
        command
            .arg("windows_process_probe_child")
            .arg("--nocapture")
            .env("ASTRID_WINDOWS_PROCESS_PROBE", "tree-root-immediate")
            .env("ASTRID_HEARTBEAT", &heartbeat)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        configure_process_group(&mut command);
        let mut command = tokio::process::Command::from(command);
        command.kill_on_drop(true);
        let mut root = command.spawn().expect("spawn suspended root");

        ProcessTree::inject_assignment_failure(&root)
            .expect_err("injected assignment failure must fail attach");
        root.start_kill().expect("kill still-suspended root");
        root.wait().await.expect("reap still-suspended root");
        assert!(
            !heartbeat.exists(),
            "child code ran before successful Job assignment"
        );
    }

    #[cfg(windows)]
    #[tokio::test(flavor = "multi_thread")]
    async fn windows_job_cleans_descendants_after_root_exits_first() {
        use std::process::Stdio;
        use std::time::Duration;

        let executable = std::env::current_exe().expect("current test executable");
        let temp = tempfile::tempdir().expect("temp dir");
        let heartbeat = temp.path().join("heartbeat");
        let mut command = std::process::Command::new(executable);
        command
            .arg("windows_process_probe_child")
            .arg("--nocapture")
            .env("ASTRID_WINDOWS_PROCESS_PROBE", "tree-root-exit")
            .env("ASTRID_HEARTBEAT", &heartbeat)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        configure_process_group(&mut command);
        let mut command = tokio::process::Command::from(command);
        command.kill_on_drop(true);
        let mut root = command.spawn().expect("spawn root");
        let tree = ProcessTree::attach(&root).expect("attach process tree");
        wait_for_file(&heartbeat, Duration::from_secs(10));
        root.wait().await.expect("root exits first");

        let before = std::fs::read_to_string(&heartbeat).expect("heartbeat before cleanup");
        std::thread::sleep(Duration::from_millis(150));
        let alive = std::fs::read_to_string(&heartbeat).expect("heartbeat while job owned");
        assert_ne!(
            before, alive,
            "descendant should still be alive before cleanup"
        );

        tree.terminate(Termination::Force)
            .expect("terminate descendants");
        std::thread::sleep(Duration::from_millis(250));
        let stopped = std::fs::read_to_string(&heartbeat).expect("stopped heartbeat");
        std::thread::sleep(Duration::from_millis(250));
        assert_eq!(
            stopped,
            std::fs::read_to_string(&heartbeat).expect("final heartbeat")
        );

        fn wait_for_file(path: &std::path::Path, timeout: Duration) {
            let deadline = std::time::Instant::now() + timeout;
            while std::time::Instant::now() < deadline {
                if path.is_file() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            panic!("timed out waiting for {}", path.display());
        }
    }
}
