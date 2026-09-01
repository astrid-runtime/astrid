//! Unix stderr-lifetime and unowned retained-generation stop regressions.

use super::*;
use crate::storage_mount::process_broker::ProcessProjectionBinding;
use crate::storage_mount::process_broker::lease_atomicity_tests::{
    diagnostics_launch, fleet_shared_kernel, retained_cleanup_state,
};
#[cfg(unix)]
use crate::storage_mount::process_broker::process_launch::abort_process_provider;
use crate::storage_mount::process_broker::rollback_or_retain_failed_launch;

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_stop_retains_unowned_generation_even_after_endpoint_release() {
    let scratch = tempfile::tempdir().expect("diagnostics scratch");
    let (_home_root, kernel) = fleet_shared_kernel().await;
    let caller = PrincipalId::default();
    let actor = kernel
        .principal_directory
        .uid_for(&caller)
        .expect("caller actor UID");
    let binding = binding(actor);
    let key = ProcessProjectionKey {
        binding: binding.clone(),
        read_write: true,
    };
    let control_path = scratch.path().join("process-control.sock");
    let (release, responder) = spawn_ready_responder(&control_path);
    let launch = diagnostics_launch(&scratch, control_path.clone());
    let mount_root = scratch.path().join("mount-root");
    std::fs::create_dir_all(&mount_root).expect("create the exact diagnostics UUID root");
    let StderrLifetimeFixture {
        provider: mut child,
        holder,
        mut stderr_task,
        reader,
    } = spawn_stderr_lifetime_fixture();
    wait_stderr_reader_ready(&reader).await;
    let old_reader = tokio::time::timeout(
        STDERR_NEGATIVE_CONTROL,
        read_stderr_to_eof(stderr_task.as_mut().expect("stderr reader")),
    )
    .await;
    assert!(
        old_reader.is_err(),
        "old stderr read_to_end remains blocked while the unrelated holder is live"
    );

    let started = tokio::time::Instant::now();
    let error = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        abort_process_provider(
            child.take(),
            &launch,
            "diagnostics deadline".to_owned(),
            stderr_task,
            crate::storage_mount::process_broker::ProcessStopPolicy::default(),
        ),
    )
    .await
    .expect("failed STOP/reap must not wait for the unrelated stderr holder");
    let elapsed = started.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(2),
        "rollback input took {elapsed:?}"
    );
    assert!(!error.cleanup_ok, "the live endpoint must retain the child");
    assert!(error.child.is_some(), "failed STOP/reap retains the child");
    wait_stderr_reader_cancelled(&reader).await;
    assert!(
        !reader.completed.load(std::sync::atomic::Ordering::Acquire),
        "aborted diagnostics reader must not be classified as completed"
    );

    let retained_child = OwnedTestChild::from(error.child);
    retained_child.wait().await;
    let mut projections = retain_fixture_rollback(
        &kernel,
        &binding,
        &key,
        control_path.clone(),
        mount_root.clone(),
        &scratch,
    )
    .await;
    let projection = Arc::clone(projections.get(&key).expect("authoritative blocker"));
    release.release_once();
    join_ready_responder(responder).await;
    assert!(
        !super::retry_failed_projection(&projection, &mut projections, &key).await,
        "endpoint release cannot prove an exact generation without retained identity"
    );
    assert!(projections.contains_key(&key));
    assert!(
        mount_root.exists(),
        "the exact retained root must remain the administrative blocker"
    );
    holder.terminate_and_reap().await;
}

#[cfg(unix)]
async fn retain_fixture_rollback(
    kernel: &Arc<crate::Kernel>,
    binding: &ProcessProjectionBinding,
    key: &ProcessProjectionKey,
    control_path: std::path::PathBuf,
    mount_root: std::path::PathBuf,
    scratch: &tempfile::TempDir,
) -> BTreeMap<
    ProcessProjectionKey,
    Arc<crate::storage_mount::process_broker::CachedProcessProjection>,
> {
    let cleanup_state =
        retained_cleanup_state(kernel, binding, None, control_path, mount_root, scratch);
    let mut projections = BTreeMap::new();
    rollback_or_retain_failed_launch(
        &mut projections,
        key,
        scratch.path().join("workspace"),
        scratch.path().join("owner"),
        None,
        cleanup_state,
    )
    .await;
    let projection = Arc::clone(projections.get(key).expect("authoritative blocker"));
    assert!(
        projection
            .cleanup_failed
            .load(std::sync::atomic::Ordering::Acquire)
    );
    let retained_root = scratch.path().join("mount-root");
    assert!(
        retained_root.exists(),
        "failed STOP must retain the exact UUID root"
    );
    projections
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn old_stderr_fixture_lifetime_hangs_until_holder_release() {
    let StderrLifetimeFixture {
        holder,
        stderr_task,
        reader,
        ..
    } = spawn_stderr_lifetime_fixture();
    let Some(mut stderr_task) = stderr_task else {
        panic!("stderr fixture owns its diagnostic reader");
    };
    wait_stderr_reader_ready(&reader).await;

    let old_shape = tokio::time::timeout(
        STDERR_NEGATIVE_CONTROL,
        read_stderr_to_eof(&mut stderr_task),
    )
    .await;
    assert!(
        old_shape.is_err(),
        "read_to_end must remain live while the unrelated holder owns stderr"
    );

    holder.terminate_and_reap().await;
    let bytes = tokio::time::timeout(std::time::Duration::from_secs(1), stderr_task)
        .await
        .expect("stderr reader completes after the owned holder is reaped")
        .expect("stderr reader task");
    assert!(bytes.is_empty(), "diagnostics stderr contained no output");
    assert!(
        reader.completed.load(std::sync::atomic::Ordering::Acquire),
        "normal reader completion must be observed"
    );
    assert!(
        !reader.cancelled.load(std::sync::atomic::Ordering::Acquire),
        "normal reader completion must not be classified as cancellation"
    );
}

#[cfg(target_os = "linux")]
static CHILD_SUBREAPER_STATE: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(target_os = "linux")]
struct TestChildSubreaper {
    _serialization: std::sync::MutexGuard<'static, ()>,
    previous: Option<bool>,
}

#[cfg(target_os = "linux")]
impl TestChildSubreaper {
    fn new() -> Self {
        use std::sync::PoisonError;

        let serialization = CHILD_SUBREAPER_STATE
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let previous = nix::sys::prctl::get_child_subreaper()
            .expect("capture the prior test-process child-subreaper state");
        nix::sys::prctl::set_child_subreaper(true)
            .expect("make test process the detached-PID subreaper");
        Self {
            _serialization: serialization,
            previous: Some(previous),
        }
    }

    fn restore(&mut self) -> Result<(), nix::errno::Errno> {
        let Some(previous) = self.previous else {
            return Ok(());
        };
        match nix::sys::prctl::set_child_subreaper(previous) {
            Ok(()) => {
                self.previous = None;
                Ok(())
            },
            Err(error) => Err(error),
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for TestChildSubreaper {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

#[cfg(target_os = "linux")]
async fn wait_for_reported_pid(pid_path: &std::path::Path) -> u32 {
    use std::io::Read as _;

    let started = tokio::time::Instant::now();
    loop {
        if let Ok(mut file) = std::fs::File::open(pid_path) {
            let mut contents = String::new();
            file.read_to_string(&mut contents)
                .expect("read detached stderr-holder PID");
            if let Ok(pid) = contents.trim().parse::<u32>() {
                return pid;
            }
        }
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "old shell did not report its detached stderr-holder PID"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

#[cfg(target_os = "linux")]
struct AdoptedTestChild {
    pid: Option<nix::unistd::Pid>,
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
enum AdoptedReapError {
    NotAdopted,
    TimedOut,
}

#[cfg(target_os = "linux")]
impl AdoptedTestChild {
    fn new(raw_pid: u32) -> Self {
        let raw_pid = i32::try_from(raw_pid).expect("bounded adopted-holder PID");
        Self {
            pid: Some(nix::unistd::Pid::from_raw(raw_pid)),
        }
    }

    async fn terminate_and_reap(mut self) -> Result<nix::sys::wait::WaitStatus, AdoptedReapError> {
        use nix::sys::signal::Signal;
        use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};

        let pid = self.pid.take().expect("adopted test child is owned once");
        nix::sys::signal::kill(pid, Signal::SIGTERM)
            .expect("terminate historical adopted stderr holder");
        let started = tokio::time::Instant::now();
        let mut escalated = false;
        loop {
            match waitpid(pid, Some(WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::StillAlive) => {
                    if started.elapsed() >= OWNED_CHILD_REAP_TIMEOUT {
                        if escalated {
                            return Err(AdoptedReapError::TimedOut);
                        }
                        let _ = nix::sys::signal::kill(pid, Signal::SIGKILL);
                        escalated = true;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                },
                Ok(status) => return Ok(status),
                Err(nix::errno::Errno::ECHILD | nix::errno::Errno::ESRCH) => {
                    return Err(AdoptedReapError::NotAdopted);
                },
                Err(_) => return Err(AdoptedReapError::TimedOut),
            }
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for AdoptedTestChild {
    fn drop(&mut self) {
        use nix::sys::signal::Signal;
        use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};

        let Some(pid) = self.pid.take() else {
            return;
        };
        let _ = nix::sys::signal::kill(pid, Signal::SIGTERM);
        // Keep unwind cleanup nonblocking and nonpanicking; escalate once and
        // stop after a second bounded interval if the adopted PID is wedged.
        let _ = std::thread::spawn(move || {
            let started = std::time::Instant::now();
            let mut escalated = false;
            while started.elapsed() < OWNED_CHILD_REAP_TIMEOUT {
                match waitpid(pid, Some(WaitPidFlag::WNOHANG)) {
                    Ok(WaitStatus::StillAlive) => {
                        if !escalated && started.elapsed() >= OWNED_CHILD_REAP_ESCALATION {
                            let _ = nix::sys::signal::kill(pid, Signal::SIGKILL);
                            escalated = true;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    },
                    Ok(_) | Err(_) => return,
                }
            }
        });
    }
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn historical_detached_pid_shell_holds_stderr_until_explicit_reap() {
    use nix::sys::signal::Signal;
    use nix::sys::wait::WaitStatus;
    use std::sync::atomic::Ordering;

    let mut subreaper = TestChildSubreaper::new();
    let scratch = tempfile::tempdir().expect("historical fixture scratch");
    let pid_path = scratch.path().join("stderr-holder.pid");
    let mut shell = OwnedTestChild::new(
        tokio::process::Command::new("/bin/sh")
            .arg("-c")
            .arg("(echo historical-inherited-stderr >&2; sleep 30) & echo $! > \"$1\"")
            .arg("/bin/sh")
            .arg(&pid_path)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn historical detached-PID shell"),
    );
    let stderr = shell
        .child_mut()
        .stderr
        .take()
        .expect("historical shell stderr pipe");
    let reader = StderrReaderState::new();
    let stderr_task = {
        let reader = Arc::clone(&reader);
        tokio::spawn(async move {
            use tokio::io::AsyncReadExt as _;

            let _observation = StderrReaderObservation {
                state: Arc::clone(&reader),
            };
            reader.ready.set(true);
            let mut stderr = stderr;
            let mut bytes = Vec::new();
            let _ = stderr.read_to_end(&mut bytes).await;
            reader.completed.store(true, Ordering::Release);
            bytes
        })
    };
    wait_stderr_reader_ready(&reader).await;
    let holder_pid = wait_for_reported_pid(&pid_path).await;
    let holder = AdoptedTestChild::new(holder_pid);
    let shell_pid = shell.process_id().expect("historical shell PID");
    let shell_status = shell.wait().await;
    assert!(
        shell_status.success(),
        "historical shell exited cleanly after reporting its descendant: {shell_status:?}"
    );
    assert_ne!(
        holder_pid, shell_pid,
        "the reported PID must identify the shell's descendant"
    );

    let mut stderr_task = stderr_task;
    let old_shape = tokio::time::timeout(
        STDERR_NEGATIVE_CONTROL,
        read_stderr_to_eof(&mut stderr_task),
    )
    .await;
    assert!(
        old_shape.is_err(),
        "the historical detached-PID shell leaves stderr read_to_end hung"
    );

    let status = holder
        .terminate_and_reap()
        .await
        .expect("subreaper adopted the historical descendant");
    assert!(
        matches!(
            status,
            WaitStatus::Signaled(_, Signal::SIGTERM | Signal::SIGKILL, _)
        ),
        "the adopted descendant was explicitly signaled and reaped: {status:?}"
    );
    let bytes = tokio::time::timeout(std::time::Duration::from_secs(1), stderr_task)
        .await
        .expect("historical stderr reader completes after explicit reap")
        .expect("historical stderr reader task");
    assert_eq!(
        bytes, b"historical-inherited-stderr\n",
        "the live descendant wrote through the inherited stderr pipe"
    );
    assert!(
        reader.completed.load(Ordering::Acquire),
        "historical reader normal completion was not observed"
    );
    subreaper
        .restore()
        .expect("restore the prior child-subreaper state");
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unwind_drop_reaps_owned_test_child() {
    use nix::sys::signal::kill;
    use nix::unistd::Pid;

    let holder = UnrelatedStderrHolder {
        child: OwnedTestChild::new(
            tokio::process::Command::new("/bin/sleep")
                .arg("30")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("spawn panic-cleanup child"),
        ),
    };
    let pid = holder
        .process_id()
        .and_then(|raw| i32::try_from(raw).ok())
        .expect("panic-cleanup child PID");
    let task = tokio::spawn(async move {
        let _holder = holder;
        panic!("intentional unwind to prove last-resort reaping");
    });
    let error = tokio::time::timeout(std::time::Duration::from_secs(1), task)
        .await
        .expect("panicking task joins boundedly")
        .expect_err("panicking task returns a JoinError");
    assert!(error.is_panic(), "task failure must be the intended panic");

    let started = tokio::time::Instant::now();
    loop {
        if kill(Pid::from_raw(pid), None) == Err(nix::errno::Errno::ESRCH) {
            return;
        }
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "unwind guard did not synchronously reap the owned child"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}
