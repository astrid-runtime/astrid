//! STOP/reap failure retention for a real provider endpoint.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use astrid_core::PrincipalId;
use astrid_core::dirs::AstridHome;

use super::{
    ProcessProjectionKey, ProjectionCleanupState, binding, retain_failed_launch_projection,
    retry_failed_projection,
};

#[cfg(unix)]
const STDERR_NEGATIVE_CONTROL: std::time::Duration = std::time::Duration::from_millis(100);
#[cfg(unix)]
const RESPONDER_JOIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

#[cfg(unix)]
#[derive(Clone)]
struct WatchFlag {
    sender: Arc<tokio::sync::watch::Sender<bool>>,
    receiver: Arc<tokio::sync::Mutex<tokio::sync::watch::Receiver<bool>>>,
}

#[cfg(unix)]
impl WatchFlag {
    fn new(initial: bool) -> Self {
        let (sender, receiver) = tokio::sync::watch::channel(initial);
        Self {
            sender: Arc::new(sender),
            receiver: Arc::new(tokio::sync::Mutex::new(receiver)),
        }
    }

    fn set(&self, value: bool) {
        self.sender.send_replace(value);
    }

    async fn wait_for(&self, value: bool) {
        let mut receiver = self.receiver.lock().await.clone();
        receiver
            .wait_for(|current| *current == value)
            .await
            .expect("watch flag remains live");
    }
}

#[cfg(unix)]
#[derive(Clone)]
struct ResponderControl {
    release: WatchFlag,
    between_responses: WatchFlag,
    advance: WatchFlag,
}

#[cfg(unix)]
impl ResponderControl {
    fn new() -> Self {
        Self {
            release: WatchFlag::new(false),
            between_responses: WatchFlag::new(false),
            advance: WatchFlag::new(false),
        }
    }

    fn release_once(&self) {
        self.release.set(true);
    }
}

#[cfg(unix)]
struct OwnedTestChild {
    child: Option<tokio::process::Child>,
}

#[cfg(unix)]
impl OwnedTestChild {
    fn new(child: tokio::process::Child) -> Self {
        Self { child: Some(child) }
    }

    fn take(&mut self) -> tokio::process::Child {
        self.child
            .take()
            .expect("owned test child is available exactly once")
    }

    #[cfg(target_os = "linux")]
    fn child_mut(&mut self) -> &mut tokio::process::Child {
        self.child.as_mut().expect("owned test child is present")
    }

    fn process_id(&self) -> Option<u32> {
        self.child.as_ref().and_then(tokio::process::Child::id)
    }

    async fn wait(mut self) -> std::process::ExitStatus {
        self.take()
            .wait()
            .await
            .expect("reap owned test provider child")
    }

    async fn kill_and_wait(mut self) -> std::process::ExitStatus {
        let mut child = self.take();
        let _ = child.start_kill();
        child.wait().await.expect("kill and reap owned test child")
    }
}

#[cfg(unix)]
impl From<Option<tokio::process::Child>> for OwnedTestChild {
    fn from(child: Option<tokio::process::Child>) -> Self {
        Self { child }
    }
}

#[cfg(unix)]
impl From<Option<Box<tokio::process::Child>>> for OwnedTestChild {
    fn from(child: Option<Box<tokio::process::Child>>) -> Self {
        Self {
            child: child.map(|child| *child),
        }
    }
}

#[cfg(unix)]
impl Drop for OwnedTestChild {
    fn drop(&mut self) {
        use nix::sys::wait::waitpid;

        let Some(mut child) = self.child.take() else {
            return;
        };
        let _ = child.start_kill();
        if let Some(raw_pid) = child.id().and_then(|pid| i32::try_from(pid).ok()) {
            let pid = nix::unistd::Pid::from_raw(raw_pid);
            match waitpid(pid, None) {
                Ok(_) | Err(nix::errno::Errno::ESRCH | nix::errno::Errno::ECHILD) => {},
                Err(error) => panic!("last-resort reap of test child {raw_pid}: {error}"),
            }
        }
    }
}

#[cfg(unix)]
struct UnrelatedStderrHolder {
    child: OwnedTestChild,
}

#[cfg(unix)]
impl UnrelatedStderrHolder {
    fn process_id(&self) -> Option<u32> {
        self.child.process_id()
    }

    async fn terminate_and_reap(self) -> std::process::ExitStatus {
        use std::os::unix::process::ExitStatusExt as _;

        let status = self.child.kill_and_wait().await;
        assert_eq!(
            status.signal(),
            Some(9),
            "stderr holder must be deterministically killed and reaped"
        );
        status
    }
}

#[cfg(unix)]
struct StderrReaderState {
    ready: WatchFlag,
    cancelled: std::sync::atomic::AtomicBool,
    completed: std::sync::atomic::AtomicBool,
}

#[cfg(unix)]
impl StderrReaderState {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            ready: WatchFlag::new(false),
            cancelled: std::sync::atomic::AtomicBool::new(false),
            completed: std::sync::atomic::AtomicBool::new(false),
        })
    }
}

#[cfg(unix)]
struct StderrReaderObservation {
    state: Arc<StderrReaderState>,
}

#[cfg(unix)]
impl Drop for StderrReaderObservation {
    fn drop(&mut self) {
        use std::sync::atomic::Ordering;

        if !self.state.completed.load(Ordering::Acquire) {
            self.state.cancelled.store(true, Ordering::Release);
        }
    }
}

#[cfg(unix)]
async fn wait_stderr_reader_ready(state: &Arc<StderrReaderState>) {
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        state.ready.wait_for(true),
    )
    .await
    .expect("stderr reader reports readiness");
}

#[cfg(unix)]
async fn wait_stderr_reader_cancelled(state: &Arc<StderrReaderState>) {
    use std::sync::atomic::Ordering;

    let started = tokio::time::Instant::now();
    while !state.cancelled.load(Ordering::Acquire) {
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "aborted stderr reader did not expose its drop guard"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

#[cfg(unix)]
struct StderrLifetimeFixture {
    provider: OwnedTestChild,
    holder: UnrelatedStderrHolder,
    stderr_task: Option<tokio::task::JoinHandle<Vec<u8>>>,
    reader: Arc<StderrReaderState>,
}

#[cfg(unix)]
async fn read_stderr_to_eof(
    task: &mut tokio::task::JoinHandle<Vec<u8>>,
) -> Result<Vec<u8>, tokio::task::JoinError> {
    task.await
}

#[cfg(unix)]
fn spawn_stderr_lifetime_fixture() -> StderrLifetimeFixture {
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    use std::process::Stdio;

    fn stderr_stdio(stream: UnixStream) -> Stdio {
        let owned_fd = OwnedFd::from(stream);
        Stdio::from(std::fs::File::from(owned_fd))
    }

    let (descendant_stderr, parent_stderr) = UnixStream::pair().expect("create shared stderr pipe");
    let provider_stderr = descendant_stderr
        .try_clone()
        .expect("duplicate shared stderr for provider");
    let holder_stderr = descendant_stderr
        .try_clone()
        .expect("duplicate shared stderr for holder");
    drop(descendant_stderr);
    parent_stderr
        .set_nonblocking(true)
        .expect("prepare stderr reader");
    let mut parent_stderr =
        tokio::net::UnixStream::from_std(parent_stderr).expect("asynchronous stderr reader");
    let reader = StderrReaderState::new();
    let observation = StderrReaderObservation {
        state: Arc::clone(&reader),
    };

    let holder = tokio::process::Command::new("/bin/sleep")
        .arg("30")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(stderr_stdio(holder_stderr))
        .spawn()
        .expect("spawn owned stderr holder");
    let provider = tokio::process::Command::new("true")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(stderr_stdio(provider_stderr))
        .kill_on_drop(true)
        .spawn()
        .expect("spawn provider child with shared stderr");
    let task_reader = Arc::clone(&reader);
    let stderr_task = tokio::spawn(async move {
        use tokio::io::AsyncReadExt as _;

        let _observation = observation;
        task_reader.ready.set(true);
        let mut bytes = Vec::new();
        let _ = parent_stderr.read_to_end(&mut bytes).await;
        task_reader
            .completed
            .store(true, std::sync::atomic::Ordering::Release);
        bytes
    });
    StderrLifetimeFixture {
        provider: OwnedTestChild::new(provider),
        holder: UnrelatedStderrHolder {
            child: OwnedTestChild::new(holder),
        },
        stderr_task: Some(stderr_task),
        reader,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_stop_retains_blocker_until_provider_cleanup_succeeds() {
    use astrid_core::local_transport;
    use tokio::io::AsyncWriteExt as _;

    use super::{ProjectionLeaseProvider, ProjectionLeaseTarget, RunningProvider};

    let temporary = tempfile::tempdir().expect("test home root");
    let home = AstridHome::from_path(temporary.path().join(".astrid"));
    let kernel = Arc::new(crate::test_kernel_with_home(home).await);
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
    let mount_root = temporary.path().join("process-mount");
    std::fs::create_dir_all(&mount_root).expect("create retained mount root");
    let control_path = mount_root.join("process-control.sock");
    let listener =
        Arc::new(local_transport::bind(&control_path).expect("bind live provider endpoint"));
    let responder_listener = Arc::clone(&listener);
    let responder = tokio::spawn(async move {
        let result = async {
            let mut stream = local_transport::accept(&responder_listener).await?;
            stream.write_all(b"{\"status\":\"ready\"}\n").await?;
            stream.flush().await
        };
        result.await.map_err(|error| error.to_string())
    });
    let child = tokio::process::Command::new("true")
        .spawn()
        .expect("spawn exited test child");
    let cleanup_state = ProjectionCleanupState {
        kernel: Arc::downgrade(&kernel),
        stop_policy: crate::storage_mount::process_broker::ProcessStopPolicy::default(),
        binding: binding.clone(),
        branch: ProjectionLeaseProvider {
            running: RunningProvider {
                child: Some(child),
                control_path: control_path.clone(),
                token: "test-token".to_owned(),
                stopped: false,
            },
            lease: ProjectionLeaseTarget {
                mount_id: astrid_core::storage_provider::StorageMountId::new(),
                target: binding.targets.owner_home.clone(),
            },
        },
        owner: ProjectionLeaseProvider {
            running: RunningProvider {
                child: None,
                control_path: mount_root.join("absent.sock"),
                token: "test-token".to_owned(),
                stopped: true,
            },
            lease: ProjectionLeaseTarget {
                mount_id: astrid_core::storage_provider::StorageMountId::new(),
                target: binding.targets.workspace.clone(),
            },
        },
        shared: None,
        mount_root: mount_root.clone(),
        cleaned: false,
    };
    let mut projections = BTreeMap::new();
    retain_failed_launch_projection(
        &mut projections,
        &key,
        temporary.path().join("workspace"),
        temporary.path().join("owner"),
        None,
        cleanup_state,
    );

    let projection = Arc::clone(projections.get(&key).expect("retained blocker"));
    let mut guard = projections;
    let stopped = retry_failed_projection(&projection, &mut guard, &key).await;
    assert!(!stopped, "a provider that remained ready must stay blocked");
    assert!(
        guard.contains_key(&key),
        "otherwise-successful lease cleanup must not remove the unreaped-provider blocker"
    );
    assert!(
        kernel.storage_mounts.is_empty(),
        "the blocker must remain authoritative without a live lease"
    );
    assert!(mount_root.exists(), "failed STOP must retain the UUID root");

    // Closing the owning listener is causal endpoint-death evidence on both
    // platforms. Unix may leave a stale pathname; Windows must not require
    // pathname persistence to release the retained projection.
    drop(listener);
    tokio::time::timeout(RESPONDER_JOIN_TIMEOUT, responder)
        .await
        .expect("one-shot responder joins boundedly")
        .expect("stop responder task")
        .expect("stop responder completed");
    assert!(
        retry_failed_projection(&projection, &mut guard, &key).await,
        "retry must complete after the provider endpoint is gone"
    );
    assert!(!guard.contains_key(&key));
    assert!(!mount_root.exists());
}

#[cfg(unix)]
fn is_peer_closed(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::NotConnected
            | std::io::ErrorKind::ConnectionReset
    )
}

#[cfg(unix)]
fn spawn_ready_responder(
    control_path: &Path,
) -> (
    ResponderControl,
    tokio::task::JoinHandle<Result<(), String>>,
) {
    use tokio::io::AsyncWriteExt as _;

    let listener = tokio::net::UnixListener::bind(control_path).expect("bind live endpoint");
    let control = ResponderControl::new();
    let responder_control = control.clone();
    let responder = tokio::spawn(async move {
        loop {
            let mut stream = tokio::select! {
                () = responder_control.release.wait_for(true) => return Ok(()),
                accepted = listener.accept() => match accepted {
                    Ok((stream, _)) => stream,
                    Err(error) if is_peer_closed(&error) => return Ok(()),
                    Err(error) => return Err(format!("accept stop request: {error}")),
                },
            };
            let answer = async {
                stream.write_all(b"{\"status\":\"ready\"}\n").await?;
                stream.flush().await
            };
            match answer.await {
                Ok(()) => {},
                Err(error) if is_peer_closed(&error) => return Ok(()),
                Err(error) => return Err(format!("write stop refusal: {error}")),
            }

            responder_control.between_responses.set(true);
            tokio::select! {
                () = responder_control.release.wait_for(true) => return Ok(()),
                () = responder_control.advance.wait_for(true) => {},
            }
            responder_control.between_responses.set(false);
        }
    });
    (control, responder)
}

#[cfg(unix)]
async fn join_ready_responder(responder: tokio::task::JoinHandle<Result<(), String>>) {
    tokio::time::timeout(RESPONDER_JOIN_TIMEOUT, responder)
        .await
        .expect("responder joins before the bounded deadline")
        .expect("responder task")
        .expect("responder completed without an unexpected peer error");
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn watch_release_cannot_be_lost_between_response_and_accept() {
    use astrid_core::local_transport;
    use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};

    let scratch = tempfile::tempdir().expect("control scratch");
    let control_path = scratch.path().join("process-control.sock");
    let (control, responder) = spawn_ready_responder(&control_path);
    let mut stream = local_transport::connect(&control_path)
        .await
        .expect("connect control endpoint");
    stream
        .write_all(b"{\"operation\":\"stop\",\"token\":\"unused\"}\n")
        .await
        .expect("send stop request");
    stream.flush().await.expect("flush stop request");
    let mut line = String::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        tokio::io::BufReader::new(stream).read_line(&mut line),
    )
    .await
    .expect("read refusal before its bounded deadline")
    .expect("read stop refusal");
    assert_eq!(line, "{\"status\":\"ready\"}\n");

    control.between_responses.wait_for(true).await;
    control.release_once();
    control.advance.set(true);
    join_ready_responder(responder).await;
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn notify_waiters_between_response_and_registration_is_lost() {
    use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};

    let scratch = tempfile::tempdir().expect("lost-notify scratch");
    let control_path = scratch.path().join("process-control.sock");
    let listener =
        tokio::net::UnixListener::bind(&control_path).expect("bind lost-notify endpoint");
    let release = Arc::new(tokio::sync::Notify::new());
    let between = Arc::new(tokio::sync::Notify::new());
    let gate = Arc::new(tokio::sync::Notify::new());
    let (cancellation, mut cancellation_receiver) = tokio::sync::watch::channel(false);
    let responder = {
        let release = Arc::clone(&release);
        let between = Arc::clone(&between);
        let gate = Arc::clone(&gate);
        tokio::spawn(async move {
            let result = async {
                let (mut stream, _) = listener.accept().await?;
                stream.write_all(b"{\"status\":\"ready\"}\n").await?;
                stream.flush().await
            };
            if let Err(error) = result.await {
                return Err(format!("write lost-notify refusal: {error}"));
            }
            between.notify_one();
            gate.notified().await;
            let release_registration = release.notified();
            tokio::pin!(release_registration);
            tokio::select! {
                () = &mut release_registration => Ok(()),
                _ = cancellation_receiver.changed() => {
                    Err("cancelled after missed notify".to_owned())
                },
            }
        })
    };

    let between_arrival = between.notified();
    tokio::pin!(between_arrival);
    let stream = tokio::net::UnixStream::connect(&control_path)
        .await
        .expect("connect lost-notify control endpoint");
    let mut line = String::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        tokio::io::BufReader::new(stream).read_line(&mut line),
    )
    .await
    .expect("read lost-notify response")
    .expect("read stop refusal");
    assert_eq!(line, "{\"status\":\"ready\"}\n");

    // The responder sends this permit after its response and before waiting
    // on the gate, which is exactly the gap where notify_waiters is lost.
    tokio::time::timeout(std::time::Duration::from_secs(1), &mut between_arrival)
        .await
        .expect("responder reaches the between-response barrier");
    gate.notify_one();

    release.notify_waiters();
    let lost_join = responder;
    tokio::pin!(lost_join);
    let lost = tokio::time::timeout(RESPONDER_JOIN_TIMEOUT, &mut lost_join).await;
    assert!(lost.is_err(), "notify_waiters before registration was lost");
    cancellation.send_replace(true);
    let cancelled = tokio::time::timeout(std::time::Duration::from_secs(1), &mut lost_join)
        .await
        .expect("cancelled lost-notify responder joins boundedly")
        .expect("lost-notify task")
        .expect_err("cancelled responder reports cancellation");
    assert_eq!(cancelled, "cancelled after missed notify");
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_stop_returns_rollback_promptly_when_descendant_holds_stderr() {
    use super::{abort_process_provider, diagnostics_launch};

    let scratch = tempfile::tempdir().expect("diagnostics scratch");
    let (_home_root, kernel) = super::fleet_shared_kernel().await;
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
        super::retry_failed_projection(&projection, &mut projections, &key).await,
        "explicit endpoint release must admit exact retained-authority retry"
    );
    assert!(!projections.contains_key(&key));
    assert!(
        !mount_root.exists(),
        "successful retry must remove the exact retained root"
    );
    holder.terminate_and_reap().await;
}

#[cfg(unix)]
async fn retain_fixture_rollback(
    kernel: &Arc<crate::Kernel>,
    binding: &super::ProcessProjectionBinding,
    key: &ProcessProjectionKey,
    control_path: std::path::PathBuf,
    mount_root: std::path::PathBuf,
    scratch: &tempfile::TempDir,
) -> BTreeMap<
    ProcessProjectionKey,
    Arc<crate::storage_mount::process_broker::CachedProcessProjection>,
> {
    let cleanup_state =
        super::retained_cleanup_state(kernel, binding, None, control_path, mount_root, scratch);
    let mut projections = BTreeMap::new();
    super::rollback_or_retain_failed_launch(
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
struct TestChildSubreaper;

#[cfg(target_os = "linux")]
impl TestChildSubreaper {
    fn new() -> Self {
        nix::sys::prctl::set_child_subreaper(true)
            .expect("make test process the detached-PID subreaper");
        Self
    }
}

#[cfg(target_os = "linux")]
impl Drop for TestChildSubreaper {
    fn drop(&mut self) {
        nix::sys::prctl::set_child_subreaper(false)
            .expect("restore the test-process child-subreaper policy");
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
async fn reap_detached_holder(pid: u32) {
    use nix::sys::signal::Signal;
    use nix::sys::wait::{WaitStatus, waitpid};

    let raw_pid = i32::try_from(pid).expect("bounded detached-holder PID");
    let target = nix::unistd::Pid::from_raw(raw_pid);
    nix::sys::signal::kill(target, Signal::SIGTERM)
        .expect("terminate historical detached stderr holder");
    let started = tokio::time::Instant::now();
    loop {
        match waitpid(target, None) {
            Ok(WaitStatus::Signaled(_, Signal::SIGTERM, _)) => return,
            Ok(status) => panic!("unexpected detached-holder status: {status:?}"),
            Err(nix::errno::Errno::ECHILD) => {
                panic!("subreaper did not adopt the historical detached holder")
            },
            Err(error) => panic!("reap historical detached holder: {error}"),
        }
    }
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn historical_detached_pid_shell_holds_stderr_until_explicit_reap() {
    use std::sync::atomic::Ordering;

    let subreaper = TestChildSubreaper::new();
    let scratch = tempfile::tempdir().expect("historical fixture scratch");
    let pid_path = scratch.path().join("stderr-holder.pid");
    let mut shell = OwnedTestChild::new(
        tokio::process::Command::new("/bin/sh")
            .arg("-c")
            .arg("sleep 30 2>&1 & echo $! > \"$1\"")
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
    shell.wait().await;

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

    reap_detached_holder(holder_pid).await;
    let bytes = tokio::time::timeout(std::time::Duration::from_secs(1), stderr_task)
        .await
        .expect("historical stderr reader completes after explicit reap")
        .expect("historical stderr reader task");
    assert!(bytes.is_empty(), "historical stderr contained no output");
    assert!(
        reader.completed.load(Ordering::Acquire),
        "historical reader normal completion was not observed"
    );
    drop(subreaper);
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
