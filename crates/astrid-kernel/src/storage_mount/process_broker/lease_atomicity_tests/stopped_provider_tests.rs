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
struct UnrelatedStderrHolder {
    child: tokio::process::Child,
}

#[cfg(unix)]
impl UnrelatedStderrHolder {
    async fn terminate_and_reap(mut self) {
        use std::os::unix::process::ExitStatusExt as _;

        self.child
            .kill()
            .await
            .expect("terminate unrelated stderr holder");
        let status = self
            .child
            .wait()
            .await
            .expect("reap unrelated stderr holder");
        assert_eq!(
            status.signal(),
            Some(9),
            "stderr holder must be deterministically killed and reaped"
        );
    }
}

#[cfg(unix)]
impl Drop for UnrelatedStderrHolder {
    fn drop(&mut self) {
        // Explicit termination is the fixture contract; this only prevents a
        // test panic from leaking a live descendant.
        let _ = self.child.start_kill();
    }
}

#[cfg(unix)]
struct StderrLifetimeFixture {
    provider: tokio::process::Child,
    holder: UnrelatedStderrHolder,
    stderr_task: Option<tokio::task::JoinHandle<Vec<u8>>>,
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
        .spawn()
        .expect("spawn provider child with shared stderr");
    let stderr_task = tokio::spawn(async move {
        use tokio::io::AsyncReadExt as _;

        let mut bytes = Vec::new();
        let _ = parent_stderr.read_to_end(&mut bytes).await;
        bytes
    });
    StderrLifetimeFixture {
        provider,
        holder: UnrelatedStderrHolder { child: holder },
        stderr_task: Some(stderr_task),
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
        let mut stream = local_transport::accept(&responder_listener)
            .await
            .expect("accept stop request");
        stream
            .write_all(b"{\"status\":\"ready\"}\n")
            .await
            .expect("write stop refusal");
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
    responder.await.expect("stop responder");
    assert!(
        retry_failed_projection(&projection, &mut guard, &key).await,
        "retry must complete after the provider endpoint is gone"
    );
    assert!(!guard.contains_key(&key));
    assert!(!mount_root.exists());
}

#[cfg(unix)]
fn spawn_ready_responder(
    control_path: &Path,
) -> (Arc<tokio::sync::Notify>, tokio::task::JoinHandle<()>) {
    use tokio::io::AsyncWriteExt as _;

    fn is_peer_closed(error: &std::io::Error) -> bool {
        matches!(
            error.kind(),
            std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::NotConnected
                | std::io::ErrorKind::ConnectionReset
        )
    }

    let listener = tokio::net::UnixListener::bind(control_path).expect("bind live endpoint");
    let release = Arc::new(tokio::sync::Notify::new());
    let release_for_responder = Arc::clone(&release);
    let responder = tokio::spawn(async move {
        loop {
            let mut stream = tokio::select! {
                () = release_for_responder.notified() => return,
                accepted = listener.accept() => match accepted {
                    Ok((stream, _)) => stream,
                    Err(error) if is_peer_closed(&error) => return,
                    Err(_) => return,
                },
            };
            let write = async {
                stream.write_all(b"{\"status\":\"ready\"}\n").await?;
                stream.flush().await
            };
            if let Err(error) = write.await
                && !is_peer_closed(&error)
            {
                panic!("write stop refusal: {error}");
            }
        }
    });
    (release, responder)
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_stop_returns_rollback_promptly_when_descendant_holds_stderr() {
    use super::{abort_process_provider, diagnostics_launch, retained_cleanup_state};

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
        provider: child,
        holder,
        mut stderr_task,
    } = spawn_stderr_lifetime_fixture();
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
            child,
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

    let cleanup_state = retained_cleanup_state(
        &kernel,
        &binding,
        error.child,
        control_path.clone(),
        mount_root.clone(),
        &scratch,
    );
    let mut projections = BTreeMap::new();
    super::rollback_or_retain_failed_launch(
        &mut projections,
        &key,
        scratch.path().join("workspace"),
        scratch.path().join("owner"),
        None,
        cleanup_state,
    )
    .await;
    let projection = Arc::clone(projections.get(&key).expect("authoritative blocker"));
    assert!(
        projection
            .cleanup_failed
            .load(std::sync::atomic::Ordering::Acquire)
    );
    assert!(
        mount_root.exists(),
        "failed STOP must retain the exact UUID root"
    );
    release.notify_waiters();
    responder
        .await
        .expect("retained endpoint responder completed");

    holder.terminate_and_reap().await;
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn old_stderr_fixture_lifetime_hangs_until_holder_release() {
    let StderrLifetimeFixture {
        holder,
        stderr_task,
        ..
    } = spawn_stderr_lifetime_fixture();
    let Some(mut stderr_task) = stderr_task else {
        panic!("stderr fixture owns its diagnostic reader");
    };

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
}
