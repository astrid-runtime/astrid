//! Discovery, launch, and readiness for the coinstalled process provider.

#[cfg(all(test, any(unix, windows)))]
use std::collections::BTreeMap;

use super::*;

pub(super) struct ProcessProviderLaunchError {
    pub(super) message: String,
    pub(super) cleanup_ok: bool,
    /// Retained only when cleanup failed. A successful cleanup is defined by
    /// `stop_process_provider`: STOP/reap completion plus a dead endpoint.
    /// Keeping the handle here makes a failed cleanup retryable against the
    /// exact provider instead of leaving an unobservable live process.
    pub(super) child: Option<Box<tokio::process::Child>>,
}

/// Fixed, non-configurable denial-of-service hard guard: a descendant holding
/// stderr cannot stall rollback past this deadline.
const PROVIDER_DIAGNOSTICS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);
/// Fixed protocol hard guard: readiness must arrive inside one bounded frame.
const PROVIDER_READY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

type SpawnedProcessProvider = (
    tokio::process::Child,
    Option<tokio::task::JoinHandle<Vec<u8>>>,
);

/// The deterministic provider startup stage represented by one launch.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum ProcessLaunchStage {
    Branch,
    OwnerHome,
    FleetShared,
}

impl ProcessLaunchStage {
    #[cfg(all(test, any(unix, windows)))]
    pub(crate) const fn as_u8(self) -> u8 {
        match self {
            Self::Branch => 1,
            Self::OwnerHome => 2,
            Self::FleetShared => 3,
        }
    }
}

#[cfg(all(test, any(unix, windows)))]
impl ProcessLaunchStage {
    pub(crate) const fn is_before(self, target: Self) -> bool {
        self.as_u8() < target.as_u8()
    }
}

#[cfg(all(test, any(unix, windows)))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LaunchFaultKind {
    Clean,
    EndpointRetained,
}

#[cfg(all(test, any(unix, windows)))]
static LAUNCH_FAILURES: std::sync::Mutex<BTreeMap<u64, ProcessLaunchStage>> =
    std::sync::Mutex::new(BTreeMap::new());

#[cfg(all(test, any(unix, windows)))]
static LAUNCH_FAILURE_KINDS: std::sync::Mutex<BTreeMap<u64, LaunchFaultKind>> =
    std::sync::Mutex::new(BTreeMap::new());

#[cfg(all(test, any(unix, windows)))]
static SPAWNED_PROVIDER_PIDS: std::sync::Mutex<BTreeMap<u64, BTreeMap<ProcessLaunchStage, u32>>> =
    std::sync::Mutex::new(BTreeMap::new());

#[cfg(all(test, any(unix, windows)))]
static PUBLISHED_PROVIDER_LEASES: std::sync::Mutex<
    BTreeMap<u64, BTreeMap<ProcessLaunchStage, StorageMountId>>,
> = std::sync::Mutex::new(BTreeMap::new());

#[cfg(all(test, any(unix, windows)))]
struct RetainedLaunchEndpoint {
    release: Arc<tokio::sync::Notify>,
    responder: tokio::task::JoinHandle<()>,
}

#[cfg(all(test, any(unix, windows)))]
static RETAINED_LAUNCH_ENDPOINTS: std::sync::Mutex<BTreeMap<u64, RetainedLaunchEndpoint>> =
    std::sync::Mutex::new(BTreeMap::new());

#[cfg(all(test, any(unix, windows)))]
pub(crate) fn arm_launch_failure(stage: ProcessLaunchStage, test_id: u64) {
    LAUNCH_FAILURES
        .lock()
        .expect("launch failure selector")
        .insert(test_id, stage);
    LAUNCH_FAILURE_KINDS
        .lock()
        .expect("launch failure modes")
        .insert(test_id, LaunchFaultKind::Clean);
}

#[cfg(all(test, any(unix, windows)))]
pub(crate) fn launch_failure_matches(stage: ProcessLaunchStage, current_test_id: u64) -> bool {
    let mut failures = LAUNCH_FAILURES.lock().expect("launch failure selector");
    if failures.get(&current_test_id) != Some(&stage) {
        return false;
    }
    failures.remove(&current_test_id);
    LAUNCH_FAILURE_KINDS
        .lock()
        .expect("launch failure modes")
        .remove(&current_test_id);
    true
}

#[cfg(all(test, any(unix, windows)))]
pub(crate) fn arm_launch_cleanup_failure(stage: ProcessLaunchStage, test_id: u64) {
    LAUNCH_FAILURES
        .lock()
        .expect("launch failure selector")
        .insert(test_id, stage);
    LAUNCH_FAILURE_KINDS
        .lock()
        .expect("launch failure modes")
        .insert(test_id, LaunchFaultKind::EndpointRetained);
}

#[cfg(all(test, any(unix, windows)))]
fn selected_launch_failure(test_id: u64) -> Option<ProcessLaunchStage> {
    LAUNCH_FAILURES
        .lock()
        .expect("launch failure selector")
        .get(&test_id)
        .copied()
}

#[cfg(all(test, any(unix, windows)))]
fn spawn_long_lived_test_provider() -> Result<tokio::process::Child, ProcessProviderLaunchError> {
    let mut command = if cfg!(unix) {
        let mut command = tokio::process::Command::new("sleep");
        command.arg("30");
        command
    } else {
        let mut command = tokio::process::Command::new("ping");
        command.args(["-n", "31", "127.0.0.1"]);
        command
    };
    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    command.spawn().map_err(|error| ProcessProviderLaunchError {
        message: format!("launch test-only prior provider: {error}"),
        cleanup_ok: true,
        child: None,
    })
}

#[cfg(all(test, any(unix, windows)))]
fn record_spawned_provider(test_id: u64, stage: ProcessLaunchStage, pid: u32) {
    SPAWNED_PROVIDER_PIDS
        .lock()
        .expect("spawned provider PIDs")
        .entry(test_id)
        .or_default()
        .insert(stage, pid);
}

#[cfg(all(test, any(unix, windows)))]
pub(crate) fn record_published_test_lease(
    stage: ProcessLaunchStage,
    lease_mount_id: StorageMountId,
) {
    let test_id = super::PROCESS_MOUNT_TEST_ID
        .try_with(|test_id| *test_id)
        .unwrap_or_default();
    PUBLISHED_PROVIDER_LEASES
        .lock()
        .expect("launched provider leases")
        .entry(test_id)
        .or_default()
        .insert(stage, lease_mount_id);
}

#[cfg(all(test, any(unix, windows)))]
pub(crate) fn spawned_provider_pids(test_id: u64) -> BTreeMap<ProcessLaunchStage, u32> {
    SPAWNED_PROVIDER_PIDS
        .lock()
        .expect("spawned provider PIDs")
        .get(&test_id)
        .cloned()
        .unwrap_or_default()
}

#[cfg(all(test, any(unix, windows)))]
pub(crate) fn published_provider_leases(
    test_id: u64,
) -> BTreeMap<ProcessLaunchStage, StorageMountId> {
    PUBLISHED_PROVIDER_LEASES
        .lock()
        .expect("launched provider leases")
        .get(&test_id)
        .cloned()
        .unwrap_or_default()
}

#[cfg(all(test, any(unix, windows)))]
fn retain_launch_failure_endpoint(
    test_id: u64,
    launch: &StorageProviderServiceLaunchV1,
) -> Result<(), String> {
    let listener = local_transport::bind(&launch.control_path)
        .map_err(|error| format!("bind retained test control endpoint: {error}"))?;
    let release = Arc::new(tokio::sync::Notify::new());
    let responder = tokio::spawn({
        let release = Arc::clone(&release);
        async move {
            loop {
                let mut stream = tokio::select! {
                    () = release.notified() => return,
                    accepted = local_transport::accept(&listener) => match accepted {
                        Ok(stream) => stream,
                        // Windows availability probes can consume and close an
                        // accept instance before transport authentication. The
                        // backend replenishes the listener; retain the endpoint.
                        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                            continue;
                        },
                        Err(_) => return,
                    },
                };

                // Transport authentication happens inside Windows accept. On
                // Unix, the 0600 socket already limits peers; requiring a
                // payload byte distinguishes an authenticated caller from a
                // connect-and-drop availability probe.
                let mut first_byte = [0_u8; 1];
                let read_payload = stream.read_exact(&mut first_byte);
                let read = tokio::select! {
                    () = release.notified() => return,
                    read = read_payload => read,
                };
                match read {
                    Ok(_) => {},
                    Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => continue,
                    Err(_) => return,
                }
                let answered = async {
                    stream.write_all(b"{\"status\":\"ready\"}\n").await.is_ok()
                        && stream.flush().await.is_ok()
                };
                tokio::select! {
                    () = release.notified() => return,
                    _ = answered => {},
                }
                release.notified().await;
            }
        }
    });
    RETAINED_LAUNCH_ENDPOINTS
        .lock()
        .expect("retained launch endpoints")
        .insert(test_id, RetainedLaunchEndpoint { release, responder });
    Ok(())
}

#[cfg(all(test, any(unix, windows)))]
pub(crate) async fn release_launch_cleanup_failure(test_id: u64) {
    let endpoint = RETAINED_LAUNCH_ENDPOINTS
        .lock()
        .expect("retained launch endpoints")
        .remove(&test_id);
    if let Some(endpoint) = endpoint {
        endpoint.release.notify_one();
        endpoint
            .responder
            .await
            .expect("retained endpoint responder");
    }
}

pub(crate) fn platform_process_provider_name() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "astrid-storage-provider-fuse"
    }
    #[cfg(target_os = "macos")]
    {
        "astrid-storage-provider-fskit"
    }
    #[cfg(windows)]
    {
        "astrid-storage-provider-winfsp"
    }
}

fn platform_process_provider_argument() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "--astrid-provider-fuse-service-v1"
    }
    #[cfg(target_os = "macos")]
    {
        "--astrid-provider-fskit-service-v1"
    }
    #[cfg(windows)]
    {
        "--astrid-provider-winfsp-service-v1"
    }
}

fn find_process_provider(name: &str) -> Result<PathBuf, String> {
    let executable = std::env::current_exe()
        .map_err(|error| format!("resolve kernel executable for storage provider: {error}"))?;
    let directory = executable
        .parent()
        .ok_or_else(|| "kernel executable has no installation directory".to_owned())?;
    let candidate = directory.join(format!("{name}{}", std::env::consts::EXE_SUFFIX));
    validate_process_provider_binary(&candidate)?;
    Ok(candidate)
}

fn validate_process_provider_binary(candidate: &Path) -> Result<(), String> {
    let metadata = std::fs::symlink_metadata(candidate)
        .map_err(|error| format!("inspect coinstalled storage provider: {error}"))?;
    if !metadata.file_type().is_file() {
        return Err("coinstalled storage provider is not a regular non-symlink file".to_owned());
    }
    astrid_core::platform_fs::verify_no_redirects(candidate)
        .map_err(|error| format!("validate coinstalled storage provider path: {error}"))?;
    #[cfg(windows)]
    astrid_core::platform_fs::validate_trusted_file(candidate)
        .map_err(|error| format!("validate coinstalled storage provider executable: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(
                "coinstalled storage provider is group/world writable and not trusted".to_owned(),
            );
        }
    }
    Ok(())
}

fn spawn_process_provider() -> Result<SpawnedProcessProvider, ProcessProviderLaunchError> {
    let binary = find_process_provider(platform_process_provider_name()).map_err(|message| {
        ProcessProviderLaunchError {
            message,
            cleanup_ok: true,
            child: None,
        }
    })?;
    let mut command = tokio::process::Command::new(binary);
    command
        .arg(platform_process_provider_argument())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|error| ProcessProviderLaunchError {
            message: format!("launch native storage provider: {error}"),
            cleanup_ok: true,
            child: None,
        })?;
    let stderr_task = child.stderr.take().map(|stderr| {
        tokio::spawn(async move {
            let mut bytes = Vec::new();
            let _ = stderr
                .take((64 * 1024 + 1) as u64)
                .read_to_end(&mut bytes)
                .await;
            bytes.truncate(64 * 1024);
            bytes
        })
    });
    Ok((child, stderr_task))
}

async fn send_process_provider_payload(
    mut child: tokio::process::Child,
    launch: &StorageProviderServiceLaunchV1,
    payload: Vec<u8>,
    stderr_task: Option<tokio::task::JoinHandle<Vec<u8>>>,
    stop_policy: super::ProcessStopPolicy,
) -> Result<SpawnedProcessProvider, ProcessProviderLaunchError> {
    let Some(mut stdin) = child.stdin.take() else {
        return Err(abort_process_provider(
            child,
            launch,
            "native storage provider stdin unavailable".to_owned(),
            stderr_task,
            stop_policy,
        )
        .await);
    };
    if let Err(error) = stdin.write_all(&payload).await {
        return Err(abort_process_provider(
            child,
            launch,
            format!("send native storage provider launch: {error}"),
            stderr_task,
            stop_policy,
        )
        .await);
    }
    Ok((child, stderr_task))
}

pub(super) async fn launch_process_provider(
    launch: &StorageProviderServiceLaunchV1,
    stage: ProcessLaunchStage,
    stop_policy: super::ProcessStopPolicy,
) -> Result<tokio::process::Child, ProcessProviderLaunchError> {
    #[cfg(not(all(test, any(unix, windows))))]
    let _ = stage;

    #[cfg(all(test, any(unix, windows)))]
    {
        let current_test_id = super::PROCESS_MOUNT_TEST_ID
            .try_with(|test_id| *test_id)
            .unwrap_or_default();
        if let Some(selected_stage) = selected_launch_failure(current_test_id) {
            if stage == selected_stage {
                let cleanup_failure = LAUNCH_FAILURE_KINDS
                    .lock()
                    .expect("launch failure modes")
                    .get(&current_test_id)
                    == Some(&LaunchFaultKind::EndpointRetained);
                if launch_failure_matches(stage, current_test_id) {
                    record_published_test_lease(stage, launch.lease.mount_id);
                    if cleanup_failure {
                        if let Err(error) = retain_launch_failure_endpoint(current_test_id, launch)
                        {
                            return Err(ProcessProviderLaunchError {
                                message: error,
                                cleanup_ok: true,
                                child: None,
                            });
                        }
                        return Err(ProcessProviderLaunchError {
                            message: "injected retained-endpoint launch failure".to_owned(),
                            cleanup_ok: false,
                            child: None,
                        });
                    }
                    return Err(ProcessProviderLaunchError {
                        message: "injected post-publication launch failure".to_owned(),
                        cleanup_ok: true,
                        child: None,
                    });
                }
            } else if stage.is_before(selected_stage) {
                return spawn_long_lived_test_provider().inspect(|child| {
                    record_spawned_provider(
                        current_test_id,
                        stage,
                        child.id().expect("fresh test provider reports a PID"),
                    );
                });
            }
        }
    }

    let (child, stderr_task) = spawn_process_provider()?;
    let payload = match serde_json::to_vec(launch) {
        Ok(payload) => payload,
        Err(error) => {
            return Err(abort_process_provider(
                child,
                launch,
                format!("encode native storage provider launch: {error}"),
                stderr_task,
                stop_policy,
            )
            .await);
        },
    };
    let (child, stderr_task) =
        send_process_provider_payload(child, launch, payload, stderr_task, stop_policy).await?;
    read_process_provider_ready(child, launch, stderr_task, stop_policy).await
}

async fn read_process_provider_ready(
    mut child: tokio::process::Child,
    launch: &StorageProviderServiceLaunchV1,
    stderr_task: Option<tokio::task::JoinHandle<Vec<u8>>>,
    stop_policy: super::ProcessStopPolicy,
) -> Result<tokio::process::Child, ProcessProviderLaunchError> {
    let Some(stdout) = child.stdout.take() else {
        return Err(abort_process_provider(
            child,
            launch,
            "native storage provider stdout unavailable".to_owned(),
            stderr_task,
            stop_policy,
        )
        .await);
    };
    let mut line = String::new();
    let reader = tokio::io::BufReader::new(stdout);
    let read = match tokio::time::timeout(
        PROVIDER_READY_TIMEOUT,
        reader.take((64 * 1024 + 1) as u64).read_line(&mut line),
    )
    .await
    {
        Ok(Ok(read)) => read,
        Ok(Err(error)) => {
            return Err(abort_process_provider(
                child,
                launch,
                format!("read native storage provider readiness: {error}"),
                stderr_task,
                stop_policy,
            )
            .await);
        },
        Err(_) => {
            return Err(abort_process_provider(
                child,
                launch,
                "timed out waiting for native storage provider readiness".to_owned(),
                stderr_task,
                stop_policy,
            )
            .await);
        },
    };
    if read > 64 * 1024 || !line.ends_with('\n') {
        return Err(abort_process_provider(
            child,
            launch,
            "native storage provider readiness frame is malformed or oversized".to_owned(),
            stderr_task,
            stop_policy,
        )
        .await);
    }
    let line = line.strip_suffix('\n').unwrap_or(&line);
    let line = line.strip_suffix('\r').unwrap_or(line);
    if let Err(error) = validate_process_provider_ready(launch, line) {
        return Err(abort_process_provider(child, launch, error, stderr_task, stop_policy).await);
    }
    drop(stderr_task);
    Ok(child)
}

pub(super) async fn abort_process_provider(
    mut child: tokio::process::Child,
    launch: &StorageProviderServiceLaunchV1,
    message: String,
    stderr_task: Option<tokio::task::JoinHandle<Vec<u8>>>,
    stop_policy: super::ProcessStopPolicy,
) -> ProcessProviderLaunchError {
    let cleanup_ok = stop_process_provider(
        &mut child,
        launch.control_path.clone(),
        launch.parent.token.clone(),
        stop_policy,
    )
    .await;
    let mut diagnostics_timeout = false;
    let diagnostics = match stderr_task {
        Some(mut task) => {
            let bytes = match tokio::time::timeout(PROVIDER_DIAGNOSTICS_TIMEOUT, &mut task).await {
                Ok(Ok(bytes)) => Some(bytes),
                // A descendant can inherit stderr after the provider child is
                // reaped. Diagnostics are advisory; rollback must not wait on
                // that unrelated lifetime.
                Err(_) => {
                    task.abort();
                    diagnostics_timeout = true;
                    None
                },
                Ok(Err(_)) => None,
            };
            bytes.and_then(|bytes| {
                (!bytes.is_empty()).then(|| String::from_utf8_lossy(&bytes).trim().to_owned())
            })
        },
        None => None,
    };
    let message = if let Some(diagnostics) = diagnostics {
        format!("{message}; provider diagnostics: {diagnostics}")
    } else if diagnostics_timeout {
        format!("{message}; provider diagnostics timed out")
    } else {
        message.clone()
    };
    ProcessProviderLaunchError {
        message,
        cleanup_ok,
        child: (!cleanup_ok).then_some(Box::new(child)),
    }
}

pub(crate) fn validate_process_provider_ready(
    launch: &StorageProviderServiceLaunchV1,
    line: &str,
) -> Result<(), String> {
    if line.len() > 64 * 1024 {
        return Err("native storage provider readiness exceeds the bounded frame".to_owned());
    }
    let ready: StorageProviderServiceReadyV1 = serde_json::from_str(line)
        .map_err(|error| format!("decode native storage provider readiness: {error}"))?;
    let canonical = serde_json::to_string(&ready)
        .map_err(|error| format!("encode native storage provider readiness: {error}"))?;
    if canonical != line {
        return Err("native storage provider readiness is not canonical JSON".to_owned());
    }
    if ready.schema != STORAGE_FILESYSTEM_SERVICE_READY_SCHEMA_V1
        || ready.provider != platform_process_provider_name()
        || ready.mount_id != launch.lease.mount_id.as_uuid()
        || ready.control_path != launch.control_path
    {
        return Err("native storage provider readiness identity mismatch".to_owned());
    }
    let expected = storage_provider_service_ready_challenge(
        &launch.parent.token,
        STORAGE_FILESYSTEM_SERVICE_READY_SCHEMA_V1,
        platform_process_provider_name(),
        launch.lease.mount_id.as_uuid(),
        &launch.control_path,
        &launch.lease.resource_path,
        &launch.lease.callback_path,
    )
    .map_err(|error| format!("derive native storage provider readiness challenge: {error}"))?;
    if !bool::from(expected.as_bytes().ct_eq(ready.challenge.as_bytes())) {
        return Err("native storage provider readiness challenge mismatch".to_owned());
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn provider_binary_validation_rejects_group_or_world_writable_files() {
        let temporary = tempfile::tempdir().expect("provider fixture root");
        let provider = temporary.path().join("astrid-storage-provider");
        std::fs::write(&provider, b"provider").expect("provider fixture");
        std::fs::set_permissions(&provider, std::fs::Permissions::from_mode(0o755))
            .expect("trusted provider mode");
        validate_process_provider_binary(&provider).expect("trusted provider accepted");

        std::fs::set_permissions(&provider, std::fs::Permissions::from_mode(0o775))
            .expect("unsafe provider mode");
        let error = validate_process_provider_binary(&provider)
            .expect_err("group-writable provider must fail closed");
        assert!(error.contains("group/world writable"));
    }
}
