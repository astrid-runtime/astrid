#![allow(unsafe_code)]

use std::io::{Read as _, Write as _};
use std::os::windows::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result, bail};
use astrid_core::local_transport;
use astrid_core::platform_fs;
use astrid_core::storage_filesystem::{
    STORAGE_FILESYSTEM_PROTOCOL_V2, STORAGE_FILESYSTEM_SERVICE_LAUNCH_SCHEMA_V1,
    STORAGE_FILESYSTEM_SERVICE_READY_SCHEMA_V1, StorageFilesystemFailureV1,
    StorageFilesystemOperationV2, StorageFilesystemOutcomeV2, StorageFilesystemRequestV2,
    StorageFilesystemResponseV2, StorageMountLeaseV1, StorageProviderServiceLaunchV1,
    StorageProviderServiceReadyV1, storage_provider_service_ready_challenge,
};
use astrid_core::storage_provider::StorageProviderAccessV1;
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _};
use widestring::U16CString;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::System::LibraryLoader::LoadLibraryW;
use windows_sys::Win32::System::Threading::{
    CREATE_NEW_PROCESS_GROUP, DETACHED_PROCESS, GetExitCodeProcess, OpenProcess,
    PROCESS_QUERY_LIMITED_INFORMATION,
};
use winfsp_wrs::{FileSystem, OperationGuardStrategy, Params, VolumeParams};

use crate::callback::endpoint_is_present;
use crate::{DAEMON_ARGUMENT, PROVIDER_NAME, provider_control_path};

mod filesystem;

use filesystem::CallbackFs;

const DAEMON_READY_TIMEOUT: Duration = Duration::from_secs(30);
const DAEMON_STOP_TIMEOUT: Duration = Duration::from_secs(30);
const MOUNTPOINT_READY_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_LEASE_BYTES: u64 = 64 * 1024;

#[derive(serde::Deserialize, serde::Serialize)]
struct DaemonStart {
    lease: StorageMountLeaseV1,
    mountpoint: PathBuf,
}

pub(crate) fn daemon_main() -> Result<()> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .lock()
        .take(MAX_LEASE_BYTES + 1)
        .read_to_end(&mut bytes)
        .context("read WinFsp daemon lease")?;
    if bytes.len() as u64 > MAX_LEASE_BYTES {
        bail!("WinFsp daemon lease exceeds limit");
    }
    let start: DaemonStart =
        serde_json::from_slice(&bytes).context("decode WinFsp daemon lease")?;
    let lease = start.lease;
    if (!start.mountpoint.is_absolute() && !is_drive_designator(&start.mountpoint))
        || !lease.callback_path.is_absolute()
    {
        bail!("WinFsp daemon lease contains a relative endpoint");
    }

    let runtime = Arc::new(start_provider_runtime("WinFsp callback runtime")?);
    let callback = CallbackFs::new(lease.clone(), Arc::clone(&runtime))
        .map_err(|failure| anyhow::anyhow!("build WinFsp callback filesystem: {failure:?}"))?;
    let control_path = provider_control_path(&lease.mount_id)?;
    let control_listener = local_transport::bind(&control_path)
        .with_context(|| format!("bind WinFsp control endpoint {}", control_path.display()))?;
    initialize_winfsp()?;
    let mountpoint = U16CString::from_os_str(start.mountpoint.as_os_str())
        .map_err(|_| anyhow::anyhow!("mountpoint is not valid UTF-16"))?;
    let filesystem = FileSystem::start(volume_params(lease.access), Some(&mountpoint), callback)
        .map_err(|status| {
            anyhow::anyhow!("WinFsp failed to start mount with status {status:#x}")
        })?;
    wait_for_mountpoint_ready(&start.mountpoint)?;

    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "READY {0}", lease.mount_id).context("report WinFsp readiness")?;
    stdout.flush().context("flush WinFsp readiness")?;

    let result = runtime.block_on(daemon_loop(filesystem, control_listener));
    if let Err(error) = result {
        eprintln!("{PROVIDER_NAME}: daemon stopped after failure: {error:#}");
        return Err(error);
    }
    Ok(())
}

fn wait_for_mountpoint_ready(mountpoint: &Path) -> Result<()> {
    let started = Instant::now();
    loop {
        // A directory mount is represented by a WinFsp junction. Follow that
        // reparse point so readiness proves the mounted root is serving I/O,
        // rather than inspecting the junction object itself.
        match std::fs::metadata(mountpoint) {
            Ok(metadata) if metadata.is_dir() => return Ok(()),
            Ok(_) => bail!(
                "WinFsp mountpoint is not a directory: {}",
                mountpoint.display()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "inspect WinFsp mountpoint readiness {}",
                        mountpoint.display()
                    )
                });
            },
        }
        if started.elapsed() >= MOUNTPOINT_READY_TIMEOUT {
            bail!(
                "WinFsp mountpoint did not become ready within {} seconds: {}",
                MOUNTPOINT_READY_TIMEOUT.as_secs(),
                mountpoint.display()
            );
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "kebab-case", tag = "operation", deny_unknown_fields)]
enum ServiceControlRequest {
    /// Probe service state with the broker bearer.
    Status { token: String },
    /// Stop and unmount the private service.
    Stop { token: String },
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "kebab-case", tag = "status", deny_unknown_fields)]
enum ServiceControlResponse {
    /// Service remains mounted.
    Ready,
    /// Service accepted a stop request.
    Stopped,
    /// Request was rejected.
    Failure { code: String, message: String },
}

const SERVICE_MAX_LAUNCH_BYTES: u64 = 64 * 1024;
const SERVICE_MAX_CONTROL_BYTES: usize = 64 * 1024;
const SERVICE_MAX_CALLBACK_BYTES: usize = 8 * 1024 * 1024;
const SERVICE_POLL: Duration = Duration::from_secs(1);

/// Run the hidden kernel-created `WinFsp` service mode.
pub(crate) fn service_main() -> Result<()> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .lock()
        .take(SERVICE_MAX_LAUNCH_BYTES + 1)
        .read_to_end(&mut bytes)
        .context("read WinFsp service launch")?;
    if bytes.len() as u64 > SERVICE_MAX_LAUNCH_BYTES {
        bail!("WinFsp service launch exceeds limit");
    }
    let launch: StorageProviderServiceLaunchV1 =
        serde_json::from_slice(&bytes).context("decode WinFsp service launch")?;
    validate_service_launch(&launch)?;
    let challenge = storage_provider_service_ready_challenge(
        &launch.parent.token,
        STORAGE_FILESYSTEM_SERVICE_READY_SCHEMA_V1,
        crate::PROVIDER_NAME,
        launch.lease.mount_id.as_uuid(),
        &launch.control_path,
        &launch.lease.resource_path,
        &launch.lease.callback_path,
    )
    .map_err(anyhow::Error::msg)?;
    let runtime = Arc::new(start_provider_runtime("WinFsp service runtime")?);
    runtime.block_on(run_private_service(launch, challenge, runtime.clone()))
}

/// Build the one runtime owned by a synchronous provider mode.
fn start_provider_runtime(context: &'static str) -> Result<tokio::runtime::Runtime> {
    if tokio::runtime::Handle::try_current().is_ok() {
        bail!("{context} cannot start inside another Tokio runtime");
    }
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .with_context(|| format!("start {context}"))
}

async fn run_private_service(
    launch: StorageProviderServiceLaunchV1,
    challenge: String,
    runtime: Arc<tokio::runtime::Runtime>,
) -> Result<()> {
    if !parent_is_alive(&launch.parent) {
        bail!("WinFsp service parent process is not alive");
    }
    probe_callback(&launch).await?;
    let listener = local_transport::bind(&launch.control_path).with_context(|| {
        format!(
            "bind WinFsp service control {}",
            launch.control_path.display()
        )
    })?;
    let callback = CallbackFs::new(launch.lease.clone(), runtime)
        .map_err(|failure| anyhow::anyhow!("build WinFsp callback filesystem: {failure:?}"))?;
    initialize_winfsp()?;
    let mountpoint = U16CString::from_os_str(launch.mountpoint.as_os_str())
        .map_err(|_| anyhow::anyhow!("WinFsp mountpoint is not valid UTF-16"))?;
    let filesystem = FileSystem::start(
        volume_params(launch.lease.access),
        Some(&mountpoint),
        callback,
    )
    .map_err(|status| anyhow::anyhow!("WinFsp failed to start private mount: {status:#x}"))?;
    let ready = StorageProviderServiceReadyV1 {
        schema: STORAGE_FILESYSTEM_SERVICE_READY_SCHEMA_V1,
        provider: crate::PROVIDER_NAME.to_owned(),
        mount_id: launch.lease.mount_id.as_uuid(),
        control_path: launch.control_path.clone(),
        challenge,
    };
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(&mut stdout, &ready).context("encode WinFsp readiness")?;
    stdout
        .write_all(b"\n")
        .context("terminate WinFsp readiness response")?;
    stdout.flush().context("flush WinFsp readiness")?;

    let result = private_service_loop(filesystem, listener, &launch).await;
    let _ = local_transport::remove_endpoint(&launch.control_path);
    result
}

fn validate_service_launch(launch: &StorageProviderServiceLaunchV1) -> Result<()> {
    if launch.schema != STORAGE_FILESYSTEM_SERVICE_LAUNCH_SCHEMA_V1 {
        bail!("unsupported WinFsp service launch schema {}", launch.schema);
    }
    if launch.parent.pid <= 1 || launch.parent.pid == std::process::id() {
        bail!("WinFsp service parent PID is invalid");
    }
    if launch.parent.token.len() < 16
        || launch.parent.token.len() > 512
        || launch.parent.token.chars().any(char::is_control)
    {
        bail!("WinFsp service parent token is invalid");
    }
    if let Some(identity) = launch.parent.start_identity.as_deref()
        && (identity.is_empty() || identity.len() > 512 || identity.chars().any(char::is_control))
    {
        bail!("WinFsp service parent start identity is invalid");
    }
    if launch.parent.start_identity.is_none() {
        bail!("WinFsp service parent start identity is required on Windows");
    }
    let lease = &launch.lease;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("read system clock")?
        .as_secs();
    if lease.expires_at_epoch_secs < now {
        bail!("WinFsp lease is expired");
    }
    if lease.lease_token.len() < 16 || lease.lease_token.len() > 4096 {
        bail!("WinFsp lease callback token is invalid");
    }
    if !lease.resource_path.is_absolute()
        || !lease.callback_path.is_absolute()
        || lease.callback_path != lease.resource_path.join("control.endpoint")
    {
        bail!("WinFsp lease paths are malformed");
    }
    platform_fs::validate_private_directory(&lease.resource_path)
        .context("validate private WinFsp lease resource")?;
    platform_fs::verify_no_redirects(&lease.resource_path)
        .context("reject redirected WinFsp lease resource")?;
    let manifest_path = lease.resource_path.join("lease.json");
    platform_fs::validate_private_file(&manifest_path)
        .context("validate private WinFsp lease manifest")?;
    let manifest = std::fs::read(&manifest_path).context("read WinFsp lease manifest")?;
    if manifest.len() > 64 * 1024 {
        bail!("WinFsp lease manifest exceeds the bounded size");
    }
    let admitted: StorageMountLeaseV1 =
        serde_json::from_slice(&manifest).context("decode WinFsp lease manifest")?;
    if admitted != *lease {
        bail!("WinFsp launch lease does not match the kernel manifest");
    }
    if !launch.mountpoint.is_absolute()
        || launch
            .mountpoint
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        bail!("WinFsp service mountpoint is malformed");
    }
    if is_public_mountpoint(&launch.mountpoint)
        || launch.mountpoint.parent().is_none()
        || launch.mountpoint == lease.resource_path
        || launch.mountpoint.starts_with(&lease.resource_path)
        || lease.resource_path.starts_with(&launch.mountpoint)
    {
        bail!("WinFsp service mountpoint is public or overlaps the lease resource");
    }
    platform_fs::validate_private_directory(&launch.mountpoint)
        .context("validate private WinFsp mountpoint")?;
    platform_fs::verify_no_redirects(&launch.mountpoint)
        .context("reject redirected WinFsp mountpoint")?;
    if std::fs::read_dir(&launch.mountpoint)?.next().is_some() {
        bail!("WinFsp service mountpoint is not empty");
    }
    if !launch.control_path.is_absolute()
        || launch
            .control_path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
        || launch.control_path != lease.resource_path.join("process-control.sock")
    {
        bail!("WinFsp service control path is malformed");
    }
    let control_parent = launch
        .control_path
        .parent()
        .context("WinFsp service control path has no parent")?;
    platform_fs::validate_private_directory(control_parent)
        .context("validate private WinFsp control parent")?;
    platform_fs::verify_no_redirects(&launch.control_path)
        .context("reject redirected WinFsp control path")?;
    if local_transport::endpoint_is_present(&launch.control_path)
        .context("inspect WinFsp service control endpoint")?
    {
        bail!("WinFsp service control endpoint is already present");
    }
    Ok(())
}

async fn probe_callback(launch: &StorageProviderServiceLaunchV1) -> Result<()> {
    let mut stream = local_transport::connect(&launch.lease.callback_path)
        .await
        .context("connect WinFsp lease callback")?;
    let request = StorageFilesystemRequestV2 {
        protocol_version: STORAGE_FILESYSTEM_PROTOCOL_V2,
        request_id: format!("winfsp-service-{}", launch.lease.mount_id),
        lease_token: launch.lease.lease_token.clone(),
        operation: StorageFilesystemOperationV2::Stat {
            path: String::new(),
        },
    };
    let bytes = serde_json::to_vec(&request).context("encode WinFsp callback probe")?;
    let length = u32::try_from(bytes.len()).context("WinFsp callback probe is too large")?;
    stream.write_all(&length.to_be_bytes()).await?;
    stream.write_all(&bytes).await?;
    stream.flush().await?;
    let mut response_length = [0_u8; 4];
    stream.read_exact(&mut response_length).await?;
    let length = u32::from_be_bytes(response_length) as usize;
    if length == 0 || length > SERVICE_MAX_CALLBACK_BYTES {
        bail!("WinFsp callback response exceeds limit");
    }
    let mut response_bytes = vec![0_u8; length];
    stream.read_exact(&mut response_bytes).await?;
    let response: StorageFilesystemResponseV2 =
        serde_json::from_slice(&response_bytes).context("decode WinFsp callback probe")?;
    if response.protocol_version != STORAGE_FILESYSTEM_PROTOCOL_V2 {
        bail!("WinFsp callback probe protocol mismatch");
    }
    if response.request_id != request.request_id {
        bail!("WinFsp callback probe correlation mismatch");
    }
    match response.outcome {
        StorageFilesystemOutcomeV2::Success(_) => Ok(()),
        StorageFilesystemOutcomeV2::Failure(StorageFilesystemFailureV1 { code, message }) => {
            bail!("WinFsp callback probe failed [{code}]: {message}")
        },
    }
}

async fn private_service_loop(
    filesystem: FileSystem,
    listener: local_transport::LocalListener,
    launch: &StorageProviderServiceLaunchV1,
) -> Result<()> {
    let mut filesystem = Some(filesystem);
    let mut poll = tokio::time::interval(SERVICE_POLL);
    loop {
        tokio::select! {
            accepted = local_transport::accept(&listener) => {
                let mut stream = accepted.context("accept WinFsp service control")?;
                let request = read_service_control(&mut stream).await?;
                let (response, stop) = match request {
                    ServiceControlRequest::Status { token } if token == launch.parent.token => {
                        (ServiceControlResponse::Ready, false)
                    },
                    ServiceControlRequest::Stop { token } if token == launch.parent.token => {
                        (ServiceControlResponse::Stopped, true)
                    },
                    ServiceControlRequest::Status { .. } | ServiceControlRequest::Stop { .. } => (
                        ServiceControlResponse::Failure {
                            code: "unauthorized".to_owned(),
                            message: "invalid parent service token".to_owned(),
                        },
                        false,
                    ),
                };
                if stop {
                    if let Some(filesystem) = filesystem.take() { filesystem.stop(); }
                    let _ = local_transport::remove_endpoint(&launch.control_path);
                }
                write_service_control(&mut stream, &response).await?;
                if stop { return Ok(()); }
            },
            _ = poll.tick() => {
                if !parent_is_alive(&launch.parent) || probe_callback(launch).await.is_err() {
                    if let Some(filesystem) = filesystem.take() { filesystem.stop(); }
                    return Ok(());
                }
            },
        }
    }
}

async fn read_service_control(
    stream: &mut local_transport::LocalStream,
) -> Result<ServiceControlRequest> {
    let mut line = String::new();
    let reader = tokio::io::BufReader::new(stream);
    let read = reader
        .take((SERVICE_MAX_CONTROL_BYTES + 1) as u64)
        .read_line(&mut line)
        .await
        .context("read WinFsp service control request")?;
    if read == 0 || line.len() > SERVICE_MAX_CONTROL_BYTES {
        bail!("WinFsp service control request exceeds limit");
    }
    serde_json::from_str(&line).context("decode WinFsp service control request")
}

async fn write_service_control(
    stream: &mut local_transport::LocalStream,
    response: &ServiceControlResponse,
) -> Result<()> {
    let bytes = serde_json::to_vec(response)?;
    stream.write_all(&bytes).await?;
    stream.write_all(b"\n").await?;
    stream.flush().await.context("flush WinFsp service control")
}

fn parent_is_alive(
    parent: &astrid_core::storage_filesystem::StorageProviderParentLifetimeV1,
) -> bool {
    // SAFETY: OpenProcess/GetExitCodeProcess/CloseHandle are called with a
    // validated PID and the returned handle is closed on every path.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, parent.pid) };
    if handle.is_null() {
        return false;
    }
    let mut exit_code = 0_u32;
    let alive = unsafe { GetExitCodeProcess(handle, &raw mut exit_code) != 0 } && exit_code == 259;
    unsafe { CloseHandle(handle) };
    if !alive {
        return false;
    }
    parent
        .start_identity
        .as_deref()
        .is_none_or(|identity| process_start_identity(parent.pid).as_deref() == Some(identity))
}

fn process_start_identity(pid: u32) -> Option<String> {
    use std::mem::MaybeUninit;
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::System::Threading::GetProcessTimes;

    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return None;
    }
    let mut creation = MaybeUninit::<FILETIME>::uninit();
    let mut exit = MaybeUninit::<FILETIME>::uninit();
    let mut kernel = MaybeUninit::<FILETIME>::uninit();
    let mut user = MaybeUninit::<FILETIME>::uninit();
    let ok = unsafe {
        GetProcessTimes(
            handle,
            creation.as_mut_ptr(),
            exit.as_mut_ptr(),
            kernel.as_mut_ptr(),
            user.as_mut_ptr(),
        ) != 0
    };
    unsafe { CloseHandle(handle) };
    if !ok {
        return None;
    }
    let creation = unsafe { creation.assume_init() };
    let value = (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime);
    Some(value.to_string())
}

async fn daemon_loop(
    filesystem: FileSystem,
    listener: local_transport::LocalListener,
) -> Result<()> {
    let mut filesystem = Some(filesystem);
    loop {
        let mut stream = local_transport::accept(&listener)
            .await
            .context("accept WinFsp control client")?;
        let mut command = [0_u8; 4];
        let read = stream
            .read(&mut command)
            .await
            .context("read stop command")?;
        if read == 0 {
            continue;
        }
        if read != command.len() || &command != b"STOP" {
            continue;
        }
        if let Some(filesystem) = filesystem.take() {
            filesystem.stop();
        }
        stream
            .write_all(b"S")
            .await
            .context("acknowledge WinFsp stop")?;
        stream
            .flush()
            .await
            .context("flush WinFsp stop acknowledgement")?;
        return Ok(());
    }
}

pub(crate) async fn spawn_daemon(lease: &StorageMountLeaseV1, mountpoint: &Path) -> Result<()> {
    let executable = std::env::current_exe().context("resolve WinFsp provider executable")?;
    let mut command = tokio::process::Command::new(&executable);
    command
        .arg(DAEMON_ARGUMENT)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
    let mut child = command
        .spawn()
        .with_context(|| format!("start detached {}", executable.display()))?;

    let success = async {
        let mut stdin = child
            .stdin
            .take()
            .context("WinFsp daemon stdin is unavailable")?;
        let start = DaemonStart {
            lease: lease.clone(),
            mountpoint: native_mountpoint(mountpoint)?,
        };
        let bytes = serde_json::to_vec(&start).context("encode WinFsp daemon lease")?;
        stdin.write_all(&bytes).await.context("send daemon lease")?;
        stdin
            .write_all(b"\n")
            .await
            .context("terminate daemon lease")?;
        drop(stdin);

        let stdout = child
            .stdout
            .take()
            .context("WinFsp daemon stdout is unavailable")?;
        let mut stdout = tokio::io::BufReader::new(stdout);
        let mut ready = String::new();
        stdout
            .read_line(&mut ready)
            .await
            .context("read WinFsp daemon readiness")?;
        let expected = format!("READY {}\n", lease.mount_id);
        if ready != expected {
            bail!("WinFsp daemon returned invalid readiness: {ready:?}");
        }
        if child.try_wait().context("inspect WinFsp daemon")?.is_some() {
            bail!("WinFsp daemon exited immediately after readiness");
        }
        Result::<()>::Ok(())
    };

    match tokio::time::timeout(DAEMON_READY_TIMEOUT, success).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            Err(error.context("start WinFsp native filesystem"))
        },
        Err(_) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            bail!("WinFsp daemon did not report readiness within 30 seconds");
        },
    }
}

fn native_mountpoint(mountpoint: &Path) -> Result<PathBuf> {
    let text = mountpoint
        .to_str()
        .context("WinFsp mountpoint is not valid Unicode")?;
    let bytes = text.as_bytes();
    if bytes.len() == 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/')
    {
        // FspFileSystemSetMountPoint accepts drive designators (`X:`), not
        // drive-root paths (`X:\\`). Keep the latter in the public lifecycle
        // record while passing the native spelling to WinFsp.
        return Ok(PathBuf::from(&text[..2]));
    }
    Ok(mountpoint.to_path_buf())
}

fn is_drive_designator(path: &Path) -> bool {
    path.to_str().is_some_and(|text| {
        let bytes = text.as_bytes();
        bytes.len() == 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
    })
}

fn is_public_mountpoint(path: &Path) -> bool {
    if is_drive_designator(path) {
        return true;
    }
    path.to_str().is_some_and(|text| {
        let bytes = text.as_bytes();
        bytes.len() == 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && matches!(bytes[2], b'\\' | b'/')
    })
}

pub(crate) async fn stop_daemon(control_path: &Path) -> Result<()> {
    let stop = async {
        let mut stream = match local_transport::connect(control_path).await {
            Ok(stream) => stream,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                return Err(error).context(format!(
                    "connect WinFsp control endpoint {}",
                    control_path.display()
                ));
            },
        };
        stream
            .write_all(b"STOP")
            .await
            .context("send WinFsp stop")?;
        stream.flush().await.context("flush WinFsp stop")?;
        let mut acknowledgement = [0_u8; 1];
        stream
            .read_exact(&mut acknowledgement)
            .await
            .context("read WinFsp stop acknowledgement")?;
        if acknowledgement[0] != b'S' {
            bail!("WinFsp daemon returned an invalid stop acknowledgement");
        }
        Result::<()>::Ok(())
    };
    tokio::time::timeout(DAEMON_STOP_TIMEOUT, stop)
        .await
        .map_err(|_| anyhow::anyhow!("WinFsp stop timed out"))??;

    let deadline = tokio::time::Instant::now()
        .checked_add(DAEMON_STOP_TIMEOUT)
        .ok_or_else(|| anyhow::anyhow!("WinFsp stop deadline overflow"))?;
    while endpoint_is_present(control_path) {
        if tokio::time::Instant::now() >= deadline {
            bail!("WinFsp control endpoint remained live after stop");
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    Ok(())
}

fn initialize_winfsp() -> Result<()> {
    load_adjacent_winfsp().context("load co-installed WinFsp runtime")?;
    winfsp_wrs::init().context("initialize installed WinFsp runtime")
}

fn load_adjacent_winfsp() -> Result<()> {
    let Some(directory) = std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(Path::to_path_buf))
    else {
        return Ok(());
    };
    let architecture = if cfg!(target_arch = "x86_64") {
        "x64"
    } else if cfg!(target_arch = "x86") {
        "x86"
    } else if cfg!(target_arch = "aarch64") {
        "a64"
    } else {
        return Ok(());
    };
    let library = directory.join(format!("winfsp-{architecture}.dll"));
    if !library.is_file() {
        return Ok(());
    }
    let encoded: Vec<u16> = library
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    if unsafe { LoadLibraryW(encoded.as_ptr()) }.is_null() {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("load co-installed WinFsp runtime {}", library.display()));
    }
    Ok(())
}

fn volume_params(access: StorageProviderAccessV1) -> Params {
    let mut volume = VolumeParams::default();
    volume
        // Astrid logical paths are case-sensitive on every backend. Advertising
        // case-insensitive lookup lets WinFsp probe differently cased aliases
        // that cannot identify the same storage key.
        .set_case_sensitive_search(true)
        .set_case_preserved_names(true)
        .set_unicode_on_disk(true)
        .set_persistent_acls(false)
        .set_read_only_volume(access == StorageProviderAccessV1::ReadOnly)
        .set_sector_size(4096)
        .set_max_component_length(255)
        .set_sectors_per_allocation_unit(1)
        .set_file_info_timeout(1000)
        .set_volume_info_timeout(1000)
        .set_dir_info_timeout(1000)
        .set_security_timeout(1000);
    Params {
        volume_params: volume,
        guard_strategy: OperationGuardStrategy::Fine,
    }
}

#[cfg(test)]
#[path = "win/tests.rs"]
mod tests;
