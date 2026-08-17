//! Private kernel-created `FSKit` service mode.

use std::io::{Read as _, Write as _};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result, bail};
use astrid_core::local_transport::{self, LocalListener, LocalStream};
use astrid_core::platform_fs;
#[cfg(test)]
use astrid_core::storage_filesystem::StorageProviderParentLifetimeV1;
use astrid_core::storage_filesystem::{
    STORAGE_FILESYSTEM_PROTOCOL_V2, STORAGE_FILESYSTEM_SERVICE_LAUNCH_SCHEMA_V1,
    STORAGE_FILESYSTEM_SERVICE_READY_SCHEMA_V1, StorageFilesystemFailureV1,
    StorageFilesystemOperationV2, StorageFilesystemOutcomeV2, StorageFilesystemRequestV2,
    StorageFilesystemResponseV2, StorageProviderServiceLaunchV1, StorageProviderServiceReadyV1,
    storage_provider_service_ready_challenge,
};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _};

const MAX_LAUNCH_BYTES: u64 = 64 * 1024;
const MAX_CONTROL_BYTES: usize = 64 * 1024;
const MAX_CALLBACK_BYTES: usize = 8 * 1024 * 1024;
const SERVICE_POLL: Duration = Duration::from_secs(1);

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", tag = "operation", deny_unknown_fields)]
enum ControlRequest {
    /// Probe service state with the parent bearer.
    Status { token: String },
    /// Unmount and terminate this private service.
    Stop { token: String },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", tag = "status", deny_unknown_fields)]
enum ControlResponse {
    /// Service remains mounted.
    Ready,
    /// Service accepted a stop request.
    Stopped,
    /// Request was rejected.
    Failure { code: String, message: String },
}

/// Run the hidden `FSKit` service mode.
///
/// The caller must be the kernel-created broker. Public provider requests use
/// the stdio mode and cannot supply this envelope without a live private lease,
/// callback bearer, and parent lifetime.
pub(crate) async fn run() -> Result<()> {
    let launch = read_launch()?;
    validate_launch(&launch)?;
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
    if !parent_is_alive(&launch.parent) {
        bail!("FSKit service parent process is not alive");
    }
    probe_callback(&launch).await?;
    let listener = bind_control(&launch.control_path)?;
    let mut mounted = match crate::native_mount(&launch.lease, &launch.mountpoint).await {
        Ok(()) => true,
        Err(error) => {
            let _ = local_transport::remove_endpoint(&launch.control_path);
            return Err(error);
        },
    };
    if let Err(error) = crate::validate_mounted_mountpoint(&launch.mountpoint) {
        let _ = crate::native_unmount(&launch.mountpoint).await;
        let _ = local_transport::remove_endpoint(&launch.control_path);
        return Err(error);
    }
    let ready = StorageProviderServiceReadyV1 {
        schema: STORAGE_FILESYSTEM_SERVICE_READY_SCHEMA_V1,
        provider: crate::PROVIDER_NAME.to_owned(),
        mount_id: launch.lease.mount_id.as_uuid(),
        control_path: launch.control_path.clone(),
        challenge,
    };
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(&mut stdout, &ready).context("encode FSKit readiness")?;
    stdout
        .write_all(b"\n")
        .context("terminate FSKit readiness response")?;
    drop(stdout);

    let result = service_loop(&listener, &launch, &mut mounted).await;
    if mounted {
        let unmount = crate::native_unmount(&launch.mountpoint).await;
        if let Err(unmount_error) = unmount {
            return match result {
                Ok(()) => Err(unmount_error),
                Err(primary) => Err(primary.context(unmount_error)),
            };
        }
    }
    let _ = local_transport::remove_endpoint(&launch.control_path);
    result
}

fn read_launch() -> Result<StorageProviderServiceLaunchV1> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .lock()
        .take(MAX_LAUNCH_BYTES + 1)
        .read_to_end(&mut bytes)
        .context("read FSKit service launch")?;
    if bytes.len() as u64 > MAX_LAUNCH_BYTES {
        bail!("FSKit service launch exceeds limit");
    }
    serde_json::from_slice(&bytes).context("decode FSKit service launch")
}

fn validate_launch(launch: &StorageProviderServiceLaunchV1) -> Result<()> {
    if launch.schema != STORAGE_FILESYSTEM_SERVICE_LAUNCH_SCHEMA_V1 {
        bail!("unsupported FSKit service launch schema {}", launch.schema);
    }
    validate_launch_parent(&launch.parent)?;
    validate_lease(&launch.lease)?;
    crate::validate_mountpoint_layout(&launch.mountpoint)?;
    if launch.mountpoint == launch.lease.resource_path
        || launch.mountpoint.starts_with(&launch.lease.resource_path)
        || launch.lease.resource_path.starts_with(&launch.mountpoint)
    {
        bail!("FSKit service mountpoint overlaps the lease resource");
    }
    crate::validate_mountpoint_ancestors(&launch.mountpoint)?;
    crate::validate_unmounted_mountpoint(&launch.mountpoint)?;
    validate_control_path(&launch.control_path, &launch.lease.resource_path)?;
    Ok(())
}

fn validate_lease(lease: &astrid_core::storage_filesystem::StorageMountLeaseV1) -> Result<()> {
    if lease.lease_token.len() < 16 || lease.lease_token.len() > 4096 {
        bail!("FSKit lease callback token is invalid");
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("read system clock")?
        .as_secs();
    if lease.expires_at_epoch_secs < now {
        bail!("FSKit lease is expired");
    }
    if !lease.resource_path.is_absolute() || !lease.callback_path.is_absolute() {
        bail!("FSKit lease paths must be absolute");
    }
    let expected_callback = lease.resource_path.join("control.sock");
    if lease.callback_path != expected_callback {
        bail!("FSKit callback path is not the kernel lease endpoint");
    }
    platform_fs::validate_private_directory(&lease.resource_path)
        .context("validate private FSKit lease resource")?;
    platform_fs::verify_no_redirects(&lease.resource_path)
        .context("reject redirected FSKit lease resource")?;
    platform_fs::validate_private_file(&lease.resource_path.join("lease.json"))
        .context("validate private FSKit lease manifest")?;
    let manifest = std::fs::read(lease.resource_path.join("lease.json"))
        .context("read FSKit lease manifest")?;
    if manifest.len() > 64 * 1024 {
        bail!("FSKit lease manifest exceeds the bounded size");
    }
    let admitted: astrid_core::storage_filesystem::StorageMountLeaseV1 =
        serde_json::from_slice(&manifest).context("decode FSKit lease manifest")?;
    if admitted != *lease {
        bail!("FSKit launch lease does not match the kernel manifest");
    }
    Ok(())
}

fn validate_control_path(control_path: &Path, resource_path: &Path) -> Result<()> {
    if !control_path.is_absolute()
        || control_path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        bail!("FSKit service control path is malformed");
    }
    let parent = control_path
        .parent()
        .context("FSKit service control path has no parent")?;
    platform_fs::validate_private_directory(parent)
        .context("validate private FSKit control parent")?;
    platform_fs::verify_no_redirects(control_path)
        .context("reject redirected FSKit control path")?;
    if control_path != resource_path.join("process-control.sock") {
        bail!("FSKit service control path is not the kernel endpoint");
    }
    if local_transport::endpoint_is_present(control_path)
        .context("inspect FSKit service control endpoint")?
    {
        bail!("FSKit service control endpoint is already present");
    }
    Ok(())
}

fn bind_control(path: &Path) -> Result<LocalListener> {
    local_transport::bind(path)
        .with_context(|| format!("bind FSKit service control {}", path.display()))
}

async fn probe_callback(launch: &StorageProviderServiceLaunchV1) -> Result<()> {
    let mut stream = local_transport::connect(&launch.lease.callback_path)
        .await
        .context("connect FSKit lease callback")?;
    let request = StorageFilesystemRequestV2 {
        protocol_version: STORAGE_FILESYSTEM_PROTOCOL_V2,
        request_id: format!("fskit-service-{}", launch.lease.mount_id),
        lease_token: launch.lease.lease_token.clone(),
        operation: StorageFilesystemOperationV2::Stat {
            path: String::new(),
        },
    };
    let bytes = serde_json::to_vec(&request).context("encode FSKit callback probe")?;
    let length = u32::try_from(bytes.len()).context("FSKit callback probe is too large")?;
    stream.write_all(&length.to_be_bytes()).await?;
    stream.write_all(&bytes).await?;
    stream.flush().await?;
    let response = read_callback_response(&mut stream).await?;
    if response.request_id != request.request_id {
        bail!("FSKit callback probe correlation mismatch");
    }
    match response.outcome {
        StorageFilesystemOutcomeV2::Success(_) => Ok(()),
        StorageFilesystemOutcomeV2::Failure(StorageFilesystemFailureV1 { code, message }) => {
            bail!("FSKit callback probe failed [{code}]: {message}")
        },
    }
}

async fn read_callback_response(stream: &mut LocalStream) -> Result<StorageFilesystemResponseV2> {
    let mut length = [0_u8; 4];
    stream.read_exact(&mut length).await?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_CALLBACK_BYTES {
        bail!("FSKit callback response exceeds the bounded frame size");
    }
    let mut bytes = vec![0_u8; length];
    stream.read_exact(&mut bytes).await?;
    let response: StorageFilesystemResponseV2 =
        serde_json::from_slice(&bytes).context("decode FSKit callback probe")?;
    if response.protocol_version != STORAGE_FILESYSTEM_PROTOCOL_V2 {
        bail!("FSKit callback probe protocol mismatch");
    }
    Ok(response)
}

async fn service_loop(
    listener: &LocalListener,
    launch: &StorageProviderServiceLaunchV1,
    mounted: &mut bool,
) -> Result<()> {
    let mut poll = tokio::time::interval(SERVICE_POLL);
    loop {
        tokio::select! {
            accepted = local_transport::accept(listener) => {
                let mut stream = accepted.context("accept FSKit service control")?;
                let request = read_control(&mut stream).await?;
                let (response, stop) = match request {
                    ControlRequest::Status { token } if token == launch.parent.token => {
                        (ControlResponse::Ready, false)
                    },
                    ControlRequest::Stop { token } if token == launch.parent.token => {
                        let response = match crate::native_unmount(&launch.mountpoint).await {
                            Ok(()) => {
                                *mounted = false;
                                let _ = local_transport::remove_endpoint(&launch.control_path);
                                ControlResponse::Stopped
                            },
                            Err(error) => ControlResponse::Failure {
                                code: "unmount".to_owned(),
                                message: error.to_string().chars().take(4096).collect(),
                            },
                        };
                        (response, true)
                    },
                    ControlRequest::Status { .. } | ControlRequest::Stop { .. } => (
                        ControlResponse::Failure {
                            code: "unauthorized".to_owned(),
                            message: "invalid parent service token".to_owned(),
                        },
                        false,
                    ),
                };
                write_control(&mut stream, &response).await?;
                if stop { return Ok(()); }
            },
            _ = poll.tick() => {
                if !parent_is_alive(&launch.parent) || probe_callback(launch).await.is_err() {
                    return Ok(());
                }
            },
        }
    }
}

async fn read_control(stream: &mut LocalStream) -> Result<ControlRequest> {
    let mut line = String::new();
    let reader = tokio::io::BufReader::new(stream);
    let read = reader
        .take((MAX_CONTROL_BYTES + 1) as u64)
        .read_line(&mut line)
        .await
        .context("read FSKit service control request")?;
    if read == 0 || line.len() > MAX_CONTROL_BYTES {
        bail!("FSKit service control request exceeds limit");
    }
    serde_json::from_str(&line).context("decode FSKit service control request")
}

async fn write_control(stream: &mut LocalStream, response: &ControlResponse) -> Result<()> {
    let bytes = serde_json::to_vec(response)?;
    stream.write_all(&bytes).await?;
    stream.write_all(b"\n").await?;
    stream.flush().await.context("flush FSKit service control")
}

#[cfg(unix)]
fn parent_is_alive(
    parent: &astrid_core::storage_filesystem::StorageProviderParentLifetimeV1,
) -> bool {
    use nix::sys::signal::kill;
    use nix::unistd::Pid;

    let Ok(pid) = i32::try_from(parent.pid) else {
        return false;
    };
    let alive = matches!(
        kill(Pid::from_raw(pid), None),
        Ok(()) | Err(nix::errno::Errno::EPERM)
    );
    if !alive {
        return false;
    }
    #[cfg(target_os = "linux")]
    if let Some(identity) = parent.start_identity.as_deref() {
        return linux_process_start_identity(parent.pid).as_deref() == Some(identity);
    }
    #[cfg(target_os = "macos")]
    if let Some(identity) = parent.start_identity.as_deref() {
        return mac_process_start_identity(parent.pid).as_deref() == Some(identity);
    }
    #[cfg(target_os = "macos")]
    if parent.start_identity.is_none() {
        return false;
    }
    #[cfg(all(not(target_os = "linux"), not(target_os = "macos")))]
    if parent.start_identity.is_some() {
        return false;
    }
    true
}

#[cfg(not(unix))]
fn parent_is_alive(
    _parent: &astrid_core::storage_filesystem::StorageProviderParentLifetimeV1,
) -> bool {
    true
}

#[cfg(target_os = "linux")]
fn linux_process_start_identity(pid: u32) -> Option<String> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let (_, rest) = text.rsplit_once(") ")?;
    rest.split_whitespace()
        .nth(19)?
        .parse::<u64>()
        .ok()
        .map(|value| value.to_string())
}

#[cfg(target_os = "macos")]
fn mac_process_start_identity(pid: u32) -> Option<String> {
    use libproc::libproc::bsd_info::BSDInfo;
    use libproc::libproc::proc_pid::pidinfo;

    let info = pidinfo::<BSDInfo>(i32::try_from(pid).ok()?, 0).ok()?;
    Some(format!(
        "{}:{}",
        info.pbi_start_tvsec, info.pbi_start_tvusec
    ))
}

fn validate_launch_parent(
    parent: &astrid_core::storage_filesystem::StorageProviderParentLifetimeV1,
) -> Result<()> {
    if parent.pid <= 1 || parent.pid == std::process::id() {
        bail!("invalid parent PID");
    }
    if parent.token.len() < 16
        || parent.token.len() > 512
        || parent.token.chars().any(char::is_control)
    {
        bail!("invalid parent token");
    }
    if let Some(identity) = parent.start_identity.as_deref()
        && (identity.is_empty() || identity.len() > 512 || identity.chars().any(char::is_control))
    {
        bail!("invalid parent start identity");
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if parent.start_identity.is_none() {
        bail!("parent start identity is required on this platform");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_request_rejects_unknown_fields() {
        let request = serde_json::json!({ "operation": "status", "token": "x", "branch": "nope" });
        assert!(serde_json::from_value::<ControlRequest>(request).is_err());
    }

    #[test]
    fn parent_liveness_rejects_self_and_zero() {
        let launch = StorageProviderParentLifetimeV1 {
            pid: std::process::id(),
            start_identity: None,
            token: "0123456789abcdef".to_owned(),
        };
        assert!(validate_launch_parent(&launch).is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn mac_parent_identity_uses_kernel_sec_usec_format() {
        let identity = mac_process_start_identity(std::process::id()).expect("current process");
        let (seconds, micros) = identity.split_once(':').expect("sec:usec identity");
        assert!(seconds.parse::<u64>().is_ok());
        assert!(micros.parse::<u64>().is_ok());
        let parent = StorageProviderParentLifetimeV1 {
            pid: std::process::id(),
            start_identity: Some(identity),
            token: "0123456789abcdef".to_owned(),
        };
        assert!(parent_is_alive(&parent));
    }
}
