//! Kernel-created private FUSE service mode.

use std::io::{Read as _, Write as _};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result, bail};
use astrid_core::local_transport::{self, LocalStream};
use astrid_core::platform_fs;
use astrid_core::storage_filesystem::{
    STORAGE_FILESYSTEM_PROTOCOL_V2, STORAGE_FILESYSTEM_SERVICE_LAUNCH_SCHEMA_V1,
    STORAGE_FILESYSTEM_SERVICE_READY_SCHEMA_V1, StorageFilesystemFailureV1,
    StorageFilesystemOperationV2, StorageFilesystemOutcomeV2, StorageFilesystemRequestV2,
    StorageFilesystemResponseV2, StorageMountLeaseV1, StorageProviderServiceLaunchV1,
    StorageProviderServiceReadyV1, storage_provider_service_ready_challenge,
};
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _};
use uuid::Uuid;

use crate::control::{KernelControlRequest, KernelControlResponse, bind_control_listener};
use crate::filesystem::{self, FuseBackgroundSession};
use crate::mountpoint;

const MAX_LAUNCH_BYTES: u64 = 64 * 1024;
const MAX_CONTROL_BYTES: usize = 64 * 1024;
const MAX_CALLBACK_BYTES: usize = 8 * 1024 * 1024;
const SERVICE_POLL: Duration = Duration::from_secs(1);

/// Run the hidden target-free service mode.
pub(crate) async fn run() -> Result<()> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .lock()
        .take(MAX_LAUNCH_BYTES + 1)
        .read_to_end(&mut bytes)
        .context("read target-free FUSE service launch")?;
    if bytes.len() as u64 > MAX_LAUNCH_BYTES {
        bail!("FUSE service launch exceeds limit");
    }
    let launch: StorageProviderServiceLaunchV1 =
        serde_json::from_slice(&bytes).context("decode target-free FUSE service launch")?;
    run_launch(launch).await
}

async fn run_launch(launch: StorageProviderServiceLaunchV1) -> Result<()> {
    if launch.schema != STORAGE_FILESYSTEM_SERVICE_LAUNCH_SCHEMA_V1 {
        bail!("unsupported FUSE service launch schema {}", launch.schema);
    }
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
    .map_err(|error| anyhow::anyhow!(error))?;
    if !parent_is_alive(&launch.parent) {
        bail!("FUSE service parent process is not alive");
    }
    probe_callback(&launch).await?;
    let listener = bind_control_listener(&launch.control_path)?;
    let mut session = match filesystem::start_session(launch.lease.clone(), &launch.mountpoint) {
        Ok(session) => Some(session),
        Err(error) => {
            let _ = std::fs::remove_file(&launch.control_path);
            return Err(error);
        },
    };
    let ready = StorageProviderServiceReadyV1 {
        schema: STORAGE_FILESYSTEM_SERVICE_READY_SCHEMA_V1,
        provider: crate::PROVIDER_NAME.to_owned(),
        mount_id: launch.lease.mount_id.as_uuid(),
        control_path: launch.control_path.clone(),
        challenge,
    };
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(&mut stdout, &ready).context("encode FUSE readiness")?;
    stdout
        .write_all(b"\n")
        .context("terminate FUSE readiness response")?;
    stdout.flush()?;
    drop(stdout);

    let result = service_loop(&listener, &launch, &mut session).await;
    if let Some(session) = session.take() {
        let unmount = tokio::task::spawn_blocking(|| session.umount_and_join()).await;
        match unmount {
            Ok(Ok(())) => {},
            Ok(Err(error)) => {
                return result.context(format!("unmount FUSE during cleanup: {error}"));
            },
            Err(error) => {
                return result.context(format!("join FUSE worker during cleanup: {error}"));
            },
        }
    }
    let _ = mountpoint::lazy_unmount(&launch.mountpoint);
    let _ = std::fs::remove_file(&launch.control_path);
    result
}

async fn service_loop(
    listener: &tokio::net::UnixListener,
    launch: &StorageProviderServiceLaunchV1,
    session: &mut Option<FuseBackgroundSession>,
) -> Result<()> {
    let mut poll = tokio::time::interval(SERVICE_POLL);
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (mut stream, _) = accepted.context("accept FUSE service control")?;
                let mut line = String::new();
                let reader = tokio::io::BufReader::new(&mut stream);
                let read = reader
                    .take((MAX_CONTROL_BYTES + 1) as u64)
                    .read_line(&mut line)
                    .await
                    .context("read FUSE service control request")?;
                if read == 0 || line.len() > MAX_CONTROL_BYTES {
                    bail!("FUSE service control request exceeds limit");
                }
                let request: KernelControlRequest = serde_json::from_str(&line)
                    .context("decode FUSE service control request")?;
                let (response, stop) = match request {
                    KernelControlRequest::Status { token } if token == launch.parent.token => {
                        (KernelControlResponse::Ready, false)
                    },
                    KernelControlRequest::Stop { token } if token == launch.parent.token => {
                        let response = match session.take() {
                            Some(session) => match tokio::task::spawn_blocking(|| session.umount_and_join()).await {
                                Ok(Ok(())) => KernelControlResponse::Stopped,
                                Ok(Err(error)) => failure_response("unmount", &error.to_string()),
                                Err(error) => failure_response("unmount", &error.to_string()),
                            },
                            None => KernelControlResponse::Stopped,
                        };
                        if matches!(&response, KernelControlResponse::Stopped) {
                            let _ = local_transport::remove_endpoint(&launch.control_path);
                        }
                        (response, true)
                    },
                    KernelControlRequest::Status { .. } | KernelControlRequest::Stop { .. } => (
                        failure_response("unauthorized", "invalid parent service token"),
                        false,
                    ),
                };
                let bytes = serde_json::to_vec(&response)?;
                stream.write_all(&bytes).await?;
                stream.write_all(b"\n").await?;
                stream.flush().await?;
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

fn failure_response(code: &str, message: &str) -> KernelControlResponse {
    KernelControlResponse::Failure {
        code: code.to_owned(),
        message: message.chars().take(4096).collect(),
    }
}

fn validate_launch(launch: &StorageProviderServiceLaunchV1) -> Result<()> {
    validate_parent(&launch.parent)?;
    validate_lease(&launch.lease)?;
    validate_mountpoint(&launch.mountpoint, &launch.lease.resource_path)?;
    validate_control_path(&launch.control_path, &launch.lease.resource_path)?;
    Ok(())
}

fn validate_parent(
    parent: &astrid_core::storage_filesystem::StorageProviderParentLifetimeV1,
) -> Result<()> {
    if parent.pid <= 1 || parent.pid == std::process::id() {
        bail!("invalid FUSE service parent PID");
    }
    if parent.token.len() < 16
        || parent.token.len() > 512
        || parent.token.chars().any(char::is_control)
    {
        bail!("invalid FUSE service parent token");
    }
    if let Some(identity) = parent.start_identity.as_deref()
        && (identity.is_empty() || identity.len() > 512 || identity.chars().any(char::is_control))
    {
        bail!("invalid FUSE service parent start identity");
    }
    #[cfg(target_os = "linux")]
    if parent.start_identity.is_none() {
        bail!("FUSE service parent start identity is required on Linux");
    }
    Ok(())
}

fn validate_lease(lease: &StorageMountLeaseV1) -> Result<()> {
    if lease.lease_token.len() < 16
        || lease.lease_token.len() > 4096
        || lease.lease_token.chars().any(char::is_control)
    {
        bail!("invalid FUSE callback token");
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("read system clock")?
        .as_secs();
    if lease.expires_at_epoch_secs < now {
        bail!("FUSE lease is expired");
    }
    if !lease.resource_path.is_absolute() || !lease.callback_path.is_absolute() {
        bail!("FUSE lease paths must be absolute");
    }
    if lease.callback_path != lease.resource_path.join("control.sock") {
        bail!("FUSE callback path is not the kernel lease endpoint");
    }
    platform_fs::validate_private_directory(&lease.resource_path)
        .context("validate private FUSE lease resource")?;
    platform_fs::verify_no_redirects(&lease.resource_path)
        .context("reject redirected FUSE lease resource")?;
    let manifest_path = lease.resource_path.join("lease.json");
    platform_fs::validate_private_file(&manifest_path)
        .context("validate private FUSE lease manifest")?;
    let manifest = std::fs::read(&manifest_path).context("read FUSE lease manifest")?;
    if manifest.len() > 64 * 1024 {
        bail!("FUSE lease manifest exceeds the bounded size");
    }
    let admitted: StorageMountLeaseV1 =
        serde_json::from_slice(&manifest).context("decode FUSE lease manifest")?;
    if admitted != *lease {
        bail!("FUSE launch lease does not match the kernel manifest");
    }
    Ok(())
}

fn validate_mountpoint(mountpoint: &Path, resource_path: &Path) -> Result<()> {
    if !mountpoint.is_absolute()
        || mountpoint
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
        || mountpoint.parent().is_none()
    {
        bail!("FUSE service mountpoint is malformed");
    }
    if mountpoint == resource_path
        || mountpoint.starts_with(resource_path)
        || resource_path.starts_with(mountpoint)
    {
        bail!("FUSE service mountpoint overlaps the lease resource");
    }
    platform_fs::validate_private_directory(mountpoint)
        .context("validate private FUSE service mountpoint")?;
    platform_fs::verify_no_redirects(mountpoint)
        .context("reject redirected FUSE service mountpoint")?;
    if std::fs::read_dir(mountpoint)?.next().is_some() {
        bail!("FUSE service mountpoint is not empty");
    }
    if mountpoint::mountinfo_contains(mountpoint)? {
        bail!("FUSE service mountpoint is already mounted");
    }
    Ok(())
}

fn validate_control_path(control_path: &Path, resource_path: &Path) -> Result<()> {
    if !control_path.is_absolute()
        || control_path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        bail!("FUSE service control path is malformed");
    }
    if control_path != resource_path.join("process-control.sock") {
        bail!("FUSE service control path is not the kernel endpoint");
    }
    let parent = control_path
        .parent()
        .context("FUSE service control path has no parent")?;
    platform_fs::validate_private_directory(parent)
        .context("validate private FUSE control parent")?;
    platform_fs::verify_no_redirects(control_path)
        .context("reject redirected FUSE control path")?;
    if local_transport::endpoint_is_present(control_path)
        .context("inspect FUSE service control endpoint")?
    {
        bail!("FUSE service control endpoint is already present");
    }
    Ok(())
}

async fn probe_callback(launch: &StorageProviderServiceLaunchV1) -> Result<()> {
    let mut stream = local_transport::connect(&launch.lease.callback_path)
        .await
        .context("connect FUSE lease callback")?;
    let request = StorageFilesystemRequestV2 {
        protocol_version: STORAGE_FILESYSTEM_PROTOCOL_V2,
        request_id: format!("fuse-service-{}", Uuid::new_v4()),
        lease_token: launch.lease.lease_token.clone(),
        operation: StorageFilesystemOperationV2::Stat {
            path: String::new(),
        },
    };
    let bytes = serde_json::to_vec(&request).context("encode FUSE callback probe")?;
    let length = u32::try_from(bytes.len()).context("FUSE callback probe is too large")?;
    stream.write_all(&length.to_be_bytes()).await?;
    stream.write_all(&bytes).await?;
    stream.flush().await?;
    let response = read_callback_response(&mut stream).await?;
    if response.request_id != request.request_id {
        bail!("FUSE callback probe correlation mismatch");
    }
    match response.outcome {
        StorageFilesystemOutcomeV2::Success(_) => Ok(()),
        StorageFilesystemOutcomeV2::Failure(StorageFilesystemFailureV1 { code, message }) => {
            bail!("FUSE callback probe failed [{code}]: {message}")
        },
    }
}

async fn read_callback_response(stream: &mut LocalStream) -> Result<StorageFilesystemResponseV2> {
    let mut length = [0_u8; 4];
    stream.read_exact(&mut length).await?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_CALLBACK_BYTES {
        bail!("FUSE callback response exceeds the bounded frame size");
    }
    let mut bytes = vec![0_u8; length];
    stream.read_exact(&mut bytes).await?;
    let response: StorageFilesystemResponseV2 =
        serde_json::from_slice(&bytes).context("decode FUSE callback probe")?;
    if response.protocol_version != STORAGE_FILESYSTEM_PROTOCOL_V2 {
        bail!("FUSE callback probe protocol mismatch");
    }
    Ok(response)
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
    if !matches!(
        kill(Pid::from_raw(pid), None),
        Ok(()) | Err(nix::errno::Errno::EPERM)
    ) {
        return false;
    }
    #[cfg(target_os = "linux")]
    if let Some(identity) = parent.start_identity.as_deref() {
        return linux_process_start_identity(parent.pid).as_deref() == Some(identity);
    }
    #[cfg(not(target_os = "linux"))]
    if parent.start_identity.is_some() {
        return false;
    }
    true
}

#[cfg(not(unix))]
fn parent_is_alive(
    _parent: &astrid_core::storage_filesystem::StorageProviderParentLifetimeV1,
) -> bool {
    false
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_requests_reject_unknown_fields() {
        let value = serde_json::json!({
            "operation": "status",
            "token": "0123456789abcdef",
            "branch": "forbidden"
        });
        assert!(serde_json::from_value::<KernelControlRequest>(value).is_err());
    }

    #[test]
    fn parent_validation_rejects_self_and_missing_linux_identity() {
        let parent = astrid_core::storage_filesystem::StorageProviderParentLifetimeV1 {
            pid: std::process::id(),
            start_identity: None,
            token: "0123456789abcdef0123456789abcdef".to_owned(),
        };
        assert!(validate_parent(&parent).is_err());

        let parent = astrid_core::storage_filesystem::StorageProviderParentLifetimeV1 {
            pid: 2,
            start_identity: None,
            token: "0123456789abcdef0123456789abcdef".to_owned(),
        };
        #[cfg(target_os = "linux")]
        assert!(validate_parent(&parent).is_err());
    }
}
