//! Private control protocol for detached FUSE services.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::{UnixListener as StdUnixListener, UnixStream};
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use astrid_core::PrincipalId;
use astrid_core::storage_filesystem::StorageMountLeaseV1;
use astrid_core::storage_provider::StorageProviderAccessV1;
use serde::{Deserialize, Serialize};

use crate::mountpoint::mountinfo_contains;

const MAX_CONTROL_FRAME_BYTES: usize = 64 * 1024;

/// Arguments passed over a private pipe when detaching the FUSE service.
#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct ServiceLaunch {
    /// Lease material used only by the detached service.
    pub lease: StorageMountLeaseV1,
    /// Principal that requested the mount.
    pub requested_by: PrincipalId,
    /// Canonical mountpoint.
    pub mountpoint: std::path::PathBuf,
    /// Whether the provider created the empty mountpoint leaf.
    pub auto_created_mountpoint: bool,
}

/// Startup result returned on one bounded line.
#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub(crate) enum ServiceStartup {
    /// The kernel mount and private control socket are live.
    Ready {
        /// Lease identity.
        mount_id: astrid_core::storage_provider::StorageMountId,
        /// PID retaining the FUSE session.
        pid: u32,
        /// Actual lease access class.
        access: StorageProviderAccessV1,
    },
    /// Startup failed explicitly.
    Error {
        /// Bounded diagnostic.
        message: String,
    },
}

/// One request to a detached mount service.
#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "operation", rename_all = "kebab-case")]
pub(crate) enum ControlRequest {
    /// Confirm the service is live and return its fixed access mode.
    Status {
        /// Required requesting principal.
        requested_by: PrincipalId,
    },
    /// Unmount and terminate the service.
    Unmount {
        /// Required requesting principal.
        requested_by: PrincipalId,
    },
}

/// One authenticated request accepted only by the kernel-created service
/// mode.  The public provider lifecycle keeps the principal-bound protocol
/// above so existing stdio clients remain compatible.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", tag = "operation", deny_unknown_fields)]
pub(crate) enum KernelControlRequest {
    /// Confirm the service is live with the broker bearer.
    Status {
        /// Parent-lifetime bearer.
        token: String,
    },
    /// Unmount and terminate the service with the broker bearer.
    Stop {
        /// Parent-lifetime bearer.
        token: String,
    },
}

/// Response from the kernel-created service control endpoint.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", tag = "status", deny_unknown_fields)]
pub(crate) enum KernelControlResponse {
    /// The service remains mounted.
    Ready,
    /// The service accepted a stop request and has unmounted.
    Stopped,
    /// The request was rejected.
    Failure {
        /// Stable local error code.
        code: String,
        /// Bounded diagnostic.
        message: String,
    },
}

/// One detached mount-service response.
#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub(crate) enum ControlResponse {
    /// Service status.
    Status {
        /// Access class retained by the service.
        access: StorageProviderAccessV1,
    },
    /// Operation completed.
    Done,
    /// Service refused the request.
    Failure {
        /// Stable local error code.
        code: String,
        /// Bounded diagnostic.
        message: String,
    },
}

/// Bind a fresh private control socket, refusing to replace a live service.
pub(crate) fn bind_control_listener(path: &Path) -> Result<tokio::net::UnixListener> {
    if path.symlink_metadata().is_ok() {
        if UnixStream::connect(path).is_ok() {
            bail!("FUSE service control endpoint is already live");
        }
        std::fs::remove_file(path).with_context(|| {
            format!(
                "remove stale FUSE service control socket {}",
                path.display()
            )
        })?;
    }
    if let Some(parent) = path.parent() {
        astrid_core::platform_fs::ensure_private_directory(parent)?;
    }
    let listener = StdUnixListener::bind(path)
        .with_context(|| format!("bind FUSE service control socket {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    tokio::net::UnixListener::from_std(listener)
        .context("convert FUSE control listener to the async runtime")
}

/// Send one newline-delimited control request and read one response.
pub(crate) fn call_control(path: &Path, request: &ControlRequest) -> Result<ControlResponse> {
    let mut stream = UnixStream::connect(path)
        .with_context(|| format!("connect FUSE service control socket {}", path.display()))?;
    let bytes = serde_json::to_vec(request)?;
    if bytes.len() >= MAX_CONTROL_FRAME_BYTES {
        bail!("FUSE control request exceeds the bounded frame size");
    }
    stream.write_all(&bytes)?;
    stream.write_all(b"\n")?;
    stream.flush()?;
    let mut reader = BufReader::new(stream);
    read_control_response(&mut reader)
}

fn read_control_response(reader: &mut BufReader<UnixStream>) -> Result<ControlResponse> {
    let mut line = String::new();
    let mut limited = reader.take((MAX_CONTROL_FRAME_BYTES + 1) as u64);
    limited
        .read_line(&mut line)
        .context("read FUSE service control response")?;
    if line.len() > MAX_CONTROL_FRAME_BYTES {
        bail!("FUSE service control response exceeds the bounded frame size");
    }
    serde_json::from_str(&line).context("decode FUSE service control response")
}

/// Remove the control endpoint and auto-created empty mountpoint.
pub(crate) fn cleanup_service_artifacts(
    control_path: &Path,
    mountpoint: &Path,
    auto_created: bool,
) -> Result<()> {
    let _ = std::fs::remove_file(control_path);
    if auto_created
        && !mountinfo_contains(mountpoint)?
        && std::fs::symlink_metadata(mountpoint).is_ok_and(|metadata| metadata.is_dir())
        && std::fs::read_dir(mountpoint)?.next().is_none()
    {
        let _ = std::fs::remove_dir(mountpoint);
    }
    Ok(())
}
