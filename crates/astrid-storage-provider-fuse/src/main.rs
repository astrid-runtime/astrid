//! Linux lifecycle provider and detached FUSE mount service.

#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("astrid-storage-provider-fuse is available only on Linux");
    std::process::ExitCode::from(2)
}

#[cfg(any(target_os = "linux", test))]
const MAX_FUSE_STDERR_BYTES: usize = 1024;

#[cfg(any(target_os = "linux", test))]
const MAX_PROVIDER_FAILURE_BYTES: usize = 4096;

#[cfg(any(target_os = "linux", test))]
fn bounded_utf8(input: impl Iterator<Item = char>, max_bytes: usize) -> String {
    let mut bounded = String::with_capacity(max_bytes);
    for character in input {
        if bounded
            .len()
            .checked_add(character.len_utf8())
            .is_none_or(|length| length > max_bytes)
        {
            break;
        }
        bounded.push(character);
    }
    bounded
}

#[cfg(any(target_os = "linux", test))]
fn bounded_stderr_snippet(bytes: &[u8]) -> String {
    bounded_utf8(
        String::from_utf8_lossy(bytes)
            .chars()
            .filter(|character| !character.is_control()),
        MAX_FUSE_STDERR_BYTES,
    )
}

#[cfg(any(target_os = "linux", test))]
fn bounded_failure_message(message: &str) -> String {
    bounded_utf8(message.chars(), MAX_PROVIDER_FAILURE_BYTES)
}

#[cfg(test)]
mod stderr_tests {
    use super::{
        MAX_FUSE_STDERR_BYTES, MAX_PROVIDER_FAILURE_BYTES, bounded_failure_message,
        bounded_stderr_snippet,
    };

    #[test]
    fn bounded_stderr_snippet_is_lossy_control_free_and_secret_bounded() {
        let secret = format!("lease-token={}", "a".repeat(MAX_FUSE_STDERR_BYTES));
        let mut bytes = vec![0, 0xff, b'\n'];
        bytes.extend_from_slice(secret.as_bytes());

        let snippet = bounded_stderr_snippet(&bytes);

        assert_eq!(snippet.len(), MAX_FUSE_STDERR_BYTES);
        assert!(snippet.starts_with('\u{fffd}'));
        assert!(snippet.chars().all(|character| !character.is_control()));
        assert!(!snippet.contains(&secret));
        assert_ne!(snippet, String::from_utf8_lossy(&bytes));
    }

    #[test]
    fn bounded_messages_respect_protocol_byte_limits_for_multibyte_text() {
        let multibyte = "😀".repeat(MAX_PROVIDER_FAILURE_BYTES);

        let snippet = bounded_stderr_snippet(multibyte.as_bytes());
        let failure = bounded_failure_message(&multibyte);

        assert_eq!(snippet.len(), MAX_FUSE_STDERR_BYTES);
        assert_eq!(failure.len(), MAX_PROVIDER_FAILURE_BYTES);
        assert!(snippet.is_char_boundary(snippet.len()));
        assert!(failure.is_char_boundary(failure.len()));
    }
}

#[cfg(target_os = "linux")]
macro_rules! linux_only {
    ($($item:item)*) => {
        $($item)*
    };
}

#[cfg(target_os = "linux")]
linux_only! {

use std::collections::BTreeMap;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use astrid_core::kernel_api::{AdminRequestKind, AdminResponseBody};
use astrid_core::storage_filesystem::{
    StorageMountLeaseV1,
};
use astrid_core::storage_provider::{
    STORAGE_PROVIDER_PROTOCOL_V1, StorageMountId, StorageMountSelectorV1, StorageProviderAccessV1,
    StorageProviderCapabilityV1, StorageProviderFailureV1, StorageProviderIdentityV1,
    StorageProviderOperationV1, StorageProviderOutcomeV1, StorageProviderRequestV1,
    StorageProviderResponseV1, StorageProviderSuccessV1,
};
use astrid_uplink::admin_client::AdminClient;
use control::{
    ControlRequest, ControlResponse, ServiceLaunch, ServiceStartup, bind_control_listener,
    call_control, cleanup_service_artifacts,
};
use filesystem::FuseBackgroundSession;
use serde::Deserialize;
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _};

mod callback;
mod control;
mod filesystem;
mod mountpoint;
mod registry;
mod service;

const PROVIDER_NAME: &str = "astrid-storage-provider-fuse";
const MAX_REQUEST_BYTES: u64 = 64 * 1024;
const SERVICE_STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const PUBLIC_SERVICE_ARGUMENT: &str = "--astrid-provider-fuse-public-service-v1";

#[tokio::main]
async fn main() -> ExitCode {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    let result = if arguments.as_slice() == ["--astrid-provider-stdio-v1"] {
        run_stdio().await
    } else if arguments.as_slice() == ["--astrid-provider-fuse-service-v1"] {
        service::run().await
    } else if arguments.as_slice() == [PUBLIC_SERVICE_ARGUMENT] {
        run_public_service().await
    } else {
        Err(anyhow::anyhow!(
            "this executable is an Astrid provider companion, not an interactive command"
        ))
    };
    if let Err(error) = result {
        eprintln!("{PROVIDER_NAME}: {error:#}");
        return ExitCode::from(2);
    }
    ExitCode::SUCCESS
}

async fn run_stdio() -> Result<()> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .lock()
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        bail!("provider request exceeds limit");
    }
    let request: StorageProviderRequestV1 = serde_json::from_slice(&bytes)?;
    if request.protocol_version != STORAGE_PROVIDER_PROTOCOL_V1 {
        bail!("unsupported provider protocol {}", request.protocol_version);
    }
    let request_id = request.request_id;
    let outcome = match execute(request).await {
        Ok(success) => StorageProviderOutcomeV1::Success(success),
        Err(error) => StorageProviderOutcomeV1::Failure(StorageProviderFailureV1 {
            code: "provider-operation".to_owned(),
            message: bounded_failure_message(&error.to_string()),
        }),
    };
    let response = StorageProviderResponseV1 {
        protocol_version: STORAGE_PROVIDER_PROTOCOL_V1,
        request_id,
        provider: StorageProviderIdentityV1 {
            name: PROVIDER_NAME.to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            capabilities: vec![
                StorageProviderCapabilityV1::PrincipalView,
                StorageProviderCapabilityV1::FleetView,
                StorageProviderCapabilityV1::AdminView,
                StorageProviderCapabilityV1::ReadOnly,
                StorageProviderCapabilityV1::ReadWrite,
                StorageProviderCapabilityV1::Lifecycle,
            ],
        },
        outcome,
    };
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(&mut stdout, &response)?;
    stdout.write_all(b"\n")?;
    stdout.flush()?;
    Ok(())
}

async fn execute(request: StorageProviderRequestV1) -> Result<StorageProviderSuccessV1> {
    let acting_principal = request.acting_principal_hint;
    let mut client = AdminClient::connect(acting_principal.clone()).await?;
    let _lifecycle_lock = registry::lock_registry()?;
    match request.operation {
        StorageProviderOperationV1::Mount {
            view,
            access,
            mountpoint,
        } => mount(&mut client, acting_principal, view, access, mountpoint).await,
        StorageProviderOperationV1::Sync { selector } => {
            sync(&mut client, &acting_principal, &selector).await
        },
        StorageProviderOperationV1::Status { selector } => {
            status(&mut client, &acting_principal, &selector).await
        },
        StorageProviderOperationV1::Unmount { selector } => {
            unmount(&mut client, &acting_principal, &selector).await
        },
    }
}

async fn mount(
    client: &mut AdminClient,
    acting_principal: astrid_core::PrincipalId,
    view: astrid_core::storage_provider::StorageProviderViewV1,
    access: StorageProviderAccessV1,
    requested_mountpoint: Option<PathBuf>,
) -> Result<StorageProviderSuccessV1> {
    let (mountpoint, auto_created) = mountpoint::prepare_mountpoint(requested_mountpoint, &view)?;
    ensure_mountpoint_available(client, &acting_principal, &mountpoint).await?;
    let body = client
        .request(AdminRequestKind::StorageMountIssue {
            view,
            access,
            provider: PROVIDER_NAME.to_owned(),
            mountpoint: mountpoint.clone(),
        })
        .await?;
    let lease = lease_from_response(body)?;
    let control_path = registry::control_path(&lease.mount_id)?;
    let launch = ServiceLaunch {
        lease: lease.clone(),
        requested_by: acting_principal,
        mountpoint: mountpoint.clone(),
        auto_created_mountpoint: auto_created,
    };
    let startup = launch_service(&launch, &control_path).await;
    let ready = match startup {
        Ok(ready) => ready,
        Err(error) => {
            let _ = client
                .request(AdminRequestKind::StorageMountRevoke {
                    mount_id: lease.mount_id,
                })
                .await;
            cleanup_mountpoint(&mountpoint, auto_created)?;
            return Err(error);
        },
    };
    if ready.mount_id != lease.mount_id || ready.access != lease.access {
        let _ = control_unmount(&control_path, &launch.requested_by);
        let _ = client
            .request(AdminRequestKind::StorageMountRevoke {
                mount_id: lease.mount_id,
            })
            .await;
        cleanup_mountpoint(&mountpoint, auto_created)?;
        bail!("detached FUSE service returned a mismatched lease identity");
    }
    if ready.pid == 0 {
        bail!("detached FUSE service returned an invalid process identity");
    }
    let record = registry::MountRecord {
        mount_id: lease.mount_id,
        requested_by: launch.requested_by,
        mountpoint: mountpoint.clone(),
        access: lease.access,
        auto_created_mountpoint: auto_created,
        control_path: control_path.clone(),
    };
    if let Err(error) = registry::write_record(&record) {
        let _ = control_unmount(&control_path, &record.requested_by);
        let _ = client
            .request(AdminRequestKind::StorageMountRevoke {
                mount_id: lease.mount_id,
            })
            .await;
        cleanup_mountpoint(&mountpoint, auto_created)?;
        return Err(error);
    }
    Ok(StorageProviderSuccessV1::Mounted {
        mount_id: lease.mount_id,
        mountpoint,
    })
}

async fn sync(
    client: &mut AdminClient,
    acting_principal: &astrid_core::PrincipalId,
    selector: &StorageMountSelectorV1,
) -> Result<StorageProviderSuccessV1> {
    let record = registry::resolve_record(selector)?;
    let status = require_live_lease(client, acting_principal, &record).await?;
    validate_record(&record, &status)?;
    let control = live_control_status(client, acting_principal, &record).await?;
    match control {
        ControlResponse::Status { access } if access == record.access => {},
        ControlResponse::Status { access } => {
            bail!("detached FUSE service access {access:?} does not match lease")
        },
        ControlResponse::Done => bail!("FUSE service returned an incompatible status response"),
        ControlResponse::Failure { code, message } => {
            bail!("FUSE service status failed [{code}]: {message}")
        },
    }
    into_success(
        client
            .request(AdminRequestKind::StorageMountSync {
                mount_id: record.mount_id,
            })
            .await?,
    )?;
    Ok(StorageProviderSuccessV1::Synced {
        mount_id: record.mount_id,
    })
}

async fn status(
    client: &mut AdminClient,
    acting_principal: &astrid_core::PrincipalId,
    selector: &StorageMountSelectorV1,
) -> Result<StorageProviderSuccessV1> {
    let record = registry::resolve_record(selector)?;
    let lease_status = require_live_lease(client, acting_principal, &record).await?;
    validate_record(&record, &lease_status)?;
    let control = live_control_status(client, acting_principal, &record).await?;
    match control {
        ControlResponse::Status { access } if access == record.access => {},
        ControlResponse::Status { access } => {
            bail!("detached FUSE service access {access:?} does not match lease")
        },
        ControlResponse::Done => bail!("FUSE service returned an incompatible status response"),
        ControlResponse::Failure { code, message } => {
            bail!("FUSE service status failed [{code}]: {message}")
        },
    }
    Ok(StorageProviderSuccessV1::Status {
        mount_id: record.mount_id,
        mountpoint: record.mountpoint,
        access: record.access,
        dirty: lease_status.dirty,
    })
}

async fn unmount(
    client: &mut AdminClient,
    acting_principal: &astrid_core::PrincipalId,
    selector: &StorageMountSelectorV1,
) -> Result<StorageProviderSuccessV1> {
    let record = registry::resolve_record(selector)?;
    if &record.requested_by != acting_principal {
        bail!("mount was issued to another acting principal");
    }
    let live = if let Some(status) = kernel_lease_status(client, &record.mount_id).await? {
        if status.mountpoint != record.mountpoint || status.access != record.access {
            bail!("kernel lease metadata does not match the FUSE provider registry");
        }
        true
    } else {
        cleanup_stale_record(client, acting_principal, &record).await?;
        false
    };
    if live {
        let control_result = control_unmount(&record.control_path, acting_principal);
        if let Err(error) = control_result {
            eprintln!(
                "falling back to stale FUSE cleanup after control unmount failure: {error:#}"
            );
            cleanup_stale_record(client, acting_principal, &record).await?;
        } else {
            into_success(
                client
                    .request(AdminRequestKind::StorageMountRevoke {
                        mount_id: record.mount_id,
                    })
                    .await?,
            )?;
        }
    }
    registry::remove_record(&record.mount_id)?;
    cleanup_mountpoint(&record.mountpoint, record.auto_created_mountpoint)?;
    Ok(StorageProviderSuccessV1::Unmounted {
        mount_id: record.mount_id,
    })
}

async fn run_public_service() -> Result<()> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .lock()
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        bail!("FUSE service launch exceeds limit");
    }
    let launch: ServiceLaunch = serde_json::from_slice(&bytes)?;
    let lease = launch.lease.clone();
    let control_path = registry::control_path(&lease.mount_id)?;
    let listener = bind_control_listener(&control_path)?;
    let mut session = match filesystem::start_session(lease.clone(), &launch.mountpoint) {
        Ok(session) => Some(session),
        Err(error) => {
            let _ = cleanup_service_artifacts(
                &control_path,
                &launch.mountpoint,
                launch.auto_created_mountpoint,
            );
            return Err(error);
        },
    };
    let stderr_sink = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/null")
        .context("open detached FUSE stderr sink")?;
    nix::unistd::dup2_stderr(&stderr_sink).context("hand off detached FUSE stderr sink")?;
    drop(stderr_sink);
    let startup = ServiceStartup::Ready {
        mount_id: lease.mount_id,
        pid: std::process::id(),
        access: lease.access,
    };
    let startup_bytes = serde_json::to_vec(&startup)?;
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(&startup_bytes)?;
    stdout.write_all(b"\n")?;
    stdout.flush()?;

    let result = service_loop(&listener, &launch, &mut session).await;
    cleanup_service_artifacts(
        &control_path,
        &launch.mountpoint,
        launch.auto_created_mountpoint,
    )?;
    result
}

async fn service_loop(
    listener: &tokio::net::UnixListener,
    launch: &ServiceLaunch,
    session: &mut Option<FuseBackgroundSession>,
) -> Result<()> {
    loop {
        let (mut stream, _) = listener.accept().await?;
        let mut line = String::new();
        let reader = tokio::io::BufReader::new(&mut stream);
        let mut limited = reader.take(64 * 1024 + 1);
        limited.read_line(&mut line).await?;
        let request: ControlRequest = serde_json::from_str(&line)?;
        let response = if request_principal(&request) == &launch.requested_by {
            match request {
                ControlRequest::Status { .. } => ControlResponse::Status {
                    access: launch.lease.access,
                },
                ControlRequest::Unmount { .. } => match session.take() {
                    Some(session) => {
                        let result =
                            tokio::task::spawn_blocking(|| session.umount_and_join()).await;
                        match result {
                            Ok(Ok(())) => ControlResponse::Done,
                            Ok(Err(error)) => {
                                failure_response("unmount", &format!("unmount FUSE: {error}"))
                            },
                            Err(error) => {
                                failure_response("unmount", &format!("join FUSE worker: {error}"))
                            },
                        }
                    },
                    None => failure_response("unmount", "FUSE session already stopped"),
                },
            }
        } else {
            failure_response("unauthorized", "FUSE service belongs to another principal")
        };
        let bytes = serde_json::to_vec(&response)?;
        stream.write_all(&bytes).await?;
        stream.write_all(b"\n").await?;
        stream.flush().await?;
        if matches!(response, ControlResponse::Done) {
            return Ok(());
        }
    }
}

fn request_principal(request: &ControlRequest) -> &astrid_core::PrincipalId {
    match request {
        ControlRequest::Status { requested_by } | ControlRequest::Unmount { requested_by } => {
            requested_by
        },
    }
}

async fn live_control_status(
    client: &mut AdminClient,
    acting_principal: &astrid_core::PrincipalId,
    record: &registry::MountRecord,
) -> Result<ControlResponse> {
    match call_control(
        &record.control_path,
        &ControlRequest::Status {
            requested_by: acting_principal.clone(),
        },
    ) {
        Ok(response) => Ok(response),
        Err(error) => {
            cleanup_stale_record(client, acting_principal, record).await?;
            bail!("stale FUSE service was cleaned up after control failure: {error:#}")
        },
    }
}

fn failure_response(code: &str, message: &str) -> ControlResponse {
    ControlResponse::Failure {
        code: code.to_owned(),
        message: bounded_failure_message(message),
    }
}

async fn launch_service(launch: &ServiceLaunch, control_path: &Path) -> Result<ControlReady> {
    use std::os::unix::process::CommandExt as _;

    let executable = std::env::current_exe()?;
    let mut command = tokio::process::Command::new(executable);
    command
        .arg(PUBLIC_SERVICE_ARGUMENT)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    command.as_std_mut().process_group(0);
    let mut child = command.spawn()?;
    let Some(mut stderr) = child.stderr.take() else {
        let _ = child.kill().await;
        let status = child.wait().await;
        return Err(anyhow::anyhow!("FUSE service stderr is unavailable")
            .context(format!("detached FUSE service status: {status:?}")));
    };
    let mut stderr_task = tokio::spawn(async move {
        let mut bytes = Vec::with_capacity(MAX_FUSE_STDERR_BYTES + 1);
        let mut buffer = [0_u8; 4096];
        loop {
            let read = stderr.read(&mut buffer).await?;
            if read == 0 {
                break;
            }
            let remaining = (MAX_FUSE_STDERR_BYTES + 1).saturating_sub(bytes.len());
            bytes.extend_from_slice(&buffer[..read.min(remaining)]);
        }
        std::io::Result::Ok(bytes)
    });
    let startup = read_service_startup(&mut child, launch, control_path).await;
    match startup {
        Ok(ready) => {
            match tokio::time::timeout(Duration::from_secs(1), &mut stderr_task).await {
                Ok(Ok(Ok(_))) => require_service_running_after_handoff(&mut child)
                    .await
                    .map(|()| ready),
                Ok(Ok(Err(error))) => {
                    let _ = child.kill().await;
                    let status = child.wait().await;
                    Err(anyhow::Error::new(error)
                        .context("read detached FUSE stderr during sink handoff")
                        .context(format!("detached FUSE service status: {status:?}")))
                },
                Ok(Err(error)) => {
                    let _ = child.kill().await;
                    let status = child.wait().await;
                    Err(anyhow::anyhow!("detached FUSE stderr drain failed: {error}")
                        .context(format!("detached FUSE service status: {status:?}")))
                },
                Err(_) => {
                    stderr_task.abort();
                    let _ = child.kill().await;
                    let status = child.wait().await;
                    Err(anyhow::anyhow!("detached FUSE stderr sink handoff timed out")
                        .context(format!("detached FUSE service status: {status:?}")))
                },
            }
        },
        Err(error) => {
            let _ = child.kill().await;
            let status = child.wait().await;
            let stderr = match stderr_task.await {
                Ok(Ok(bytes)) => bounded_stderr_snippet(&bytes),
                Ok(Err(_)) | Err(_) => String::new(),
            };
            let status_context = format!("detached FUSE service status: {status:?}");
            if stderr.is_empty() {
                Err(error.context(status_context))
            } else {
                Err(error.context(format!("{status_context}; stderr: {stderr}")))
            }
        },
    }
}

async fn require_service_running_after_handoff(
    child: &mut tokio::process::Child,
) -> Result<()> {
    match child.try_wait() {
        Ok(None) => Ok(()),
        Ok(Some(status)) => bail!("detached FUSE service exited after readiness: {status}"),
        Err(error) => {
            let _ = child.kill().await;
            let status = child.wait().await;
            Err(anyhow::Error::new(error)
                .context("inspect detached FUSE service after stderr sink handoff")
                .context(format!("detached FUSE service status: {status:?}")))
        },
    }
}

async fn read_service_startup(
    child: &mut tokio::process::Child,
    launch: &ServiceLaunch,
    control_path: &Path,
) -> Result<ControlReady> {
    let mut stdin = child
        .stdin
        .take()
        .context("FUSE service stdin is unavailable")?;
    let bytes = serde_json::to_vec(launch)?;
    stdin.write_all(&bytes).await?;
    stdin.write_all(b"\n").await?;
    drop(stdin);
    let stdout = child
        .stdout
        .take()
        .context("FUSE service stdout is unavailable")?;
    let mut line = String::new();
    let reader = tokio::io::BufReader::new(stdout);
    let read = tokio::time::timeout(SERVICE_STARTUP_TIMEOUT, async {
        let mut limited = reader.take(64 * 1024 + 1);
        limited.read_line(&mut line).await
    })
    .await
    .context("timed out waiting for the FUSE service")??;
    if read == 0 {
        bail!("detached FUSE service exited before readiness");
    }
    if line.len() > 64 * 1024 {
        bail!("detached FUSE service exceeded the startup response size");
    }
    match serde_json::from_str(&line)? {
        ServiceStartup::Ready {
            mount_id,
            pid,
            access,
        } => {
            if !control_path.exists() {
                bail!("detached FUSE service did not retain its control endpoint");
            }
            if pid == 0 {
                bail!("detached FUSE service returned an invalid process identity");
            }
            Ok(ControlReady {
                mount_id,
                pid,
                access,
            })
        },
        ServiceStartup::Error { message } => bail!("detached FUSE service failed: {message}"),
    }
}

#[derive(Debug)]
struct ControlReady {
    mount_id: StorageMountId,
    pid: u32,
    access: StorageProviderAccessV1,
}

#[derive(Debug, Deserialize)]
struct LeaseStatus {
    #[allow(dead_code)]
    mount_id: StorageMountId,
    access: StorageProviderAccessV1,
    mountpoint: PathBuf,
    dirty: bool,
}

async fn kernel_lease_status(
    client: &mut AdminClient,
    mount_id: &StorageMountId,
) -> Result<Option<LeaseStatus>> {
    let body = client
        .request(AdminRequestKind::StorageMountStatus {
            mount_id: *mount_id,
        })
        .await?;
    match body {
        AdminResponseBody::Success(value) => {
            let status =
                serde_json::from_value(value).context("decode kernel storage mount status")?;
            Ok(Some(status))
        },
        AdminResponseBody::Error(error)
            if error.contains("was not found") || error.contains("expired or revoked") =>
        {
            Ok(None)
        },
        AdminResponseBody::Error(error) => {
            bail!("kernel refused storage lifecycle request: {error}")
        },
        _ => bail!("kernel returned an unexpected storage lifecycle response"),
    }
}

async fn require_live_lease(
    client: &mut AdminClient,
    acting_principal: &astrid_core::PrincipalId,
    record: &registry::MountRecord,
) -> Result<LeaseStatus> {
    if &record.requested_by != acting_principal {
        bail!("mount was issued to another acting principal");
    }
    kernel_lease_status(client, &record.mount_id)
        .await?
        .with_context(|| format!("storage mount lease {} is stale", record.mount_id))
}

fn validate_record(record: &registry::MountRecord, status: &LeaseStatus) -> Result<()> {
    if status.mountpoint != record.mountpoint || status.access != record.access {
        bail!("kernel lease metadata does not match the FUSE provider registry");
    }
    if record.control_path != registry::control_path(&record.mount_id)? {
        bail!("FUSE provider control path is not canonical");
    }
    Ok(())
}

async fn ensure_mountpoint_available(
    client: &mut AdminClient,
    acting_principal: &astrid_core::PrincipalId,
    mountpoint: &Path,
) -> Result<()> {
    let key = mountpoint
        .to_str()
        .context("mountpoint must be canonical Unicode text")?
        .to_owned();
    let registry: BTreeMap<String, registry::MountRecord> = registry::load_registry()?;
    let Some(record) = registry.get(&key).cloned() else {
        return Ok(());
    };
    let status = kernel_lease_status(client, &record.mount_id).await?;
    let Some(status) = status else {
        cleanup_stale_record(client, acting_principal, &record).await?;
        return Ok(());
    };
    validate_record(&record, &status)?;
    match call_control(
        &record.control_path,
        &ControlRequest::Status {
            requested_by: record.requested_by.clone(),
        },
    ) {
        Ok(ControlResponse::Status { access }) if access == status.access => {
            bail!("mountpoint is already mounted: {}", mountpoint.display())
        },
        Ok(ControlResponse::Status { access }) => {
            bail!("registered FUSE service access {access:?} does not match its lease")
        },
        Ok(_) => bail!("registered FUSE service returned an incompatible status response"),
        Err(_) => {
            cleanup_stale_record(client, acting_principal, &record).await?;
            Ok(())
        },
    }
}

async fn cleanup_stale_record(
    client: &mut AdminClient,
    acting_principal: &astrid_core::PrincipalId,
    record: &registry::MountRecord,
) -> Result<()> {
    let lease_is_live = kernel_lease_status(client, &record.mount_id)
        .await?
        .is_some();
    let _ = call_control(
        &record.control_path,
        &ControlRequest::Unmount {
            requested_by: acting_principal.clone(),
        },
    );
    mountpoint::lazy_unmount(&record.mountpoint)?;
    if lease_is_live {
        into_success(
            client
                .request(AdminRequestKind::StorageMountRevoke {
                    mount_id: record.mount_id,
                })
                .await?,
        )?;
    }
    registry::remove_record(&record.mount_id)?;
    cleanup_service_artifacts(
        &record.control_path,
        &record.mountpoint,
        record.auto_created_mountpoint,
    )?;
    Ok(())
}

fn control_unmount(control_path: &Path, acting_principal: &astrid_core::PrincipalId) -> Result<()> {
    match call_control(
        control_path,
        &ControlRequest::Unmount {
            requested_by: acting_principal.clone(),
        },
    )? {
        ControlResponse::Done => Ok(()),
        ControlResponse::Failure { code, message } => {
            bail!("FUSE service unmount failed [{code}]: {message}")
        },
        ControlResponse::Status { .. } => {
            bail!("FUSE service returned an incompatible unmount response")
        },
    }
}

fn cleanup_mountpoint(mountpoint: &Path, auto_created: bool) -> Result<()> {
    if auto_created
        && !mountpoint::mountinfo_contains(mountpoint)?
        && std::fs::symlink_metadata(mountpoint).is_ok_and(|metadata| metadata.is_dir())
        && std::fs::read_dir(mountpoint)?.next().is_none()
    {
        let _ = std::fs::remove_dir(mountpoint);
    }
    Ok(())
}

fn lease_from_response(body: AdminResponseBody) -> Result<StorageMountLeaseV1> {
    match body {
        AdminResponseBody::StorageMountLease(lease) => Ok(*lease),
        AdminResponseBody::Error(error) => bail!("kernel refused storage mount: {error}"),
        _ => bail!("kernel returned an unexpected storage mount response"),
    }
}

fn into_success(body: AdminResponseBody) -> Result<serde_json::Value> {
    match body {
        AdminResponseBody::Success(value) => Ok(value),
        AdminResponseBody::Error(error) => {
            bail!("kernel refused storage lifecycle request: {error}")
        },
        _ => bail!("kernel returned an unexpected storage lifecycle response"),
    }
}

#[cfg(test)]
mod launcher_tests {
    use super::require_service_running_after_handoff;
    use anyhow::Result;

    #[tokio::test]
    async fn stderr_handoff_rejects_a_service_that_already_exited() -> Result<()> {
        let mut child = tokio::process::Command::new("/bin/sh")
            .args(["-c", "exit 0"])
            .spawn()?;
        let status = child.wait().await?;
        assert!(status.success());

        let error = require_service_running_after_handoff(&mut child)
            .await
            .expect_err("an exited service must not be registered as ready");
        assert!(error.to_string().contains("exited after readiness"));
        Ok(())
    }

    #[tokio::test]
    async fn stderr_handoff_accepts_a_service_that_is_still_running() -> Result<()> {
        let mut child = tokio::process::Command::new("/bin/sh")
            .args(["-c", "sleep 30"])
            .spawn()?;

        require_service_running_after_handoff(&mut child).await?;
        child.kill().await?;
        let _ = child.wait().await?;
        Ok(())
    }
}

}
