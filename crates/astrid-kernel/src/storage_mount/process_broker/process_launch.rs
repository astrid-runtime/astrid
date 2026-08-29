//! Discovery, launch, and readiness for the coinstalled process provider.

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

type SpawnedProcessProvider = (
    tokio::process::Child,
    Option<tokio::task::JoinHandle<Vec<u8>>>,
);

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
) -> Result<SpawnedProcessProvider, ProcessProviderLaunchError> {
    let Some(mut stdin) = child.stdin.take() else {
        return Err(abort_process_provider(
            child,
            launch,
            "native storage provider stdin unavailable".to_owned(),
            stderr_task,
        )
        .await);
    };
    if let Err(error) = stdin.write_all(&payload).await {
        return Err(abort_process_provider(
            child,
            launch,
            format!("send native storage provider launch: {error}"),
            stderr_task,
        )
        .await);
    }
    Ok((child, stderr_task))
}

pub(super) async fn launch_process_provider(
    launch: &StorageProviderServiceLaunchV1,
) -> Result<tokio::process::Child, ProcessProviderLaunchError> {
    let (child, stderr_task) = spawn_process_provider()?;
    let payload = match serde_json::to_vec(launch) {
        Ok(payload) => payload,
        Err(error) => {
            return Err(abort_process_provider(
                child,
                launch,
                format!("encode native storage provider launch: {error}"),
                stderr_task,
            )
            .await);
        },
    };
    let (child, stderr_task) =
        send_process_provider_payload(child, launch, payload, stderr_task).await?;
    read_process_provider_ready(child, launch, stderr_task).await
}

async fn read_process_provider_ready(
    mut child: tokio::process::Child,
    launch: &StorageProviderServiceLaunchV1,
    stderr_task: Option<tokio::task::JoinHandle<Vec<u8>>>,
) -> Result<tokio::process::Child, ProcessProviderLaunchError> {
    let Some(stdout) = child.stdout.take() else {
        return Err(abort_process_provider(
            child,
            launch,
            "native storage provider stdout unavailable".to_owned(),
            stderr_task,
        )
        .await);
    };
    let mut line = String::new();
    let reader = tokio::io::BufReader::new(stdout);
    let read = match tokio::time::timeout(
        std::time::Duration::from_secs(15),
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
            )
            .await);
        },
        Err(_) => {
            return Err(abort_process_provider(
                child,
                launch,
                "timed out waiting for native storage provider readiness".to_owned(),
                stderr_task,
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
        )
        .await);
    }
    let line = line.strip_suffix('\n').unwrap_or(&line);
    let line = line.strip_suffix('\r').unwrap_or(line);
    if let Err(error) = validate_process_provider_ready(launch, line) {
        return Err(abort_process_provider(child, launch, error, stderr_task).await);
    }
    drop(stderr_task);
    Ok(child)
}

async fn abort_process_provider(
    mut child: tokio::process::Child,
    launch: &StorageProviderServiceLaunchV1,
    message: String,
    stderr_task: Option<tokio::task::JoinHandle<Vec<u8>>>,
) -> ProcessProviderLaunchError {
    let cleanup_ok = stop_process_provider(
        &mut child,
        launch.control_path.clone(),
        launch.parent.token.clone(),
    )
    .await;
    let diagnostics = match stderr_task {
        Some(task) => task.await.ok().and_then(|bytes| {
            (!bytes.is_empty()).then(|| String::from_utf8_lossy(&bytes).trim().to_owned())
        }),
        None => None,
    };
    let message = diagnostics.map_or_else(
        || message.clone(),
        |diagnostics| format!("{message}; provider diagnostics: {diagnostics}"),
    );
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
