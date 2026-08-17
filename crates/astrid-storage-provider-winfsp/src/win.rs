#![allow(unsafe_code)]

use std::io::{Read as _, Write as _};
use std::os::windows::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};
use astrid_core::local_transport;
use astrid_core::storage_filesystem::StorageMountLeaseV1;
use astrid_core::storage_provider::StorageProviderAccessV1;
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _};
use widestring::U16CString;
use windows_sys::Win32::System::LibraryLoader::LoadLibraryW;
use windows_sys::Win32::System::Threading::{CREATE_NEW_PROCESS_GROUP, DETACHED_PROCESS};
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

    let runtime = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .context("start WinFsp callback runtime")?,
    );
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
