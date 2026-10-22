//! Confirm native projection unmount before releasing leases or removing roots.

#[cfg(target_os = "linux")]
use std::path::PathBuf;
use std::{path::Path, time::Duration};

// Poll cadence only; command and confirmation waits use operator policy.
const UNMOUNT_CONFIRM_INTERVAL: Duration = Duration::from_millis(50);

pub(super) async fn confirm_projection_unmounted(
    paths: &super::ProjectionMountPaths,
    policy: super::ProcessStopPolicy,
) -> bool {
    let mountpoints = [&paths.workspace, &paths.owner]
        .into_iter()
        .chain(paths.fleet_shared.as_ref());
    for mountpoint in mountpoints {
        if let Err(error) = ensure_unmounted(mountpoint, policy.unmount_confirmation()).await {
            tracing::error!(%error, "native projection unmount failed; retaining fenced resources");
            return false;
        }
    }
    true
}

pub(super) async fn ensure_unmounted(mountpoint: &Path, timeout: Duration) -> Result<(), String> {
    if !native_projection_mount_is_active(mountpoint)? {
        return Ok(());
    }
    if let Err(error) = unmount_known_projection_path(mountpoint, timeout).await {
        if !native_projection_mount_is_active(mountpoint)? {
            return Ok(());
        }
        return Err(error);
    }
    let deadline = tokio::time::Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(tokio::time::Instant::now);
    loop {
        if !native_projection_mount_is_active(mountpoint)? {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(format!(
                "projection mountpoint remains mounted: {}",
                mountpoint.display()
            ));
        }
        tokio::time::sleep(UNMOUNT_CONFIRM_INTERVAL).await;
    }
}

fn native_projection_mount_is_active(mountpoint: &Path) -> Result<bool, String> {
    #[cfg(target_os = "macos")]
    {
        match nix::sys::statfs::statfs(mountpoint) {
            Ok(status) => Ok(status.filesystem_type_name() == "astridfs"),
            Err(nix::errno::Errno::ENOENT) => Ok(false),
            Err(error) => Err(format!(
                "inspect projection mountpoint {}: {error}",
                mountpoint.display()
            )),
        }
    }
    #[cfg(target_os = "linux")]
    {
        let canonical = match std::fs::canonicalize(mountpoint) {
            Ok(path) => path,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => {
                return Err(format!(
                    "canonicalize projection mountpoint {}: {error}",
                    mountpoint.display()
                ));
            },
        };
        linux_mountinfo_has_path(&canonical)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        match std::fs::symlink_metadata(mountpoint) {
            Ok(_) => Ok(false),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(format!(
                "inspect projection mountpoint {}: {error}",
                mountpoint.display()
            )),
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
async fn unmount_known_projection_path(mountpoint: &Path, timeout: Duration) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    const UMOUNT: &str = "/sbin/umount";
    #[cfg(target_os = "linux")]
    const UMOUNT: &str = "/bin/umount";

    run_unmount_command(UMOUNT, mountpoint, timeout).await
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
async fn run_unmount_command(
    program: impl AsRef<std::ffi::OsStr>,
    mountpoint: &Path,
    timeout: Duration,
) -> Result<(), String> {
    let mut child = tokio::process::Command::new(program)
        .arg(mountpoint)
        .kill_on_drop(true)
        .spawn()
        .map_err(|error| format!("invoke native unmount {}: {error}", mountpoint.display()))?;
    match tokio::time::timeout(timeout, child.wait()).await {
        Ok(Ok(status)) if status.success() => Ok(()),
        Ok(Ok(status)) => Err(format!(
            "native unmount of {} failed with {status}",
            mountpoint.display()
        )),
        Ok(Err(error)) => Err(format!(
            "invoke native unmount {}: {error}",
            mountpoint.display()
        )),
        Err(_) => {
            let _ = child.start_kill();
            match tokio::time::timeout(timeout, child.wait()).await {
                Ok(Ok(_)) => Err(format!(
                    "native unmount of {} timed out",
                    mountpoint.display()
                )),
                Ok(Err(error)) => Err(format!(
                    "invoke native unmount {}: {error}",
                    mountpoint.display()
                )),
                Err(_) => Err(format!(
                    "native unmount of {} timed out and did not reap",
                    mountpoint.display()
                )),
            }
        },
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn unmount_known_projection_path(
    mountpoint: &Path,
    _timeout: Duration,
) -> std::future::Ready<Result<(), String>> {
    let _ = mountpoint;
    std::future::ready(Ok(()))
}

#[cfg(target_os = "linux")]
fn linux_mountinfo_has_path(canonical: &Path) -> Result<bool, String> {
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo")
        .map_err(|error| format!("read mount table: {error}"))?;
    Ok(mountinfo.lines().any(|line| {
        line.split_whitespace()
            .nth(4)
            .and_then(decode_mountinfo_path)
            .is_some_and(|mount| mount == canonical)
    }))
}

#[cfg(target_os = "linux")]
fn decode_mountinfo_path(raw: &str) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStringExt as _;

    let mut decoded = Vec::with_capacity(raw.len());
    let bytes = raw.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let escape_end = index.checked_add(4)?;
        let escape_start = index.checked_add(1)?;
        if bytes[index] == b'\\' && escape_end <= bytes.len() {
            let value = u8::from_str_radix(
                std::str::from_utf8(bytes.get(escape_start..escape_end)?).ok()?,
                8,
            )
            .ok()?;
            decoded.push(value);
            index = escape_end;
        } else {
            decoded.push(bytes[index]);
            index = index.checked_add(1)?;
        }
    }
    Some(PathBuf::from(std::ffi::OsString::from_vec(decoded)))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn ensure_unmounted_accepts_missing_and_ordinary_directories() {
        let missing = {
            let temporary = tempfile::tempdir().expect("temporary root");
            temporary.path().join("absent")
        };
        ensure_unmounted(&missing, Duration::from_secs(5))
            .await
            .expect("missing path is not a native projection mount");

        let temporary = tempfile::tempdir().expect("temporary root");
        let empty = temporary.path().join("empty");
        astrid_core::platform_fs::ensure_private_directory(&empty)
            .expect("ordinary empty directory");
        ensure_unmounted(&empty, Duration::from_secs(5))
            .await
            .expect("ordinary empty directory must not be unmounted");
        assert!(empty.is_dir(), "host directory must remain");
    }

    #[cfg(windows)]
    #[test]
    fn native_projection_inspect_fails_closed_on_invalid_path() {
        let invalid = std::path::Path::new(r"C:\*");
        let error = native_projection_mount_is_active(invalid)
            .expect_err("invalid Windows path inspect must fail closed");
        assert!(error.contains("inspect projection mountpoint"), "{error}");
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[tokio::test]
    async fn hung_unmount_command_times_out_and_reaps() {
        use std::os::unix::fs::PermissionsExt as _;

        let temporary = tempfile::tempdir().expect("hung unmount fixture");
        let script = temporary.path().join("hung-umount");
        let pidfile = temporary.path().join("pid");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\necho $$ > '{}'\nexec sleep 30\n",
                pidfile.display()
            ),
        )
        .expect("hung unmount script");
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))
            .expect("executable hung unmount script");
        let mountpoint = temporary.path().join("mnt");
        let error = run_unmount_command(&script, &mountpoint, Duration::from_millis(200))
            .await
            .expect_err("hung unmount must time out");
        assert!(
            error.contains("timed out"),
            "timeout error must name the native unmount: {error}"
        );
        assert!(
            !error.contains("did not reap"),
            "timed-out unmount must reap the owned subprocess: {error}"
        );
        if let Ok(pid_text) = std::fs::read_to_string(&pidfile) {
            let pid = pid_text.trim();
            if !pid.is_empty() {
                let status = std::process::Command::new("/bin/kill")
                    .args(["-0", pid])
                    .status()
                    .expect("probe hung unmount pid");
                assert!(
                    !status.success(),
                    "hung unmount child must be reaped, pid={pid}"
                );
            }
        }
    }
}
