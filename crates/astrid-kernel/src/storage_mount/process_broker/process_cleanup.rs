//! Confirm native unmount before revoking process-projection leases.

use std::path::Path;
use std::time::Duration;

use super::*;

const UNMOUNT_CONFIRM_TIMEOUT: Duration = Duration::from_secs(5);
const UNMOUNT_CONFIRM_INTERVAL: Duration = Duration::from_millis(50);

pub(super) struct RunningProvider {
    pub(super) child: tokio::process::Child,
    pub(super) control_path: PathBuf,
    pub(super) token: String,
    pub(super) stopped: bool,
    pub(super) mountpoint: PathBuf,
}

pub(super) struct ProjectionCleanupState {
    pub(super) kernel: std::sync::Weak<Kernel>,
    pub(super) principal: PrincipalId,
    pub(super) branch: RunningProvider,
    pub(super) owner: RunningProvider,
    pub(super) shared: Option<RunningProvider>,
    pub(super) branch_id: StorageMountId,
    pub(super) owner_id: StorageMountId,
    pub(super) shared_id: Option<StorageMountId>,
    pub(super) mount_root: PathBuf,
    pub(super) cleaned: bool,
}

pub(super) async fn cleanup_projection_state(
    cleanup_state: Arc<tokio::sync::Mutex<ProjectionCleanupState>>,
) -> bool {
    let mut state = cleanup_state.lock().await;
    if state.cleaned {
        return true;
    }
    if !stop_projection_providers(&mut state).await {
        return false;
    }
    if !unmount_projection_mounts(&state).await {
        return false;
    }
    let Some(kernel) = state.kernel.upgrade() else {
        tracing::error!("kernel shut down before process storage projection leases were revoked");
        return false;
    };
    if !revoke_projection_leases(&kernel, &state).await {
        return false;
    }
    if let Err(error) = std::fs::remove_dir_all(&state.mount_root) {
        tracing::error!(%error, "failed to remove process storage projection root");
        return false;
    }
    state.cleaned = true;
    true
}

async fn stop_projection_providers(state: &mut ProjectionCleanupState) -> bool {
    let branch_stopped = stop_running_provider(&mut state.branch).await;
    let owner_stopped = stop_running_provider(&mut state.owner).await;
    let shared_stopped = match state.shared.as_mut() {
        Some(shared) => stop_running_provider(shared).await,
        None => true,
    };
    if branch_stopped && owner_stopped && shared_stopped {
        return true;
    }
    tracing::error!(
        branch_stopped,
        owner_stopped,
        shared_stopped,
        "native process storage provider teardown failed; retaining private mount resources"
    );
    false
}

async fn stop_running_provider(provider: &mut RunningProvider) -> bool {
    if provider.stopped {
        return true;
    }
    let stopped = stop_process_provider(
        &mut provider.child,
        provider.control_path.clone(),
        provider.token.clone(),
    )
    .await;
    if stopped {
        provider.stopped = true;
    }
    stopped
}

async fn unmount_projection_mounts(state: &ProjectionCleanupState) -> bool {
    let mut ok = true;
    for mountpoint in projection_mountpoints(state) {
        if let Err(error) = ensure_unmounted(mountpoint).await {
            tracing::error!(
                %error,
                mountpoint = %mountpoint.display(),
                "failed to unmount process storage projection"
            );
            ok = false;
        }
    }
    ok
}

fn projection_mountpoints(state: &ProjectionCleanupState) -> impl Iterator<Item = &Path> {
    std::iter::once(state.branch.mountpoint.as_path())
        .chain(std::iter::once(state.owner.mountpoint.as_path()))
        .chain(
            state
                .shared
                .as_ref()
                .map(|provider| provider.mountpoint.as_path()),
        )
}

async fn revoke_projection_leases(kernel: &Kernel, state: &ProjectionCleanupState) -> bool {
    if revoke_lease_if_present(kernel, &state.principal, true, state.branch_id)
        .await
        .is_err()
        || revoke_lease_if_present(kernel, &state.principal, true, state.owner_id)
            .await
            .is_err()
    {
        tracing::error!("failed to revoke process storage projection leases; retaining resources");
        return false;
    }
    if let Some(shared_id) = state.shared_id
        && revoke_lease_if_present(kernel, &state.principal, true, shared_id)
            .await
            .is_err()
    {
        tracing::error!("failed to revoke Fleet shared projection lease");
        return false;
    }
    true
}

async fn ensure_unmounted(mountpoint: &Path) -> Result<(), String> {
    if !native_projection_mount_is_active(mountpoint)? {
        return Ok(());
    }
    if let Err(error) = unmount_known_projection_path(mountpoint).await {
        if !native_projection_mount_is_active(mountpoint)? {
            return Ok(());
        }
        return Err(error);
    }
    let deadline = tokio::time::Instant::now()
        .checked_add(UNMOUNT_CONFIRM_TIMEOUT)
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
async fn unmount_known_projection_path(mountpoint: &Path) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    const UMOUNT: &str = "/sbin/umount";
    #[cfg(target_os = "linux")]
    const UMOUNT: &str = "/bin/umount";

    let status = tokio::process::Command::new(UMOUNT)
        .arg(mountpoint)
        .status()
        .await
        .map_err(|error| format!("invoke native unmount {}: {error}", mountpoint.display()))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "native unmount of {} failed with {status}",
            mountpoint.display()
        ))
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn unmount_known_projection_path(mountpoint: &Path) -> std::future::Ready<Result<(), String>> {
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

    async fn spawn_reaped_child() -> tokio::process::Child {
        let mut command = {
            #[cfg(unix)]
            {
                tokio::process::Command::new("true")
            }
            #[cfg(windows)]
            {
                let mut command = tokio::process::Command::new("cmd");
                command.args(["/C", "exit", "0"]);
                command
            }
        };
        command.kill_on_drop(true);
        let mut child = command.spawn().expect("spawn reaped child");
        let _ = child.wait().await;
        child
    }

    async fn reaped_provider(mountpoint: PathBuf) -> RunningProvider {
        RunningProvider {
            child: spawn_reaped_child().await,
            control_path: mountpoint.join("missing.sock"),
            token: "unused-token".to_owned(),
            stopped: true,
            mountpoint,
        }
    }

    #[cfg(unix)]
    struct RestoreMode {
        path: PathBuf,
        mode: u32,
    }

    #[cfg(unix)]
    impl Drop for RestoreMode {
        fn drop(&mut self) {
            use std::os::unix::fs::PermissionsExt as _;
            let _ =
                std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(self.mode));
        }
    }

    #[tokio::test]
    async fn ensure_unmounted_accepts_missing_and_ordinary_directories() {
        let missing = {
            let temporary = tempfile::tempdir().expect("temporary root");
            temporary.path().join("absent")
        };
        ensure_unmounted(&missing)
            .await
            .expect("missing path is not a native projection mount");

        let temporary = tempfile::tempdir().expect("temporary root");
        let empty = temporary.path().join("empty");
        astrid_core::platform_fs::ensure_private_directory(&empty)
            .expect("ordinary empty directory");
        ensure_unmounted(&empty)
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn revoke_lease_if_present_is_idempotent_and_preserves_principal_check() {
        let temporary = tempfile::tempdir().unwrap();
        let home = astrid_core::dirs::AstridHome::from_path(temporary.path().join(".astrid"));
        let kernel = crate::test_kernel_with_home(home).await;
        let caller = PrincipalId::default();
        let foreign = PrincipalId::new("other").expect("foreign principal");
        let lease = issue_lease(
            &kernel,
            caller.clone(),
            true,
            StorageProviderViewV1::Admin,
            StorageFilesystemTargetV1::OwnerRoot,
            StorageProviderAccessV1::ReadWrite,
            "cleanup-test-provider".to_owned(),
            temporary.path().join("mount"),
        )
        .await
        .unwrap();

        let error = revoke_lease_if_present(&kernel, &foreign, false, lease.mount_id)
            .await
            .expect_err("foreign principal must not revoke");
        assert!(error.contains("another principal"));

        let state = kernel
            .storage_mounts
            .get(&lease.mount_id)
            .expect("lease remains after foreign reject");
        state.mark_revoked_for_test();
        drop(state);

        revoke_lease_if_present(&kernel, &caller, false, lease.mount_id)
            .await
            .expect("expired present lease is removed");
        revoke_lease_if_present(&kernel, &caller, false, lease.mount_id)
            .await
            .expect("missing lease is success");
        revoke_lease_if_present(&kernel, &caller, false, StorageMountId::new())
            .await
            .expect("unknown lease is success");
        let missing = revoke_lease(&kernel, &caller, false, StorageMountId::new())
            .await
            .expect_err("admin revoke still fails closed on missing");
        assert!(missing.contains("was not found"));
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cleanup_retries_after_failed_root_removal() {
        use std::os::unix::fs::PermissionsExt as _;

        let temporary = tempfile::tempdir().unwrap();
        let home = astrid_core::dirs::AstridHome::from_path(temporary.path().join(".astrid"));
        let kernel = crate::test_kernel_with_home(home).await;
        let caller = PrincipalId::default();
        let mount_root = temporary.path().join("process-root");
        let workspace = mount_root.join("workspace");
        let owner = mount_root.join("owner");
        astrid_core::platform_fs::ensure_private_directory(&workspace).unwrap();
        astrid_core::platform_fs::ensure_private_directory(&owner).unwrap();

        let branch_lease = issue_lease(
            &kernel,
            caller.clone(),
            true,
            StorageProviderViewV1::Admin,
            StorageFilesystemTargetV1::OwnerRoot,
            StorageProviderAccessV1::ReadWrite,
            "cleanup-branch".to_owned(),
            workspace.clone(),
        )
        .await
        .unwrap();
        let owner_lease = issue_lease(
            &kernel,
            caller.clone(),
            true,
            StorageProviderViewV1::Admin,
            StorageFilesystemTargetV1::OwnerRoot,
            StorageProviderAccessV1::ReadWrite,
            "cleanup-owner".to_owned(),
            owner.clone(),
        )
        .await
        .unwrap();

        let cleanup_state = Arc::new(tokio::sync::Mutex::new(ProjectionCleanupState {
            kernel: Arc::downgrade(&kernel),
            principal: caller.clone(),
            branch: reaped_provider(workspace).await,
            owner: reaped_provider(owner).await,
            shared: None,
            branch_id: branch_lease.mount_id,
            owner_id: owner_lease.mount_id,
            shared_id: None,
            mount_root: mount_root.clone(),
            cleaned: false,
        }));

        let original = std::fs::metadata(&mount_root)
            .expect("mount root metadata")
            .permissions()
            .mode();
        let first = {
            let _guard = RestoreMode {
                path: mount_root.clone(),
                mode: original,
            };
            std::fs::set_permissions(&mount_root, std::fs::Permissions::from_mode(0o500))
                .expect("restrict mount root");
            cleanup_projection_state(Arc::clone(&cleanup_state)).await
        };
        assert!(!first, "first pass must fail closed on root removal");
        assert!(
            cleanup_projection_state(cleanup_state).await,
            "retry must succeed after idempotent revoke and restored root mode"
        );
        assert!(!mount_root.exists(), "projection root must be removed");
        revoke_lease_if_present(&kernel, &caller, true, branch_lease.mount_id)
            .await
            .unwrap();
        revoke_lease_if_present(&kernel, &caller, true, owner_lease.mount_id)
            .await
            .unwrap();
    }
}
