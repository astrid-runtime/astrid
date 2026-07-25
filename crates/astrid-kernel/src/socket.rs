use std::path::PathBuf;

use astrid_core::local_transport::{self, LocalListener};
use astrid_core::session_token::SessionToken;
use tracing::warn;

/// Create the daemon run directory (the parent of the socket and lockfile)
/// with `0o700` perms.
///
/// `AstridHome::ensure()` does this at boot, but if the directory is created
/// here it would otherwise inherit the process umask (commonly `0o755`, making
/// the socket/lockfile listable by other users), so the mode is set
/// explicitly. Idempotent — safe to call more than once per boot.
fn ensure_run_dir(socket_path: &std::path::Path) -> Result<(), std::io::Error> {
    if let Some(parent) = socket_path.parent() {
        astrid_core::platform_fs::ensure_private_directory(parent).map_err(|e| {
            std::io::Error::other(format!(
                "Failed to create private socket parent directory {}: {e}",
                parent.display()
            ))
        })?;
    }
    Ok(())
}

/// Acquire the daemon singleton advisory lock as the FIRST fallible boot step,
/// before ANY shared state store (KV, audit) is opened.
///
/// Returns the lock file, which the caller MUST keep alive for the process
/// lifetime (dropping it releases the lock). Acquiring the lock ahead of the
/// store opens means a boot-race loser fails HERE with the actionable "already
/// running (singleton lock held)" error and never opens — or even touches —
/// the shared surrealkv stores, instead of dying on a raw
/// `Database ... LOCK is already locked` from the KV/audit layer after having
/// opened them. Split from [`bind_listener`] precisely so the lock can be taken
/// before the stores; the listener bind runs later and does NOT re-acquire it.
///
/// Takes the already-resolved [`AstridHome`](astrid_core::dirs::AstridHome) so
/// the path is resolved exactly once, by the caller. There is intentionally no
/// `/tmp` fallback: the caller resolves `ASTRID_HOME` strictly and a daemon
/// that can't resolve it refuses to boot, rather than diverging to a `/tmp`
/// path and running side by side with another instance (split-brain).
///
/// # Errors
/// Returns an error if the run directory cannot be created or the singleton
/// lock is already held by another kernel instance.
pub(crate) fn acquire_boot_singleton_lock(
    home: &astrid_core::dirs::AstridHome,
) -> Result<std::fs::File, std::io::Error> {
    astrid_core::platform_fs::try_acquire_daemon_singleton(home)?.ok_or_else(|| {
        std::io::Error::other(format!(
            "Another kernel instance is already running (singleton lock held): {}",
            home.run_dir().join("system.lock").display()
        ))
    })
}

/// Bind the daemon's local listener, assuming the singleton lock is ALREADY held
/// (via [`acquire_boot_singleton_lock`]).
///
/// Returns the bound listener for the WASM execution context. This step only
/// prepares the platform endpoint and binds it. It does NOT touch the singleton
/// lock, which the caller acquired first so it precedes KV/audit store opens.
///
/// # Errors
/// Returns an error if the endpoint cannot be bound or another kernel is
/// already listening on it.
pub(crate) fn bind_listener(
    home: &astrid_core::dirs::AstridHome,
) -> Result<LocalListener, std::io::Error> {
    let path = home.socket_path();

    // Defensive: the run dir already exists (the lock step created it), but a
    // second idempotent create keeps this callable independently.
    ensure_run_dir(&path)?;

    let listener = local_transport::bind(&path)?;

    // Also clean stale readiness file as defense-in-depth for daemon
    // crashes that bypassed graceful shutdown. Do this only after endpoint
    // preparation succeeds so a rejected live endpoint keeps its sentinel.
    remove_readiness_file();

    Ok(listener)
}

/// Acquire an exclusive, non-blocking advisory lock on `lock_path`, returning
/// the open file handle. The lock is held for as long as the returned `File`
/// is alive — the caller stores it for the daemon's lifetime, and the OS
/// releases it on process exit (so a crash can't wedge a restart). The
/// lockfile itself is intentionally left in place between runs.
#[cfg(test)]
pub(crate) fn acquire_singleton_lock(
    lock_path: &std::path::Path,
) -> Result<std::fs::File, std::io::Error> {
    use std::fs::OpenOptions;

    let mut opts = OpenOptions::new();
    opts.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let file = opts.open(lock_path).map_err(|e| {
        std::io::Error::other(format!(
            "Failed to open singleton lockfile {}: {e}",
            lock_path.display()
        ))
    })?;

    file.try_lock().map_err(|e| match e {
        std::fs::TryLockError::WouldBlock => std::io::Error::other(format!(
            "Another kernel instance is already running (singleton lock held): {}",
            lock_path.display()
        )),
        std::fs::TryLockError::Error(err) => std::io::Error::other(format!(
            "Failed to acquire singleton lock {}: {err}",
            lock_path.display()
        )),
    })?;

    Ok(file)
}

/// Generate a random session token and write it to the token file.
///
/// Returns both the token and the path it was written to. The caller should
/// store the path so that the exact same path is used for cleanup at shutdown
/// (avoids fallback mismatch if the env changes between boot and shutdown).
///
/// The token is written with 0o600 permissions so only the owning user
/// can read it. The CLI reads this token at connect time and sends it
/// as part of the handshake.
///
/// # Errors
/// Returns an error if `ASTRID_HOME` cannot be resolved or the token file
/// cannot be written. Unlike socket/CLI paths, there is no `/tmp` fallback
/// because writing a secret token under a world-listable directory would
/// undermine the authentication it provides.
pub(crate) fn generate_session_token() -> Result<(SessionToken, PathBuf), std::io::Error> {
    use astrid_core::dirs::AstridHome;

    let token = SessionToken::generate();

    let home = AstridHome::resolve().map_err(|e| {
        std::io::Error::other(format!(
            "Cannot generate session token: failed to resolve ASTRID_HOME: {e}"
        ))
    })?;

    let path = home.token_path();
    token.write_to_file(&path)?;
    Ok((token, path))
}

/// Path to the daemon readiness sentinel file.
///
/// NOTE: This is intentionally duplicated in `astrid-cli/src/socket_client.rs`
/// because the CLI cannot depend on `astrid-kernel`. The canonical path
/// definition is `AstridHome::ready_path()` in `astrid-core`.
///
/// # Panics
///
/// On Windows, panics if the private per-user Astrid home cannot be resolved.
/// Windows never falls back to a shared or drive-relative `/tmp` path.
#[must_use]
pub fn readiness_path() -> PathBuf {
    match platform_readiness_path(try_readiness_path()) {
        Ok(path) => path,
        Err(e) => {
            panic!("Failed to resolve the private Windows ASTRID_HOME: {e}");
        },
    }
}

/// Resolve the daemon readiness sentinel without a platform fallback.
///
/// # Errors
///
/// Returns an error when the private per-user Astrid home cannot be resolved.
pub fn try_readiness_path() -> std::io::Result<PathBuf> {
    use astrid_core::dirs::AstridHome;
    AstridHome::resolve().map(|home| home.ready_path())
}

fn platform_readiness_path(resolved: std::io::Result<PathBuf>) -> std::io::Result<PathBuf> {
    #[cfg(windows)]
    {
        resolved
    }

    #[cfg(not(windows))]
    {
        Ok(resolved.unwrap_or_else(|error| {
            warn!(
                %error,
                "Failed to resolve ASTRID_HOME; falling back to /tmp/.astrid/run/system.ready"
            );
            PathBuf::from("/tmp/.astrid/run/system.ready")
        }))
    }
}

/// Write the readiness sentinel file to signal that the daemon is fully
/// initialized and accepting connections.
///
/// This must be called **after** the boot-critical default capsule view has
/// loaded and completed readiness checks. The CLI polls for this file instead
/// of the socket file to avoid connecting before the accept loop is running.
///
/// # Errors
/// Returns an error if the file cannot be written. The caller should treat
/// this as a fatal boot failure - without the sentinel, the CLI will never
/// detect that the daemon is ready.
pub fn write_readiness_file() -> Result<(), std::io::Error> {
    let workspace_root = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    write_readiness_file_for_workspace(
        &workspace_root,
        &astrid_core::dirs::WorkspaceLayout::default(),
    )
}

/// Write readiness metadata for the selected project workspace.
///
/// # Errors
/// Returns an error if the sentinel cannot be written.
pub fn write_readiness_file_for_workspace(
    workspace_root: &std::path::Path,
    workspace_layout: &astrid_core::dirs::WorkspaceLayout,
) -> Result<(), std::io::Error> {
    let path = platform_readiness_path(try_readiness_path())?;
    let fingerprint = astrid_core::dirs::checked_workspace_selection_fingerprint(
        workspace_root,
        workspace_layout,
    )?;
    publish_readiness_metadata(&path, &format!("v1:{fingerprint}\n"))
}

fn publish_readiness_metadata(path: &std::path::Path, metadata: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        astrid_core::platform_fs::ensure_private_directory(parent)?;
    }

    #[cfg(windows)]
    {
        astrid_core::platform_fs::atomic_write_private_file(path, metadata.as_bytes())
    }

    #[cfg(not(windows))]
    {
        use std::io::Write as _;

        let tmp = path.with_extension(format!("ready.tmp.{}", std::process::id()));
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }

        let write_result = (|| -> std::io::Result<()> {
            let mut file = opts.open(&tmp)?;
            file.write_all(metadata.as_bytes())?;
            file.flush()?;
            file.sync_all()
        })();
        if let Err(error) = write_result {
            let _ = std::fs::remove_file(&tmp);
            return Err(error);
        }
        if let Err(error) = std::fs::rename(&tmp, path) {
            let _ = std::fs::remove_file(&tmp);
            return Err(error);
        }
        Ok(())
    }
}

/// Remove the readiness sentinel file (best-effort).
///
/// Called during shutdown and stale-file cleanup. Errors are silently
/// ignored - a missing file is not an error, and if removal fails the
/// CLI's pre-spawn cleanup will handle it on next boot.
pub fn remove_readiness_file() {
    match platform_readiness_path(try_readiness_path()) {
        Ok(path) => {
            let _ = std::fs::remove_file(path);
        },
        Err(error) => warn!(%error, "Failed to resolve readiness path during cleanup"),
    }
}

/// Path to the daemon PID file (`run/system.pid`).
///
/// NOTE: kept here alongside the other run-dir path helpers; the canonical
/// definition is `AstridHome::pid_path()` in `astrid-core`.
///
/// # Panics
///
/// On Windows, panics if the private per-user Astrid home cannot be resolved.
/// Windows never falls back to a shared or drive-relative `/tmp` path.
#[must_use]
pub fn pid_path() -> PathBuf {
    match try_pid_path() {
        Ok(path) => path,
        Err(e) => {
            #[cfg(windows)]
            panic!("Failed to resolve the private Windows ASTRID_HOME: {e}");
            #[cfg(not(windows))]
            {
                warn!(error = %e, "Failed to resolve ASTRID_HOME; falling back to /tmp/.astrid/run/system.pid");
                PathBuf::from("/tmp/.astrid/run/system.pid")
            }
        },
    }
}

/// Resolve the daemon PID file without a platform fallback.
///
/// # Errors
///
/// Returns an error when the private per-user Astrid home cannot be resolved.
pub fn try_pid_path() -> std::io::Result<PathBuf> {
    use astrid_core::dirs::AstridHome;
    AstridHome::resolve().map(|home| home.pid_path())
}

/// Write the current process identity to the daemon PID file, atomically.
///
/// Called at boot while the singleton lock is held, so the recorded identity
/// always belongs to the process that owns the daemon namespace. The CLI reads
/// this in `astrid stop`/`astrid restart` to signal a wedged daemon that is no
/// longer reachable over the socket but is still holding the lock.
///
/// Written via temp-file + rename so a reader never observes a half-written
/// PID, and with 0o600 permissions to match the other run-dir artifacts.
///
/// # Errors
/// Returns an error if the run directory cannot be created or the file cannot
/// be written/renamed. Unix treats this as best-effort. Windows treats it as
/// boot-critical because safe termination requires its process creation token.
pub fn write_pid_file() -> Result<(), std::io::Error> {
    let home = astrid_core::dirs::AstridHome::resolve()?;
    write_pid_file_for_home(&home)
}

/// Write daemon identity beneath the exact home captured by the kernel at
/// boot, without re-resolving process-global environment state.
///
/// # Errors
///
/// Returns an error when the run directory or private PID file cannot be
/// created, secured, flushed, or atomically published.
pub fn write_pid_file_for_home(home: &astrid_core::dirs::AstridHome) -> Result<(), std::io::Error> {
    let path = home.pid_path();

    if let Some(parent) = path.parent() {
        astrid_core::platform_fs::ensure_private_directory(parent)?;
    }

    // Resolve our own executable, canonicalized to defeat the launch symlink
    // (`~/.astrid/bin/astrid-daemon` → the real binary). The CLI compares this
    // against the live process's exe before signalling, so a recycled PID owned
    // by an unrelated process is never killed. Best-effort: if we can't resolve
    // it, write the PID alone and the CLI fails secure (treats it as unverifiable).
    let exe_line = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .ok()
        .and_then(|p| p.to_str().map(str::to_owned));

    #[cfg(not(windows))]
    let contents = exe_line.map_or_else(
        || std::process::id().to_string(),
        |exe| format!("{}\n{exe}", std::process::id()),
    );

    #[cfg(windows)]
    {
        let creation_time = current_process_creation_time()?;
        let contents = format!(
            "{}\n{}\ncreation_time={creation_time}",
            std::process::id(),
            exe_line.unwrap_or_default()
        );
        astrid_core::platform_fs::atomic_write_private_file(&path, contents.as_bytes())
    }

    #[cfg(not(windows))]
    {
        use std::io::Write as _;

        let tmp = path.with_extension(format!("pid.tmp.{}", std::process::id()));
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }

        let write_result = (|| -> std::io::Result<()> {
            let mut file = opts.open(&tmp)?;
            file.write_all(contents.as_bytes())?;
            file.flush()?;
            file.sync_all()
        })();
        if let Err(error) = write_result {
            let _ = std::fs::remove_file(&tmp);
            return Err(error);
        }
        if let Err(error) = std::fs::rename(&tmp, &path) {
            let _ = std::fs::remove_file(&tmp);
            return Err(error);
        }
        Ok(())
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn current_process_creation_time() -> std::io::Result<u64> {
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessTimes};

    let mut creation = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut exit = creation;
    let mut kernel = creation;
    let mut user = creation;
    // SAFETY: `GetCurrentProcess` returns a valid pseudo-handle for this
    // process. All output pointers refer to live writable `FILETIME` values.
    let ok = unsafe {
        GetProcessTimes(
            GetCurrentProcess(),
            &raw mut creation,
            &raw mut exit,
            &raw mut kernel,
            &raw mut user,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let ticks = (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime);
    if ticks == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Windows returned an empty process creation identity",
        ));
    }
    Ok(ticks)
}

/// Remove the daemon PID file (best-effort).
///
/// Called during graceful shutdown. Errors are silently ignored — a missing
/// file is not an error, and a stale PID file is handled by the CLI's
/// liveness check (a PID that is dead is treated as already-gone) plus the
/// pre-spawn cleanup on next boot.
pub fn remove_pid_file() {
    match try_pid_path() {
        Ok(path) => {
            let _ = std::fs::remove_file(path);
        },
        Err(error) => warn!(%error, "Failed to resolve PID path during cleanup"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct PrivateTempDir {
        path: std::path::PathBuf,
        #[cfg(not(windows))]
        _temporary: tempfile::TempDir,
    }

    impl PrivateTempDir {
        fn path(&self) -> &std::path::Path {
            &self.path
        }
    }

    #[cfg(windows)]
    impl Drop for PrivateTempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn private_tempdir() -> PrivateTempDir {
        #[cfg(windows)]
        {
            let runtime_root = astrid_core::platform_fs::default_astrid_home_root()
                .expect("resolve Windows LocalAppData");
            let local_app_data = runtime_root
                .parent()
                .and_then(std::path::Path::parent)
                .expect("Astrid runtime root is below Windows LocalAppData");
            let path = local_app_data.join(format!("AstridTest-{}", uuid::Uuid::new_v4().simple()));
            astrid_core::platform_fs::ensure_private_directory(&path)
                .expect("create a private Windows test directory");
            PrivateTempDir { path }
        }

        #[cfg(not(windows))]
        {
            let temporary = tempfile::tempdir().expect("create test directory");
            PrivateTempDir {
                path: temporary.path().to_path_buf(),
                _temporary: temporary,
            }
        }
    }

    fn assert_only_readiness_artifacts(directory: &std::path::Path) {
        let mut actual = std::fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        actual.sort();

        let mut expected = vec![std::ffi::OsString::from("system.ready")];
        #[cfg(windows)]
        expected.push(std::ffi::OsString::from(".astrid-private-write.lock"));
        expected.sort();

        assert_eq!(actual, expected);
    }

    #[test]
    fn readiness_publication_preserves_the_platform_resolution_policy() {
        let unresolved = Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no private home",
        ));
        let result = platform_readiness_path(unresolved);

        #[cfg(windows)]
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::NotFound);
        #[cfg(not(windows))]
        assert_eq!(
            result.unwrap(),
            std::path::PathBuf::from("/tmp/.astrid/run/system.ready")
        );
    }

    #[test]
    fn readiness_metadata_is_published_atomically() {
        let dir = private_tempdir();
        let run_dir = dir.path().join("run");
        let path = run_dir.join("system.ready");

        publish_readiness_metadata(&path, "v1:selected\n").unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), "v1:selected\n");
        assert_only_readiness_artifacts(&run_dir);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&run_dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700);
        }
    }

    #[test]
    fn readiness_metadata_replaces_a_crashed_daemons_stale_file() {
        let dir = private_tempdir();
        let path = dir.path().join("system.ready");
        publish_readiness_metadata(&path, "v1:stale\n").unwrap();

        publish_readiness_metadata(&path, "v1:current\n").unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), "v1:current\n");
        assert_only_readiness_artifacts(dir.path());
    }

    #[test]
    fn pid_record_is_published_under_the_captured_home() {
        let dir = private_tempdir();
        let home = astrid_core::dirs::AstridHome::from_path(dir.path());

        write_pid_file_for_home(&home).expect("publish daemon identity");

        let contents = astrid_core::platform_fs::read_private_file_to_string(&home.pid_path())
            .expect("read protected daemon identity");
        let mut lines = contents.lines();
        assert_eq!(
            lines.next().and_then(|line| line.parse::<u32>().ok()),
            Some(std::process::id())
        );
        let executable = lines.next().unwrap_or_default();
        assert!(
            executable.is_empty() || std::path::Path::new(executable).is_absolute(),
            "recorded executable must be empty or absolute"
        );
        #[cfg(windows)]
        {
            let creation_time = lines
                .next()
                .and_then(|line| line.strip_prefix("creation_time="))
                .and_then(|ticks| ticks.parse::<u64>().ok());
            assert!(
                creation_time.is_some_and(|ticks| ticks != 0),
                "Windows identity must include a non-zero creation token"
            );
        }
        assert!(lines.next().is_none(), "identity record has extra fields");
    }

    #[test]
    fn singleton_lock_is_exclusive() {
        let dir = private_tempdir();
        let lock = dir.path().join("system.lock");

        // First acquisition holds the lock for the duration of `_first`.
        let _first = acquire_singleton_lock(&lock).expect("first acquisition succeeds");

        // A second acquisition while the first is held must fail — this is the
        // "another kernel is already running" guard.
        let err = acquire_singleton_lock(&lock).unwrap_err();
        assert!(
            err.to_string().contains("already running"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn boot_singleton_lock_precedes_and_blocks_a_second_boot() {
        // Regression for the boot-order fix: the singleton lock is acquired via
        // `acquire_boot_singleton_lock` as a standalone FIRST boot step (before
        // any KV/audit store opens). Acquiring it must create the run dir and,
        // while held, block a second boot with the actionable "already running"
        // error — the loser never reaches (or touches) the shared stores.
        let dir = private_tempdir();
        let home = astrid_core::dirs::AstridHome::from_path(dir.path());

        let first = acquire_boot_singleton_lock(&home).expect("first boot acquires the lock");
        // The run directory (parent of the socket/lockfile) now exists.
        assert!(
            home.socket_path()
                .parent()
                .is_some_and(std::path::Path::is_dir),
            "run dir must be created by the boot lock step"
        );

        // A racing second boot fails at the lock — before opening any store.
        let err = acquire_boot_singleton_lock(&home).expect_err("second boot must lose the race");
        assert!(
            err.to_string().contains("already running"),
            "loser must report 'already running (singleton lock held)', got: {err}"
        );

        // Releasing the lock lets a fresh boot acquire it (no wedged restart).
        drop(first);
        let _second = acquire_boot_singleton_lock(&home)
            .expect("lock is re-acquirable after the holder exits");
    }

    #[test]
    fn singleton_lock_is_released_on_drop() {
        let dir = private_tempdir();
        let lock = dir.path().join("system.lock");

        // Acquire and drop — mirrors a daemon exiting and releasing the lock.
        {
            let _first = acquire_singleton_lock(&lock).expect("first acquisition succeeds");
        }

        // A fresh daemon can now acquire the same lock (no wedged restart).
        let _second =
            acquire_singleton_lock(&lock).expect("lock should be re-acquirable after release");
    }
}
