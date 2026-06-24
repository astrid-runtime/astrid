use std::path::PathBuf;

use astrid_core::session_token::SessionToken;
use tokio::net::UnixListener;
use tracing::warn;

/// Path to the local Unix Domain Socket for the kernel.
#[must_use]
pub(crate) fn kernel_socket_path() -> PathBuf {
    use astrid_core::dirs::AstridHome;
    match AstridHome::resolve() {
        Ok(home) => home.socket_path(),
        Err(e) => {
            warn!(error = %e, "Failed to resolve ASTRID_HOME; falling back to /tmp/.astrid/run/system.sock");
            PathBuf::from("/tmp/.astrid/run/system.sock")
        },
    }
}

/// Maximum byte length for a Unix domain socket path.
/// macOS/FreeBSD/OpenBSD `sockaddr_un.sun_path` is 104 bytes; Linux is 108.
#[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd"))]
const MAX_SOCKET_PATH_LEN: usize = 104;
#[cfg(not(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd")))]
const MAX_SOCKET_PATH_LEN: usize = 108;

/// Binds a local Unix Domain Socket for the OS and acquires the singleton lock.
/// Returns the bound listener (for the WASM execution context) plus the lock
/// file, which the caller MUST keep alive for the process lifetime.
///
/// Takes the already-resolved [`AstridHome`](astrid_core::dirs::AstridHome) so
/// the path is resolved exactly once, by the caller. There is intentionally no
/// `/tmp` fallback: the caller resolves `ASTRID_HOME` strictly and a daemon
/// that can't resolve it refuses to boot, rather than binding a divergent
/// `/tmp` path and running side by side with another instance (split-brain).
///
/// # Errors
/// Returns an error if the socket cannot be bound, the path exceeds the
/// platform's `sun_path` limit, the singleton lock is already held by another
/// kernel instance, or another kernel is already listening on the socket.
pub(crate) fn bind_session_socket(
    home: &astrid_core::dirs::AstridHome,
) -> Result<(UnixListener, std::fs::File), std::io::Error> {
    let path = home.socket_path();

    // Create the run directory first — both the lockfile and the socket live
    // in it. Enforce 0o700: AstridHome::ensure() does this at boot, but if the
    // directory was just created here it would inherit the process umask
    // (commonly 0o755, making the socket listable by other users).
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            std::io::Error::other(format!(
                "Failed to create socket parent directory {}: {e}",
                parent.display()
            ))
        })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        }
    }

    // Singleton guard: hold an exclusive advisory lock on a lockfile next to
    // the socket for the daemon's lifetime. This closes the connect-probe ->
    // bind TOCTOU window in `prepare_socket_path` deterministically — a second
    // daemon fails to acquire the lock and exits before touching the socket.
    // The OS releases the lock when the process dies, so a crashed daemon
    // never wedges a restart. The caller MUST keep the returned file alive for
    // the process lifetime (dropping it releases the lock).
    let lock = acquire_singleton_lock(&path.with_file_name("system.lock"))?;

    prepare_socket_path(&path)?;

    // Also clean stale readiness file as defense-in-depth for daemon
    // crashes that bypassed graceful shutdown.
    remove_readiness_file();

    let listener = UnixListener::bind(&path)?;
    Ok((listener, lock))
}

/// Acquire an exclusive, non-blocking advisory lock on `lock_path`, returning
/// the open file handle. The lock is held for as long as the returned `File`
/// is alive — the caller stores it for the daemon's lifetime, and the OS
/// releases it on process exit (so a crash can't wedge a restart). The
/// lockfile itself is intentionally left in place between runs.
fn acquire_singleton_lock(lock_path: &std::path::Path) -> Result<std::fs::File, std::io::Error> {
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

/// Validate a socket path and handle stale/live socket detection.
///
/// Extracted from `bind_session_socket` for testability. Returns `Ok(())`
/// if the path is safe to bind (stale socket removed or no socket exists).
/// Returns `Err` if the path is too long or another kernel is listening.
fn prepare_socket_path(path: &std::path::Path) -> Result<(), std::io::Error> {
    let path_len = path.as_os_str().as_encoded_bytes().len();
    if path_len >= MAX_SOCKET_PATH_LEN {
        return Err(std::io::Error::other(format!(
            "Socket path is {path_len} bytes, exceeding the platform limit of {MAX_SOCKET_PATH_LEN} bytes: {}",
            path.display()
        )));
    }

    if path.is_symlink() {
        warn!(path = %path.display(), "Removing unexpected symlink at socket path");
        std::fs::remove_file(path).map_err(|e| {
            std::io::Error::other(format!(
                "Failed to remove symlink at socket path {}: {e}",
                path.display()
            ))
        })?;
    } else if path.exists() {
        match std::os::unix::net::UnixStream::connect(path) {
            Ok(_stream) => {
                return Err(std::io::Error::other(format!(
                    "Another kernel instance is already running on this socket: {}",
                    path.display()
                )));
            },
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                // No listener attached: stale socket, safe to remove.
                std::fs::remove_file(path).map_err(|e| {
                    std::io::Error::other(format!(
                        "Failed to remove stale socket {}: {e}",
                        path.display()
                    ))
                })?;
            },
            Err(e) => {
                // Other errors (EACCES, etc.) may indicate a live kernel
                // under a different user or transient issue. Don't delete.
                return Err(std::io::Error::other(format!(
                    "Failed to probe existing socket {}: {e}",
                    path.display()
                )));
            },
        }
    }

    Ok(())
}

/// Path to the daemon readiness sentinel file.
///
/// NOTE: This is intentionally duplicated in `astrid-cli/src/socket_client.rs`
/// because the CLI cannot depend on `astrid-kernel`. The canonical path
/// definition is `AstridHome::ready_path()` in `astrid-core`.
#[must_use]
pub fn readiness_path() -> PathBuf {
    use astrid_core::dirs::AstridHome;
    match AstridHome::resolve() {
        Ok(home) => home.ready_path(),
        Err(e) => {
            warn!(
                error = %e,
                "Failed to resolve ASTRID_HOME; falling back to /tmp/.astrid/run/system.ready"
            );
            PathBuf::from("/tmp/.astrid/run/system.ready")
        },
    }
}

/// Write the readiness sentinel file to signal that the daemon is fully
/// initialized and accepting connections.
///
/// This must be called **after** `load_all_capsules()` completes (which
/// includes `await_capsule_readiness()`). The CLI polls for this file
/// instead of the socket file to avoid connecting before the accept loop
/// is running.
///
/// # Errors
/// Returns an error if the file cannot be written. The caller should treat
/// this as a fatal boot failure - without the sentinel, the CLI will never
/// detect that the daemon is ready.
pub fn write_readiness_file() -> Result<(), std::io::Error> {
    use std::fs::OpenOptions;

    let path = readiness_path();

    // Ensure the parent directory exists (defense-in-depth for contexts
    // where bind_session_socket() has not run first).
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Create the sentinel file with owner-only permissions set atomically
    // via OpenOptions::mode() to avoid a TOCTOU window where the file exists
    // with default permissions before chmod.
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }

    opts.open(&path)?;
    Ok(())
}

/// Remove the readiness sentinel file (best-effort).
///
/// Called during shutdown and stale-file cleanup. Errors are silently
/// ignored - a missing file is not an error, and if removal fails the
/// CLI's pre-spawn cleanup will handle it on next boot.
pub fn remove_readiness_file() {
    let _ = std::fs::remove_file(readiness_path());
}

/// Path to the daemon PID file (`run/system.pid`).
///
/// NOTE: kept here alongside the other run-dir path helpers; the canonical
/// definition is `AstridHome::pid_path()` in `astrid-core`. Falls back to
/// the same `/tmp` location as the socket so a dev daemon that can't resolve
/// `ASTRID_HOME` still records its PID consistently with where the CLI looks.
#[must_use]
pub fn pid_path() -> PathBuf {
    use astrid_core::dirs::AstridHome;
    match AstridHome::resolve() {
        Ok(home) => home.pid_path(),
        Err(e) => {
            warn!(error = %e, "Failed to resolve ASTRID_HOME; falling back to /tmp/.astrid/run/system.pid");
            PathBuf::from("/tmp/.astrid/run/system.pid")
        },
    }
}

/// Write the current process PID to the daemon PID file, atomically.
///
/// Called at boot AFTER the singleton lock is acquired, so the recorded PID
/// always belongs to the process that holds the state-db lock. The CLI reads
/// this in `astrid stop`/`astrid restart` to signal a wedged daemon that is
/// no longer reachable over the socket but is still holding the lock.
///
/// Written via temp-file + rename so a reader never observes a half-written
/// PID, and with 0o600 permissions to match the other run-dir artifacts.
///
/// # Errors
/// Returns an error if the run directory cannot be created or the file cannot
/// be written/renamed. The caller treats this as best-effort (a missing PID
/// file only degrades `stop`/`restart` to socket-only cleanup), so it logs
/// rather than aborting boot.
pub fn write_pid_file() -> Result<(), std::io::Error> {
    use std::io::Write as _;

    let path = pid_path();

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Write to a uniquely-named temp file in the same directory, then rename
    // over the target so the swap is atomic on the same filesystem.
    let tmp = path.with_extension(format!("pid.tmp.{}", std::process::id()));

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
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

    let write_result = (|| -> std::io::Result<()> {
        let mut file = opts.open(&tmp)?;
        match &exe_line {
            Some(exe) => write!(file, "{}\n{}", std::process::id(), exe)?,
            None => write!(file, "{}", std::process::id())?,
        }
        file.flush()?;
        file.sync_all()?;
        Ok(())
    })();
    if let Err(e) = write_result {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }

    if let Err(e) = std::fs::rename(&tmp, &path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

/// Remove the daemon PID file (best-effort).
///
/// Called during graceful shutdown. Errors are silently ignored — a missing
/// file is not an error, and a stale PID file is handled by the CLI's
/// liveness check (a PID that is dead is treated as already-gone) plus the
/// pre-spawn cleanup on next boot.
pub fn remove_pid_file() {
    let _ = std::fs::remove_file(pid_path());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_too_long_is_rejected() {
        // Build a path that exceeds the platform limit.
        let long_name = "a".repeat(MAX_SOCKET_PATH_LEN + 10);
        let path = PathBuf::from(format!("/tmp/{long_name}.sock"));
        let err = prepare_socket_path(&path).unwrap_err();
        assert!(
            err.to_string().contains("exceeding the platform limit"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn stale_socket_is_removed() {
        // Bind a listener, drop it (making the socket stale), then verify
        // prepare_socket_path removes it.
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("test.sock");

        // Create and immediately drop a listener to leave a stale socket file.
        let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        drop(listener);

        assert!(sock.exists(), "socket file should exist after bind");
        prepare_socket_path(&sock).unwrap();
        assert!(!sock.exists(), "stale socket should have been removed");
    }

    #[test]
    fn live_socket_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("test.sock");

        // Keep the listener alive so connect succeeds.
        let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();

        let err = prepare_socket_path(&sock).unwrap_err();
        assert!(
            err.to_string().contains("already running"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn symlink_is_removed() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::write(&target, "not a socket").unwrap();

        let sock = dir.path().join("test.sock");
        std::os::unix::fs::symlink(&target, &sock).unwrap();
        assert!(sock.is_symlink());

        prepare_socket_path(&sock).unwrap();
        assert!(!sock.exists(), "symlink should have been removed");
        assert!(target.exists(), "target should be untouched");
    }

    #[test]
    fn nonexistent_path_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("does_not_exist.sock");
        prepare_socket_path(&sock).unwrap();
    }

    #[test]
    fn singleton_lock_is_exclusive() {
        let dir = tempfile::tempdir().unwrap();
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
    fn singleton_lock_is_released_on_drop() {
        let dir = tempfile::tempdir().unwrap();
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
