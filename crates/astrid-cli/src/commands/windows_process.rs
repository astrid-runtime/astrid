//! Windows handle-inheritance hygiene for detached child-process spawns.
//!
//! Stable Rust 1.95 creates child processes with broad handle inheritance
//! enabled. Replacing a child's standard streams does not stop other
//! inheritable copies of the parent's standard handles from entering the
//! child. Redirecting `astrid start` or `astrid update` through a pipe could
//! therefore let a long-lived child keep the pipe writer alive after the CLI
//! exited.

use std::os::windows::io::AsRawHandle as _;

use windows_sys::Win32::Foundation::{
    HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, SetHandleInformation,
};

/// Prevent a detached child from receiving ambient copies of this process's
/// standard handles.
///
/// The change is deliberately permanent for this process. Temporarily
/// clearing and restoring these process-wide flags would race concurrent
/// process creation. Explicit future `Stdio::inherit()` calls remain valid:
/// Rust duplicates the requested standard handle into a fresh inheritable
/// handle for that specific child.
pub(super) fn prevent_ambient_standard_handle_inheritance() -> std::io::Result<()> {
    let handles: [HANDLE; 3] = [
        std::io::stdin().as_raw_handle().cast(),
        std::io::stdout().as_raw_handle().cast(),
        std::io::stderr().as_raw_handle().cast(),
    ];
    for handle in handles {
        clear_inherit_flag(handle)?;
    }
    Ok(())
}

fn clear_inherit_flag(handle: HANDLE) -> std::io::Result<()> {
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Ok(());
    }
    // SAFETY: `handle` is borrowed from one of this process's standard stream
    // objects and remains valid for the call. The mask changes only its
    // inheritance bit; it neither closes the handle nor changes I/O access.
    if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) } == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant, SystemTime};

    use super::super::daemon_process::configure_background;

    const HELPER_TEST: &str =
        "commands::windows_process::tests::redirected_background_spawn_helper";
    const LEAF_TEST: &str = "commands::windows_process::tests::detached_leaf_stays_running";
    const READY_ENV: &str = "ASTRID_TEST_DETACHED_LEAF_READY";
    const RELEASE_ENV: &str = "ASTRID_TEST_DETACHED_LEAF_RELEASE";
    const DONE_ENV: &str = "ASTRID_TEST_DETACHED_LEAF_DONE";

    fn ignored_test_command(name: &str) -> Command {
        let mut command = Command::new(std::env::current_exe().expect("current test executable"));
        command.args(["--ignored", "--exact", name, "--nocapture"]);
        command
    }

    fn marker_directory() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("system clock must follow the Unix epoch")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "astrid-daemon-handle-inheritance-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).expect("create unique marker directory");
        directory
    }

    fn wait_for_marker(path: &Path, budget: Duration) -> bool {
        let deadline = Instant::now()
            .checked_add(budget)
            .expect("marker wait deadline");
        while Instant::now() < deadline {
            if path.exists() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        path.exists()
    }

    fn describe_output(output: &std::process::Output) -> String {
        format!(
            "status={}, stdout={:?}, stderr={:?}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    }

    #[test]
    fn detached_child_does_not_retain_parent_redirect_pipes() {
        let directory = marker_directory();
        let ready = directory.join("ready");
        let release = directory.join("release");
        let done = directory.join("done");

        let mut helper = ignored_test_command(HELPER_TEST);
        helper
            .env(READY_ENV, &ready)
            .env(RELEASE_ENV, &release)
            .env(DONE_ENV, &done)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let output_thread = std::thread::spawn(move || {
            sender
                .send(helper.output())
                .expect("parent must receive helper output");
        });

        let leaf_ready = wait_for_marker(&ready, Duration::from_secs(10));
        let output_before_release = receiver.recv_timeout(Duration::from_secs(5));
        std::fs::write(&release, b"release\n").expect("release detached leaf");
        let leaf_finished = wait_for_marker(&done, Duration::from_secs(10));

        let inherited_handle_timeout = output_before_release.is_err();
        let output = output_before_release.unwrap_or_else(|_| {
            receiver
                .recv_timeout(Duration::from_secs(10))
                .expect("helper streams must close after releasing detached leaf")
        });
        let output = output.expect("redirected helper must run");
        output_thread.join().expect("helper output thread");
        let _ = std::fs::remove_file(&ready);
        let _ = std::fs::remove_file(&release);
        let _ = std::fs::remove_file(&done);
        let _ = std::fs::remove_dir(&directory);

        assert!(
            !inherited_handle_timeout,
            "redirected streams remained open while detached leaf was alive; {}",
            describe_output(&output)
        );
        assert!(leaf_ready, "detached leaf never reported readiness");
        assert!(
            leaf_finished,
            "detached leaf did not exit after its explicit release"
        );
        assert!(
            output.status.success(),
            "redirected helper failed: {}",
            describe_output(&output)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("helper stdout closed"),
            "helper stdout marker missing"
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("helper stderr closed"),
            "helper stderr marker missing"
        );
    }

    #[test]
    #[ignore = "spawned by detached_child_does_not_retain_parent_redirect_pipes"]
    fn redirected_background_spawn_helper() {
        let mut command = ignored_test_command(LEAF_TEST);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        configure_background(&mut command).expect("background policy must apply");

        let mut child = command.spawn().expect("detached leaf must spawn");
        let ready = PathBuf::from(std::env::var_os(READY_ENV).expect("ready marker path"));
        assert!(
            wait_for_marker(&ready, Duration::from_secs(10)),
            "detached leaf must report readiness"
        );
        assert!(
            child.try_wait().expect("detached leaf status").is_none(),
            "detached leaf must still be running when its parent exits"
        );
        println!("helper stdout closed");
        eprintln!("helper stderr closed");
    }

    #[test]
    #[ignore = "spawned by redirected_background_spawn_helper"]
    fn detached_leaf_stays_running() {
        let ready = PathBuf::from(std::env::var_os(READY_ENV).expect("ready marker path"));
        let release = PathBuf::from(std::env::var_os(RELEASE_ENV).expect("release marker path"));
        let done = PathBuf::from(std::env::var_os(DONE_ENV).expect("done marker path"));
        std::fs::write(&ready, b"ready\n").expect("publish detached leaf readiness");
        let released = wait_for_marker(&release, Duration::from_secs(30));
        std::fs::write(&done, b"done\n").expect("publish detached leaf completion");
        assert!(released, "detached leaf was never released");
    }
}
