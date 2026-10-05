use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn owned_principal_discovery_does_not_wait_for_a_stopped_daemon() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home");
    std::fs::create_dir(&home).unwrap();
    assert_discovery_refuses_without_starting(&home, root.path());
    assert!(!home.join("run/system.pid").exists());
}

#[test]
fn unrelated_live_pid_does_not_justify_a_readiness_wait() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home");
    std::fs::create_dir_all(home.join("run")).unwrap();
    let record = format!(
        "{}\n/nonexistent/astrid-daemon\nstale-boot\n",
        std::process::id()
    );
    let pid_path = home.join("run/system.pid");
    std::fs::write(&pid_path, &record).unwrap();
    assert_discovery_refuses_without_starting(&home, root.path());
    assert_eq!(std::fs::read_to_string(pid_path).unwrap(), record);
}

fn assert_discovery_refuses_without_starting(home: &std::path::Path, workspace: &std::path::Path) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_astrid"))
        .current_dir(workspace)
        .env("ASTRID_HOME", home)
        .env_remove("DYLD_FALLBACK_LIBRARY_PATH")
        .env_remove("ASTRID_RUN_DIR")
        .env_remove("ASTRID_PRINCIPAL")
        .env_remove("ASTRID_CLIENT_CONFIG")
        .args([
            "--principal",
            "default",
            "agent",
            "list",
            "--mine",
            "--format",
            "json",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Includes OS executable loading: on macOS a Cargo-launched child was
    // sampled inside dyld before entering main, then completed in 3.92s.
    // This is not an application-latency benchmark. The uncorrected command
    // waits for the 600s readiness budget; this bound catches that regression.
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(30))
        .expect("fixture deadline fits the monotonic clock");
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let output = child.wait_with_output().unwrap();
            panic!(
                "discovery waited for a daemon that is not running: {}: {}",
                env!("CARGO_BIN_EXE_astrid"),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("daemon is not running"), "{error}");
    assert!(error.contains("astrid start"), "{error}");
    assert!(!home.join("run/system.ready").exists());
}
