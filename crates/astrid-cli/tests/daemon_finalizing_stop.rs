//! Stop must serialize cleanup with the finalizer after PID/socket retirement.
#![cfg(unix)]

use astrid_core::dirs::AstridHome;
use astrid_storage::principal_state::RuntimeLifecycleGuard;
use std::io::{BufRead as _, BufReader};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

fn cli(home: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_astrid"));
    command
        .env("ASTRID_HOME", home)
        .env_remove("ASTRID_RUN_DIR")
        .env_remove("ASTRID_CONFIG")
        .env("ASTRID_DAEMON_LOG_TARGET", "stderr")
        .current_dir(home)
        .stdin(Stdio::null())
        .stdout(Stdio::null());
    command
}

struct OwnedStop(Child);
impl Drop for OwnedStop {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

enum Event {
    Waiting,
    Exited(String),
}

#[test]
fn stop_waits_for_finalizer_before_touching_runtime_files() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home");
    std::fs::create_dir(&home).unwrap();
    for command in ["start", "stop"] {
        let output = cli(&home)
            .arg(command)
            .stderr(Stdio::piped())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{command}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let lifecycle = RuntimeLifecycleGuard::acquire(&AstridHome::from_path(&home)).unwrap();
    let run = home.join("run");
    std::fs::create_dir(&run).unwrap();
    let marker = run.join("system.lock");
    std::fs::write(&marker, b"owned finalization control").unwrap();
    let mut stop = OwnedStop(
        cli(&home)
            .arg("--verbose")
            .arg("stop")
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let stderr = stop.0.stderr.take().unwrap();
    let (sender, receiver) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut output = String::new();
        for line in BufReader::new(stderr).lines() {
            let line = line.unwrap();
            if line.contains("waiting for runtime finalization") {
                let _ = sender.send(Event::Waiting);
            }
            output.push_str(&line);
            output.push('\n');
        }
        let _ = sender.send(Event::Exited(output.clone()));
        output
    });
    match receiver.recv_timeout(Duration::from_mins(1)).unwrap() {
        Event::Waiting => {},
        Event::Exited(output) => panic!(
            "stop exited while finalization still owned the home: {output}; marker exists: {}",
            marker.exists()
        ),
    }
    assert_eq!(
        std::fs::read(&marker).unwrap(),
        b"owned finalization control",
        "stop removed state protected by the finalizer"
    );
    assert!(stop.0.try_wait().unwrap().is_none());
    drop(lifecycle);
    let status = stop.0.wait().unwrap();
    let output = reader.join().unwrap();
    assert!(status.success(), "stop failed: {output}");
    let entries: Vec<_> = std::fs::read_dir(&home)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(entries, [std::ffi::OsString::from("astrid.volume")]);
}

#[test]
fn finalizer_timeout_preserves_runtime_control_files() {
    use std::os::unix::fs::PermissionsExt as _;

    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home");
    std::fs::create_dir(&home).unwrap();
    let owner = RuntimeLifecycleGuard::acquire(&AstridHome::from_path(&home)).unwrap();
    let run = home.join("run");
    std::fs::create_dir(&run).unwrap();
    let marker = run.join("system.lock");
    std::fs::write(&marker, b"preserve until finalization completes").unwrap();
    let config = root.path().join("client.toml");
    std::fs::write(&config, b"daemon_shutdown_secs = 1\n").unwrap();
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
    let output = cli(&home)
        .env("ASTRID_CLIENT_CONFIG_PATH", &config)
        .arg("stop")
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(
        stderr.contains("within the client shutdown budget"),
        "{stderr}"
    );
    assert_eq!(
        std::fs::read(&marker).unwrap(),
        b"preserve until finalization completes"
    );
    assert!(RuntimeLifecycleGuard::acquire(&AstridHome::from_path(&home)).is_err());
    drop(owner);
}

#[test]
fn unsafe_finalization_control_is_rejected_without_waiting() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home");
    std::fs::create_dir(&home).unwrap();
    let identity = AstridHome::from_path(&home);
    drop(RuntimeLifecycleGuard::acquire(&identity).unwrap());
    let lock = identity.lifecycle_lock_path().unwrap();
    std::fs::remove_file(&lock).unwrap();
    std::fs::create_dir(&lock).unwrap();
    let run = home.join("run");
    std::fs::create_dir(&run).unwrap();
    let marker = run.join("system.lock");
    std::fs::write(&marker, b"untouched").unwrap();
    let output = cli(&home)
        .arg("--verbose")
        .arg("stop")
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(
        stderr.contains("lifecycle lock is not a regular file"),
        "{stderr}"
    );
    assert!(
        !stderr.contains("waiting for runtime finalization"),
        "{stderr}"
    );
    assert_eq!(std::fs::read(&marker).unwrap(), b"untouched");
}
