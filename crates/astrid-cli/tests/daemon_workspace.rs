//! One daemon root must remain usable from independent client projects.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

struct Runtime {
    fixture: tempfile::TempDir,
    home: PathBuf,
    workspace: PathBuf,
    run: PathBuf,
}

impl Runtime {
    fn new() -> Self {
        let fixture = tempfile::tempdir().expect("owned fixture");
        let home = fixture.path().join("home");
        let workspace = fixture.path().join("daemon-workspace");
        let run = fixture.path().join("run");
        std::fs::create_dir(&workspace).expect("daemon workspace");
        Self {
            fixture,
            home,
            workspace,
            run,
        }
    }

    fn command(&self, cwd: &Path, selected: bool, args: &[&str]) -> Output {
        // A first boot inherits stderr. A pipe would remain open in the
        // detached daemon and make `output()` wait for daemon retirement.
        let stderr = tempfile::NamedTempFile::new_in(self.fixture.path()).expect("command log");
        let mut command = Command::new(env!("CARGO_BIN_EXE_astrid"));
        command
            .current_dir(cwd)
            .env("ASTRID_HOME", &self.home)
            .env("ASTRID_RUN_DIR", &self.run)
            .env_remove("ASTRID_CONFIG")
            .env_remove("ASTRID_PRINCIPAL")
            .env_remove("ASTRID_WORKSPACE_STATE_DIR")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(stderr.reopen().expect("command log handle"));
        if selected {
            command.arg("--daemon-workspace").arg(&self.workspace);
        }
        let mut child = command.args(args).spawn().expect("run owned CLI");
        // A regression must not consume the full production readiness budget.
        // This bounds a no-capsule fixture, not supported startup performance.
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(45))
            .expect("fixture deadline");
        while child.try_wait().expect("command status").is_none() {
            if Instant::now() >= deadline {
                child.kill().expect("stop timed-out fixture command");
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let mut output = child.wait_with_output().expect("command output");
        output.stderr = std::fs::read(stderr.path()).expect("command diagnostics");
        output
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        // Clean only this fixture's process, including after a failed assertion.
        let output = self.command(&self.workspace, true, &["stop"]);
        if !output.status.success() {
            eprintln!(
                "owned cleanup failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}

#[test]
fn explicit_daemon_root_survives_warm_attach_from_another_project() {
    let runtime = Runtime::new();
    let first = runtime.fixture.path().join("first-project");
    let second = runtime.fixture.path().join("second-project");
    for project in [&first, &second] {
        std::fs::create_dir(project).expect("client project");
    }
    let start = runtime.command(&first, true, &["start"]);
    assert!(
        start.status.success(),
        "start: {}",
        String::from_utf8_lossy(&start.stderr)
    );
    let identity = std::fs::read(runtime.run.join("system.ready")).expect("daemon identity");

    // `start` verifies the existing daemon's workspace rather than just listing
    // processes. It must not replace or restart the first daemon.
    let attach = runtime.command(&second, true, &["start"]);
    assert!(
        attach.status.success(),
        "warm attach: {}",
        String::from_utf8_lossy(&attach.stderr)
    );
    assert_eq!(
        std::fs::read(runtime.run.join("system.ready")).unwrap(),
        identity
    );

    let wrong = runtime.command(&second, false, &["start"]);
    assert!(!wrong.status.success());
    assert!(String::from_utf8_lossy(&wrong.stderr).contains("another project or workspace layout"));
    assert_eq!(
        std::fs::read(runtime.run.join("system.ready")).unwrap(),
        identity
    );
    assert!(!first.join(".astrid").exists());
    assert!(!second.join(".astrid").exists());
    let stop = runtime.command(&second, true, &["stop"]);
    assert!(
        stop.status.success(),
        "stop: {}",
        String::from_utf8_lossy(&stop.stderr)
    );
    assert!(!runtime.run.exists());
    let entries = std::fs::read_dir(&runtime.home)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    assert_eq!(entries, [std::ffi::OsString::from("astrid.volume")]);
}
