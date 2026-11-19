//! A detached daemon must not retain its launcher's output stream.
#![cfg(unix)]

use std::io::Read as _;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

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

struct StopOnDrop<'a>(Option<&'a Path>);

impl StopOnDrop<'_> {
    fn finish(mut self) {
        let home = self.0.expect("armed owned cleanup");
        let output = cli(home)
            .arg("stop")
            .stderr(Stdio::piped())
            .output()
            .expect("stop launcher");
        assert!(
            output.status.success(),
            "stop failed: {}; stderr: {}; entries: {:?}",
            output.status,
            String::from_utf8_lossy(&output.stderr),
            entries(home)
        );
        self.0 = None;
    }
}

fn entries(home: &Path) -> Vec<std::ffi::OsString> {
    let mut entries: Vec<_> = std::fs::read_dir(home)
        .expect("runtime root")
        .map(|entry| entry.expect("runtime entry").file_name())
        .collect();
    entries.sort();
    entries
}

impl Drop for StopOnDrop<'_> {
    fn drop(&mut self) {
        if let Some(home) = self.0 {
            let _ = cli(home).arg("stop").stderr(Stdio::null()).status();
        }
    }
}

fn start_and_check_eof(home: &Path, ephemeral: bool) {
    let (mut reader, writer) = UnixStream::pair().expect("captured stderr");
    reader
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("read deadline");
    let mut command = cli(home);
    command.arg("start");
    if ephemeral {
        command.arg("--ephemeral");
    }
    let mut launcher = command
        .stderr(Stdio::from(OwnedFd::from(writer)))
        .spawn()
        .expect("start launcher");
    // Command retains its configured Stdio after spawn; the test itself must
    // release that writer before checking the child's inherited descriptors.
    drop(command);
    let cleanup = StopOnDrop(Some(home));
    let started = Instant::now();
    loop {
        if let Some(status) = launcher.try_wait().expect("launcher status") {
            assert!(status.success(), "startup failed: {status}");
            break;
        }
        assert!(
            started.elapsed() < Duration::from_mins(1),
            "launcher did not exit"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(
        home.join("run/system.ready").exists(),
        "daemon must remain ready"
    );
    let mut output = Vec::new();
    reader
        .read_to_end(&mut output)
        .expect("stderr must reach EOF while daemon is alive");
    assert!(
        home.join("run/system.ready").exists(),
        "EOF must not depend on shutdown"
    );
    cleanup.finish();
}

fn check_fresh_and_volume_only_homes(ephemeral: bool) {
    let directory = tempfile::tempdir().expect("owned test root");
    let home = directory.path().join("runtime");
    std::fs::create_dir(&home).expect("runtime root");
    start_and_check_eof(&home, ephemeral);
    assert_eq!(entries(&home), [std::ffi::OsString::from("astrid.volume")]);
    assert!(home.join("astrid.volume").is_file());
    start_and_check_eof(&home, ephemeral);
    assert_eq!(entries(&home), [std::ffi::OsString::from("astrid.volume")]);
}

#[test]
fn captured_persistent_start_returns_for_fresh_and_volume_only_homes() {
    check_fresh_and_volume_only_homes(false);
}

#[test]
fn captured_ephemeral_start_returns_for_fresh_and_volume_only_homes() {
    check_fresh_and_volume_only_homes(true);
}

#[test]
fn redirected_temporary_directory_is_refused_before_runtime_mutation() {
    for ephemeral in [false, true] {
        let directory = tempfile::tempdir().expect("owned test root");
        let home = directory.path().join("runtime");
        let temporary = home.join("temporary");
        std::fs::create_dir_all(&temporary).expect("configured temporary directory");
        let mut command = cli(&home);
        command
            .arg("start")
            .env("TMPDIR", &temporary)
            .env("TMP", &temporary)
            .env("TEMP", &temporary);
        if ephemeral {
            command.arg("--ephemeral");
        }
        let output = command.output().expect("refused startup");
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("daemon temporary directory must be outside Astrid home"),
            "unexpected refusal: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            std::fs::read_dir(&home).expect("runtime entries").count(),
            1
        );
        assert_eq!(
            std::fs::read_dir(&temporary)
                .expect("temporary entries")
                .count(),
            0
        );
        assert!(!home.join("run").exists());
    }
}

#[test]
fn symlinked_fence_directory_is_refused_without_mutating_home() {
    let directory = tempfile::tempdir().expect("owned test root");
    let home = directory.path().join("runtime");
    let temporary = directory.path().join("temporary");
    std::fs::create_dir(&home).expect("fresh runtime");
    std::fs::create_dir(&temporary).expect("temporary root");
    std::os::unix::fs::symlink(&home, temporary.join("astrid-start-fences"))
        .expect("redirect fence directory");
    let output = cli(&home)
        .arg("start")
        .env("TMPDIR", &temporary)
        .env("TMP", &temporary)
        .env("TEMP", &temporary)
        .output()
        .expect("refused startup");
    assert!(!output.status.success(), "redirected startup must fail");
    assert_eq!(
        std::fs::read_dir(&home).expect("runtime entries").count(),
        0,
        "start fence must not follow a directory alias into runtime"
    );
}
