//! A detached persistent daemon must not retain its launcher's output stream.
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

struct StopOnDrop<'a>(&'a Path);

impl Drop for StopOnDrop<'_> {
    fn drop(&mut self) {
        let _ = cli(self.0).arg("stop").stderr(Stdio::null()).status();
    }
}

fn start_and_check_eof(home: &Path) {
    let (mut reader, writer) = UnixStream::pair().expect("captured stderr");
    reader
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("read deadline");
    let mut launcher = cli(home)
        .arg("start")
        .stderr(Stdio::from(OwnedFd::from(writer)))
        .spawn()
        .expect("start launcher");
    let _cleanup = StopOnDrop(home);
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
}

#[test]
fn captured_start_returns_for_fresh_and_volume_only_homes() {
    let directory = tempfile::tempdir().expect("owned test root");
    let home = directory.path().join("runtime");
    std::fs::create_dir(&home).expect("runtime root");
    start_and_check_eof(&home);
    assert_eq!(std::fs::read_dir(&home).expect("stopped root").count(), 1);
    assert!(home.join("astrid.volume").is_file());
    start_and_check_eof(&home);
    assert_eq!(std::fs::read_dir(&home).expect("stopped root").count(), 1);
}
