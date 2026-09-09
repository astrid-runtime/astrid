//! Every graceful termination source must leave the same durable root.
#![cfg(unix)]

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn command(binary: &str, home: &Path) -> Command {
    let mut command = Command::new(binary);
    command
        .env("ASTRID_HOME", home)
        .env_remove("ASTRID_RUN_DIR")
        .env_remove("ASTRID_CONFIG")
        .env("ASTRID_DAEMON_LOG_TARGET", "stderr")
        .current_dir(home);
    command
}

fn start(home: &Path, ephemeral: bool, log: &Path) -> Daemon {
    let mut command = command(env!("CARGO_BIN_EXE_astrid-daemon"), home);
    command.arg("--workspace").arg(home);
    if ephemeral {
        command.arg("--ephemeral");
    }
    let mut child = Daemon(
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(log).unwrap())
            .spawn()
            .unwrap(),
    );
    let started = Instant::now();
    while !home.join("run/system.ready").exists() {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "boot exited: {}",
            std::fs::read_to_string(log).unwrap()
        );
        assert!(started.elapsed() < Duration::from_secs(30), "boot timeout");
        std::thread::sleep(Duration::from_millis(25));
    }
    child
}

fn wait(child: &mut Daemon, log: &Path) {
    let started = Instant::now();
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(
                status.success(),
                "shutdown failed: {}",
                std::fs::read_to_string(log).unwrap()
            );
            return;
        }
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "shutdown timeout"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn stop(child: &mut Daemon, home: &Path, log: &Path) {
    let mut cli = command(env!("CARGO_BIN_EXE_astrid"), home)
        .arg("stop")
        .spawn()
        .unwrap();
    // This test is the daemon's parent. Reap it while stop waits for process
    // exit, rather than leaving a zombie that kill(pid, 0) still sees as live.
    wait(child, log);
    assert!(cli.wait().unwrap().success());
}

#[test]
fn idle_signal_and_cli_stop_finalize_and_restore_identically() {
    for mode in ["idle", "signal", "cli"] {
        let directory = tempfile::tempdir().unwrap();
        let home = directory.path().join("runtime");
        std::fs::create_dir(&home).unwrap();
        let log = directory.path().join("daemon.log");
        let mut daemon = start(&home, mode == "idle", &log);
        assert!(
            command(env!("CARGO_BIN_EXE_astrid-daemon"), &home)
                .arg("--version")
                .output()
                .unwrap()
                .status
                .success()
        );
        std::fs::write(home.join("final-write.txt"), mode).unwrap();
        match mode {
            "signal" => nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(i32::try_from(daemon.0.id()).unwrap()),
                nix::sys::signal::Signal::SIGTERM,
            )
            .unwrap(),
            "cli" => stop(&mut daemon, &home, &log),
            _ => {},
        }
        wait(&mut daemon, &log);
        let entries = std::fs::read_dir(&home)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(entries.len(), 1, "{mode} left host sidecars");
        assert_eq!(entries[0].file_name(), "astrid.volume");
        let mut restarted = start(&home, false, &log);
        assert_eq!(
            std::fs::read_to_string(home.join("final-write.txt")).unwrap(),
            mode
        );
        stop(&mut restarted, &home, &log);
    }
}
