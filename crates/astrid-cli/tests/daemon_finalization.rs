//! Every graceful termination source must leave the same durable root.
#![cfg(unix)]

use std::io::Write as _;
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

fn retain_boot_connection(home: &Path) -> (tokio::runtime::Runtime, tokio::task::JoinHandle<()>) {
    // CLI startup itself can exceed startup grace on loaded CI machines.
    // Hand off this boot connection only after install reaches approval.
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let mut stream = runtime.block_on(async {
        let mut stream = astrid_core::local_transport::connect(&home.join("run/system.sock"))
            .await
            .unwrap();
        assert!(
            astrid_uplink::socket_client::perform_handshake_for_test(
                &mut stream,
                &astrid_core::PrincipalId::new("default").unwrap(),
                &astrid_core::dirs::AstridHome::from_path(home),
            )
            .await
            .unwrap()
        );
        stream
    });
    let boot_lease = runtime.spawn(async move {
        use tokio::io::AsyncReadExt as _;
        let mut buffer = [0; 4096];
        while matches!(stream.read(&mut buffer).await, Ok(count) if count > 0) {}
    });
    (runtime, boot_lease)
}

#[test]
fn install_approval_retains_ephemeral_daemon_and_runtime_identity() {
    let directory = tempfile::tempdir().unwrap();
    let home = directory.path().join("runtime");
    std::fs::create_dir(&home).unwrap();
    let source = directory.path().join("unsigned-capsule");
    std::fs::create_dir(&source).unwrap();
    std::fs::write(
        source.join("Capsule.toml"),
        "[package]\nname=\"ephemeral-install-probe\"\nversion=\"1.0.0\"\n",
    )
    .unwrap();
    let log = directory.path().join("daemon.log");
    let mut daemon = start(&home, true, &log);
    let (runtime, boot_lease) = retain_boot_connection(&home);
    let key = std::fs::read(home.join("keys/runtime.key")).unwrap();
    let approval_log = directory.path().join("approval.log");
    let mut install = Daemon(
        command(env!("CARGO_BIN_EXE_astrid"), &home)
            .args(["--principal", "default", "capsule", "install"])
            .arg(&source)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(&approval_log).unwrap())
            .spawn()
            .unwrap(),
    );
    let started = Instant::now();
    loop {
        let output = std::fs::read_to_string(&approval_log).unwrap();
        if output.contains("Approve this exact install once? [y/N]") {
            break;
        }
        assert!(install.0.try_wait().unwrap().is_none(), "{output}");
        assert!(started.elapsed() < Duration::from_secs(30), "{output}");
        std::thread::sleep(Duration::from_millis(25));
    }
    boot_lease.abort();
    runtime.block_on(async {
        let _ = boot_lease.await;
    });
    // Exceed the kernel's five-second startup grace with stdin still open.
    // The test-owned boot connection is gone: only install can keep it alive.
    std::thread::sleep(Duration::from_secs(7));
    assert!(
        daemon.0.try_wait().unwrap().is_none(),
        "retired during approval: {}\nCLI: {}",
        std::fs::read_to_string(&log).unwrap(),
        std::fs::read_to_string(&approval_log).unwrap()
    );
    assert_eq!(std::fs::read(home.join("keys/runtime.key")).unwrap(), key);
    install.0.stdin.take().unwrap().write_all(b"n\n").unwrap();
    let started = Instant::now();
    loop {
        if let Some(status) = install.0.try_wait().unwrap() {
            assert!(!status.success(), "unapproved install succeeded");
            break;
        }
        assert!(started.elapsed() < Duration::from_secs(30));
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(
        std::fs::read_to_string(&approval_log)
            .unwrap()
            .contains("capsule install authority was not approved")
    );
    wait(&mut daemon, &log);
    let entries = std::fs::read_dir(&home)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(entries.len(), 1, "decline left runtime sidecars");
    assert_eq!(entries[0].file_name(), "astrid.volume");
    let mut restarted = start(&home, false, &log);
    assert_eq!(std::fs::read(home.join("keys/runtime.key")).unwrap(), key);
    stop(&mut restarted, &home, &log);
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
