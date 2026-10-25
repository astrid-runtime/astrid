//! Exercise actual daemon restore, CLI precedence and public native shutdown.
#![cfg(unix)]

use astrid_core::dirs::AstridHome;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct OwnedDaemon(Child);
impl Drop for OwnedDaemon {
    fn drop(&mut self) {
        if self.0.try_wait().unwrap().is_none() {
            self.0.kill().unwrap();
            self.0.wait().unwrap();
        }
    }
}

fn launch(home: &AstridHome, workspace: &Path, log: &Path, override_limits: bool) -> OwnedDaemon {
    let mut command = Command::new(env!("CARGO_BIN_EXE_astrid-daemon"));
    command
        .arg("--workspace")
        .arg(workspace)
        .env("ASTRID_HOME", home.root())
        .env_remove("ASTRID_RUN_DIR")
        .env("ASTRID_DAEMON_LOG_TARGET", "stderr")
        .env_remove("MallocStackLogging")
        .env_remove("MallocStackLoggingNoCompact")
        .env_remove("MallocStackLoggingDirectory")
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(log).unwrap());
    if override_limits {
        command.args(["--host-blocking-concurrency", "11"]);
    }
    let mut daemon = OwnedDaemon(command.spawn().unwrap());
    let started = Instant::now();
    while !home.ready_path().exists() {
        assert!(
            daemon.0.try_wait().unwrap().is_none(),
            "{}",
            std::fs::read_to_string(log).unwrap()
        );
        assert!(
            started.elapsed() < Duration::from_mins(1),
            "daemon did not become ready"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    daemon
}

fn stop(home: &AstridHome, daemon: &mut OwnedDaemon) {
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "shutdown_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("ASTRID_TEST_BOOT_RPC", "1")
        .env("ASTRID_HOME", home.root())
        .env_remove("ASTRID_RUN_DIR")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("public shutdown acknowledged"));
    let started = Instant::now();
    loop {
        if let Some(status) = daemon.0.try_wait().unwrap() {
            assert!(status.success(), "daemon shutdown failed: {status}");
            break;
        }
        assert!(
            started.elapsed() < Duration::from_mins(1),
            "daemon failed to finalize"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let names: Vec<_> = std::fs::read_dir(home.root())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(names, [std::ffi::OsString::from("astrid.volume")]);
}

#[test]
fn packed_public_daemon_restores_config_before_resolving_cli_limits() {
    let root = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(root.path().join("home"));
    let workspace = root.path().join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let mut daemon = launch(&home, &workspace, &root.path().join("seed.log"), false);
    std::fs::write(
        home.root().join("config.toml"),
        "[capsule]\nhost_io_concurrency = 73\n",
    )
    .unwrap();
    std::fs::write(home.root().join("etc/config.toml"),
        "[capsule]\nhost_blocking_concurrency = 3\ninstance_pool_size = 7\n[http]\ndefault_timeout_secs = 47\n[logging]\nlevel = 'debug'\n").unwrap();
    stop(&home, &mut daemon);
    drop(daemon);
    let log = root.path().join("restored.log");
    let mut daemon = launch(&home, &workspace, &log, true);
    let text = std::fs::read_to_string(&log).unwrap();
    for expected in [
        "Resolved admitted boot limits",
        "blocking_concurrency=11",
        "io_concurrency=73",
        "instance_pool_size=7",
        "http_timeout_secs=47",
    ] {
        assert!(text.contains(expected), "missing {expected}: {text}");
    }
    stop(&home, &mut daemon);
}

#[test]
fn shutdown_child() {
    if std::env::var_os("ASTRID_TEST_BOOT_RPC").is_none() {
        return;
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let mut client = astrid_uplink::kernel_client::KernelClient::connect(
            astrid_core::PrincipalId::default(),
        )
        .await
        .unwrap();
        let response = client
            .request(astrid_core::kernel_api::KernelRequest::Shutdown {
                reason: Some("public boot regression".into()),
            })
            .await
            .unwrap();
        assert!(
            !matches!(
                response,
                astrid_core::kernel_api::KernelResponse::Error { .. }
            ),
            "{response:?}"
        );
        println!("public shutdown acknowledged");
    });
}
