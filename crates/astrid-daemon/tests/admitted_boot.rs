//! Exercise actual daemon restore, CLI precedence and public native shutdown.
#![cfg(unix)]

use astrid_core::dirs::AstridHome;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct OwnedDaemon(Child);
impl Drop for OwnedDaemon {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn daemon_command(
    home: &AstridHome,
    workspace: &Path,
    log: &Path,
    override_limits: bool,
) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_astrid-daemon"));
    command
        .arg("--workspace")
        .arg(workspace)
        .env("ASTRID_HOME", home.root())
        .current_dir(workspace)
        .env_remove("ASTRID_RUN_DIR")
        .env_remove("ASTRID_WORKSPACE_STATE_DIR")
        .env_remove("ASTRID_CAPSULE_HOST_BLOCKING_CONCURRENCY")
        .env_remove("ASTRID_CAPSULE_HOST_IO_CONCURRENCY")
        .env_remove("ASTRID_CAPSULE_INSTANCE_POOL_SIZE")
        .env("ASTRID_DAEMON_LOG_TARGET", "stderr")
        .env_remove("MallocStackLogging")
        .env_remove("MallocStackLoggingNoCompact")
        .env_remove("MallocStackLoggingDirectory")
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(log).unwrap());
    if override_limits {
        command.args(["--host-blocking-concurrency", "11"]);
    }
    command
}

fn launch(home: &AstridHome, workspace: &Path, log: &Path, override_limits: bool) -> OwnedDaemon {
    launch_command(
        daemon_command(home, workspace, log, override_limits),
        home,
        log,
    )
}

fn launch_command(mut command: Command, home: &AstridHome, log: &Path) -> OwnedDaemon {
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
        .env("ASTRID_TEST_BOOT_PID", daemon.0.id().to_string())
        .env("ASTRID_HOME", home.root())
        .current_dir(home.root().parent().unwrap().join("workspace"))
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
        "Resolved native boot limits",
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
            .request(astrid_core::kernel_api::KernelRequest::GetStatus)
            .await
            .unwrap();
        let astrid_core::kernel_api::KernelResponse::Status(status) = response else {
            panic!("expected owned daemon status");
        };
        let expected: u32 = std::env::var("ASTRID_TEST_BOOT_PID")
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(status.pid, expected, "refusing to stop a different daemon");
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

fn failed_boot(home: &AstridHome, workspace: &Path, log: &Path, file_logging: bool) {
    let mut command = daemon_command(home, workspace, log, false);
    if file_logging {
        command.env_remove("ASTRID_DAEMON_LOG_TARGET");
    }
    let mut daemon = OwnedDaemon(command.spawn().unwrap());
    let started = Instant::now();
    loop {
        if let Some(status) = daemon.0.try_wait().unwrap() {
            assert!(!status.success(), "malformed policy was silently accepted");
            break;
        }
        assert!(
            started.elapsed() < Duration::from_mins(1),
            "invalid boot did not return"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        !home.ready_path().exists(),
        "invalid policy published readiness"
    );
    let text = std::fs::read_to_string(log).unwrap();
    assert!(text.contains("cannot load boot policy"), "{text}");
}

#[test]
fn fresh_invalid_policy_never_starts_file_logging_and_can_retry() {
    let root = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(root.path().join("home"));
    let workspace = root.path().join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    astrid_core::platform_fs::create_private_directory(&workspace.join(".astrid")).unwrap();
    std::fs::write(
        workspace.join(".astrid/config.toml"),
        "[capsule]\nhost_io_concurrency = 'bad'\n",
    )
    .unwrap();
    failed_boot(&home, &workspace, &root.path().join("invalid.log"), true);
    assert!(
        !home.log_dir().exists(),
        "file logging amended a failed boot"
    );
    std::fs::write(
        workspace.join(".astrid/config.toml"),
        "[capsule]\nhost_io_concurrency = 73\n",
    )
    .unwrap();
    let mut daemon = launch(&home, &workspace, &root.path().join("retry.log"), false);
    assert!(
        std::fs::read_to_string(root.path().join("retry.log"))
            .unwrap()
            .contains("io_concurrency=73")
    );
    stop(&home, &mut daemon);
}

#[test]
fn malformed_packed_policy_fails_closed_then_recovers_after_correction() {
    let root = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(root.path().join("home"));
    let workspace = root.path().join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let mut daemon = launch(&home, &workspace, &root.path().join("seed.log"), false);
    std::fs::write(home.config_path(), "[http]\ndefault_timeout_secs = 'bad'\n").unwrap();
    stop(&home, &mut daemon);
    failed_boot(&home, &workspace, &root.path().join("invalid.log"), true);
    std::fs::write(home.config_path(), "[http]\ndefault_timeout_secs = 47\n").unwrap();
    let mut daemon = launch(&home, &workspace, &root.path().join("corrected.log"), false);
    assert!(
        std::fs::read_to_string(root.path().join("corrected.log"))
            .unwrap()
            .contains("http_timeout_secs=47")
    );
    stop(&home, &mut daemon);
}

#[test]
fn packed_restart_uses_restored_logging_format() {
    let root = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(root.path().join("home"));
    let workspace = root.path().join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let mut daemon = launch(&home, &workspace, &root.path().join("seed.log"), false);
    std::fs::write(
        home.config_path(),
        "[logging]\nformat = 'json'\nlevel = 'debug'\n[capsule]\nhost_io_concurrency = 73\n",
    )
    .unwrap();
    stop(&home, &mut daemon);
    let log = root.path().join("json.log");
    let mut daemon = launch(&home, &workspace, &log, false);
    let text = std::fs::read_to_string(log).unwrap();
    let fields = text
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .find(|event| event["fields"]["message"] == "Resolved native boot limits")
        .expect("restored logging policy must select the JSON formatter");
    assert_eq!(fields["fields"]["io_concurrency"], 73);
    stop(&home, &mut daemon);
}

fn identity_warning_reaches_configured_logging(file_logging: bool) {
    let config = "[[identity.links]]\nplatform = 'regression'\nplatform_user_id = 'missing-user'\nastrid_user = '11111111-1111-4111-8111-111111111111'\n";
    for packed in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(root.path().join("home"));
        let workspace = root.path().join("workspace");
        std::fs::create_dir(&workspace).unwrap();
        if packed {
            let mut daemon = launch(&home, &workspace, &root.path().join("seed.log"), false);
            std::fs::write(home.config_path(), config).unwrap();
            stop(&home, &mut daemon);
        } else {
            astrid_core::platform_fs::create_private_directory(&workspace.join(".astrid")).unwrap();
            std::fs::write(workspace.join(".astrid/config.toml"), config).unwrap();
        }
        let log = root.path().join("warning.log");
        let mut command = daemon_command(&home, &workspace, &log, false);
        if file_logging {
            command.env_remove("ASTRID_DAEMON_LOG_TARGET");
        }
        let mut daemon = launch_command(command, &home, &log);
        let text = if file_logging {
            std::fs::read_dir(home.log_dir())
                .unwrap()
                .map(|entry| std::fs::read_to_string(entry.unwrap().path()).unwrap())
                .collect::<Vec<_>>()
                .join("\n")
        } else {
            std::fs::read_to_string(&log).unwrap()
        };
        assert!(
            text.contains("Failed to apply identity link from config")
                && text.contains("11111111-1111-4111-8111-111111111111"),
            "missing identity warning (packed={packed}, file={file_logging}): {text}"
        );
        stop(&home, &mut daemon);
    }
}

#[test]
fn identity_warning_reaches_configured_stderr() {
    identity_warning_reaches_configured_logging(false);
}

#[test]
fn identity_warning_reaches_configured_file() {
    identity_warning_reaches_configured_logging(true);
}

#[test]
fn configured_identity_link_survives_public_stop_and_packed_restart() {
    let root = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(root.path().join("home"));
    let workspace = root.path().join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    astrid_core::platform_fs::create_private_directory(&workspace.join(".astrid")).unwrap();
    std::fs::write(workspace.join(".astrid/config.toml"),
        "[logging]\nlevel = 'debug'\n[[identity.links]]\nplatform = 'regression'\nplatform_user_id = 'durable-user'\nastrid_user = 'configured-user'\n").unwrap();
    let log = root.path().join("identity.log");
    let mut daemon = launch(&home, &workspace, &log, false);
    assert!(
        std::fs::read_to_string(&log)
            .unwrap()
            .contains("Created user from config identity link")
    );
    stop(&home, &mut daemon);
    let mut daemon = launch(&home, &workspace, &log, false);
    let text = std::fs::read_to_string(&log).unwrap();
    assert!(
        text.contains("Identity link from config already exists"),
        "{text}"
    );
    assert!(
        !text.contains("Created user from config identity link"),
        "{text}"
    );
    stop(&home, &mut daemon);
}
