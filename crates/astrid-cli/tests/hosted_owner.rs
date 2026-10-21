//! Fresh hosted provisioning must authorize a real native lifecycle, not only a graph fixture.

use ed25519_dalek::SigningKey;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[path = "hosted_owner/cancel.rs"]
mod cancel;
#[path = "hosted_owner/pending.rs"]
mod pending;

struct Runtime {
    root: tempfile::TempDir,
    home: PathBuf,
    workspace: PathBuf,
    daemon: Option<OwnedChild>,
}

// Retain process ownership even if a CLI assertion unwinds during shutdown.
// Drop never discovers a PID, invokes the live host daemon, or panics.
struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Runtime {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("owned hosted fixture");
        let home = root.path().join("home");
        let workspace = root.path().join("workspace");
        std::fs::create_dir(&workspace).unwrap();
        Self {
            root,
            home,
            workspace,
            daemon: None,
        }
    }

    fn environment(&self, command: &mut Command) {
        command
            .current_dir(&self.workspace)
            .env("ASTRID_HOME", &self.home)
            .env("ASTRID_PRINCIPAL", "default")
            .env_remove("ASTRID_CONFIG")
            .env_remove("ASTRID_RUN_DIR")
            .env_remove("ASTRID_WORKSPACE_STATE_DIR")
            .stdin(Stdio::null());
    }

    fn command(&self, args: &[&str]) -> Output {
        // File-backed output avoids pipe deadlocks and inheritance from a daemon.
        let stdout = tempfile::NamedTempFile::new_in(self.root.path()).unwrap();
        let stderr = tempfile::NamedTempFile::new_in(self.root.path()).unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_astrid"));
        self.environment(&mut command);
        let mut child = command
            .args(args)
            .stdout(stdout.reopen().unwrap())
            .stderr(stderr.reopen().unwrap())
            .spawn()
            .expect("owned CLI");
        let deadline = Instant::now().checked_add(Duration::from_secs(90)).unwrap();
        while child.try_wait().unwrap().is_none() {
            if Instant::now() >= deadline {
                child.kill().expect("kill timed-out CLI");
                child.wait().expect("reap timed-out CLI");
                panic!("hosted CLI timed out: {args:?}");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        Output {
            status: child.wait().unwrap(),
            stdout: std::fs::read(stdout.path()).unwrap(),
            stderr: std::fs::read(stderr.path()).unwrap(),
        }
    }

    fn json(&self, args: &[&str]) -> Value {
        let output = self.command(args);
        assert!(
            output.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).expect("public JSON result")
    }

    fn write(&self, name: &str, value: &Value) -> PathBuf {
        let path = self.root.path().join(name);
        std::fs::write(&path, serde_json::to_vec(value).unwrap()).unwrap();
        path
    }

    fn start(&mut self) {
        let log = std::fs::File::create(self.root.path().join("daemon.log")).unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_astrid-daemon"));
        self.environment(&mut command);
        self.daemon = Some(OwnedChild(
            command
                .arg("--workspace")
                .arg(&self.workspace)
                .stdout(log.try_clone().unwrap())
                .stderr(log)
                .spawn()
                .unwrap(),
        ));
        let deadline = Instant::now().checked_add(Duration::from_secs(90)).unwrap();
        loop {
            assert!(
                self.daemon
                    .as_mut()
                    .unwrap()
                    .0
                    .try_wait()
                    .unwrap()
                    .is_none(),
                "daemon failed: {}",
                std::fs::read_to_string(self.root.path().join("daemon.log")).unwrap()
            );
            let output = self.command(&["owner", "inspect"]);
            if output.status.success()
                && serde_json::from_slice::<Value>(&output.stdout)
                    .is_ok_and(|value| value["status"] == "inspected")
            {
                break;
            }
            assert!(Instant::now() < deadline, "hosted daemon readiness timeout");
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn stop(&mut self) {
        let Some(mut owned) = self.daemon.take() else {
            return;
        };
        if owned.0.try_wait().unwrap().is_some() {
            return;
        }
        // Reap our daemon concurrently with the authenticated stop command:
        // otherwise a terminated, unreaped child still appears alive to stop.
        let log = std::fs::File::create(self.root.path().join("stop.log")).unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_astrid"));
        self.environment(&mut command);
        let mut stop = OwnedChild(
            command
                .arg("stop")
                .stdout(log.try_clone().unwrap())
                .stderr(log)
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now().checked_add(Duration::from_secs(90)).unwrap();
        loop {
            let daemon_exited = owned.0.try_wait().unwrap().is_some();
            if let Some(status) = stop.0.try_wait().unwrap()
                && daemon_exited
            {
                assert!(
                    status.success(),
                    "authenticated owned shutdown failed: {}",
                    std::fs::read_to_string(self.root.path().join("stop.log")).unwrap()
                );
                break;
            }
            assert!(Instant::now() < deadline, "owned daemon shutdown timed out");
            std::thread::sleep(Duration::from_millis(20));
        }
        // OwnedChild also bounds failure cleanup to exactly these children and
        // always waits/reaps; it never discovers or signals a host daemon PID.
        owned.0.wait().expect("reap owned daemon");
        stop.0.wait().expect("reap owned stop command");
    }
}
impl Drop for Runtime {
    fn drop(&mut self) {
        // Reap before TempDir fields are removed, including assertion failures.
        drop(self.daemon.take());
    }
}

fn text(path: &Path) -> &str {
    path.to_str().expect("fixture UTF-8 path")
}

fn configure(runtime: &Runtime, policy: &Value) -> Value {
    let path = runtime.write("policy.json", policy);
    runtime.json(&[
        "owner",
        "configure",
        "--policy",
        text(&path),
        "--target-default",
    ])
}

#[test]
fn offline_inspection_uses_transport_presence_without_bootstrapping() {
    let runtime = Runtime::new();
    let offline = json!({"status": "offline", "durable_status": "unavailable"});
    assert_eq!(runtime.json(&["owner", "inspect"]), offline);
    assert!(!runtime.home.exists(), "inspection must not create a home");

    // A filesystem-shaped endpoint token is not evidence of a live transport:
    // Unix requires a socket; Windows uses a separate SID-scoped pipe namespace.
    let run = runtime.home.join("run");
    std::fs::create_dir_all(&run).unwrap();
    let token = run.join("system.sock");
    std::fs::write(&token, b"not a transport endpoint").unwrap();
    assert_eq!(runtime.json(&["owner", "inspect"]), offline);
    assert_eq!(std::fs::read(token).unwrap(), b"not a transport endpoint");
    assert_eq!(std::fs::read_dir(run).unwrap().count(), 1);
    assert_eq!(std::fs::read_dir(&runtime.home).unwrap().count(), 1);
}

#[test]
fn invalid_offline_policy_never_admits_execution_identity() {
    let runtime = Runtime::new();
    let expiry = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;
    for policy in [
        json!({"deployment_key": vec![0; 32], "generation": 1, "expires_at": expiry}),
        json!({"deployment_key": SigningKey::from_bytes(&[12;32]).verifying_key().to_bytes(), "generation": 1, "expires_at": 1}),
    ] {
        let path = runtime.write("invalid.json", &policy);
        assert!(
            !runtime
                .command(&[
                    "owner",
                    "configure",
                    "--policy",
                    text(&path),
                    "--target-default"
                ])
                .status
                .success()
        );
        assert!(
            !runtime.home.exists(),
            "invalid policy must fail before native admission"
        );
    }
}

fn configure_twice(runtime: &Runtime, deployment: &SigningKey, now: u64) -> Value {
    let mut policy = json!({"deployment_key": deployment.verifying_key().to_bytes(), "generation": 1, "expires_at": now.checked_add(3600).unwrap()});
    let first = configure(runtime, &policy);
    assert!(first["pending"].is_null() && first["completion"].is_null());
    policy["generation"] = json!(2);
    let second = configure(runtime, &policy);
    assert_eq!(first["policy"]["target"], second["policy"]["target"]);
    assert_eq!(first["installation"], second["installation"]);
    assert!(second["pending"].is_null() && second["completion"].is_null());
    second
}

fn signing_keys(runtime: &Runtime) -> (SigningKey, SigningKey, PathBuf, PathBuf) {
    let owner = SigningKey::from_bytes(&[91; 32]);
    let deployment = SigningKey::from_bytes(&[92; 32]);
    let owner_path = runtime.root.path().join("owner.key");
    let deployment_path = runtime.root.path().join("deployment.key");
    std::fs::write(&owner_path, owner.to_bytes()).unwrap();
    std::fs::write(&deployment_path, deployment.to_bytes()).unwrap();
    (owner, deployment, owner_path, deployment_path)
}

fn enrolled_lifecycle(runtime: &Runtime) {
    for args in [
        vec!["agent", "create", "enrolled", "-y"],
        vec!["agent", "claim", "enrolled"],
        vec!["agent", "delete", "enrolled", "-y"],
    ] {
        let output = runtime.command(&args);
        assert!(
            output.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn two_external_roles_enable_native_lifecycle_and_survive_restart() {
    let mut runtime = Runtime::new();
    assert_eq!(runtime.json(&["owner", "inspect"])["status"], "offline");
    assert!(!runtime.home.exists());
    let (owner, deployment, owner_path, deployment_path) = signing_keys(&runtime);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let second = configure_twice(&runtime, &deployment, now);
    runtime.start();
    assert_eq!(
        runtime.json(&["owner", "inspect"])["enrollment"],
        "unenrolled"
    );
    assert!(
        !runtime
            .command(&["agent", "create", "before-enrollment", "-y"])
            .status
            .success()
    );
    let genesis = runtime.json(&[
        "owner",
        "prepare",
        "--owner-public-key",
        &hex::encode(owner.verifying_key().to_bytes()),
    ]);
    let genesis_path = runtime.write("genesis.json", &genesis);
    let packet = runtime.json(&[
        "owner",
        "challenge",
        "--genesis",
        text(&genesis_path),
        "--expires-at",
        &(now + 1800).to_string(),
    ]);
    assert_eq!(packet["policy"], second["policy"]);
    let packet_path = runtime.write("challenge.json", &packet);
    let owner_signed = runtime.json(&[
        "owner",
        "sign-owner",
        "--challenge",
        text(&packet_path),
        "--signing-key",
        text(&owner_path),
    ]);
    let owner_signed_path = runtime.write("owner-signed.json", &owner_signed);
    let before = runtime.json(&["owner", "inspect"]);
    assert!(
        !runtime
            .command(&["owner", "provision", "--envelope", text(&owner_signed_path)])
            .status
            .success()
    );
    assert_eq!(runtime.json(&["owner", "inspect"]), before);
    let signed = runtime.json(&[
        "owner",
        "authorize",
        "--envelope",
        text(&owner_signed_path),
        "--signing-key",
        text(&deployment_path),
    ]);
    let signed_path = runtime.write("signed.json", &signed);
    runtime.stop();
    pending::persist(&runtime, &signed);
    runtime.start();
    assert_eq!(runtime.json(&["owner", "inspect"])["enrollment"], "pending");
    let enrolled = runtime.json(&["owner", "provision", "--envelope", text(&signed_path)]);
    assert_eq!(enrolled["status"], "enrolled");
    assert_eq!(
        runtime.json(&["owner", "provision", "--envelope", text(&signed_path)]),
        enrolled
    );
    enrolled_lifecycle(&runtime);
    runtime.stop();
    runtime.start();
    let inspected = runtime.json(&["owner", "inspect"]);
    assert_eq!(inspected["enrollment"], "enrolled");
    assert_eq!(inspected["completion"], enrolled["completion"]);
    assert_eq!(
        runtime.json(&["owner", "provision", "--envelope", text(&signed_path)]),
        enrolled
    );
    for args in [
        vec!["agent", "create", "retained", "-y"],
        vec!["agent", "delete", "retained", "-y"],
    ] {
        let output = runtime.command(&args);
        assert!(
            output.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    runtime.stop();
}
