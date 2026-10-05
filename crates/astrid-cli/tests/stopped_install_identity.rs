use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn unavailable_daemon_does_not_generate_identity_in_stopped_home() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home");
    let binaries = root.path().join("bin");
    let source = root.path().join("capsule");
    for directory in [&home, &binaries, &source] {
        std::fs::create_dir(directory).unwrap();
    }
    let volume = b"stopped-volume-must-not-be-opened-without-a-daemon";
    std::fs::write(home.join("astrid.volume"), volume).unwrap();
    std::fs::write(
        source.join("Capsule.toml"),
        "[package]\nname = \"stopped-install-probe\"\nversion = \"1.0.0\"\n",
    )
    .unwrap();
    let cli = binaries.join(format!("astrid{}", std::env::consts::EXE_SUFFIX));
    std::fs::copy(env!("CARGO_BIN_EXE_astrid"), &cli).unwrap();
    let mut child = Command::new(&cli)
        .current_dir(root.path())
        .env("ASTRID_HOME", &home)
        .env("PATH", &binaries)
        .env_remove("ASTRID_RUN_DIR")
        .env_remove("ASTRID_PRINCIPAL_ID")
        .env_remove("ASTRID_CLIENT_CONFIG")
        .env_remove("DYLD_FALLBACK_LIBRARY_PATH")
        .args(["--principal", "default", "capsule", "install"])
        .arg(&source)
        .args(["--yes", "--approve-untrusted"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            child.kill().unwrap();
            panic!("install did not refuse the missing co-installed daemon");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("astrid-daemon not found"), "{error}");
    assert!(
        !home.join("keys").exists(),
        "inspection generated a sidecar key"
    );
    assert_eq!(std::fs::read(home.join("astrid.volume")).unwrap(), volume);
}
