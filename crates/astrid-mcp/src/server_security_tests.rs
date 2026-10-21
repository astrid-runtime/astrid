//! Native MCP grants must not reopen runtime state hidden from the child.

use super::*;

const CHILD_MARKER: &str = "ASTRID_TEST_MCP_RUNTIME_GRANTS";

#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn protected_runtime_grants_are_denied() {
    if std::env::var_os(CHILD_MARKER).is_some() {
        check_protected_grants_in_child();
        return;
    }
    let root = tempfile::tempdir().expect("isolated runtime home");
    let output = std::process::Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "server::security_tests::protected_runtime_grants_are_denied",
            "--nocapture",
        ])
        .env("ASTRID_HOME", root.path())
        .env(CHILD_MARKER, "1")
        .output()
        .expect("isolated child test");
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn check_protected_grants_in_child() {
    let home = astrid_core::dirs::AstridHome::resolve().expect("isolated home");
    let volume = home.storage_volume_path();
    std::fs::write(&volume, b"synthetic-volume").expect("synthetic volume");
    let alias = home.root().join("volume-alias");
    std::os::unix::fs::symlink(&volume, &alias).expect("volume alias");
    let safe = tempfile::tempdir().expect("external workspace");
    let manager =
        ServerManager::new(ServersConfig::default()).with_workspace_root(safe.path().to_path_buf());
    for denied in [&volume, home.root(), alias.as_path()] {
        for mut config in [
            ServerConfig::stdio("test", "echo").with_write_path(denied),
            ServerConfig::stdio("test", "echo").with_read_path(denied),
            ServerConfig::stdio("test", "echo"),
        ] {
            if config.allowed_read_paths.is_empty() && config.allowed_write_paths.is_empty() {
                config.cwd = Some(denied.to_path_buf());
            }
            let error = manager
                .build_sandboxed_command("test", "echo", &config)
                .expect_err("protected runtime grant must be denied");
            assert!(
                matches!(error, McpError::ServerStartFailed { .. }),
                "{error}"
            );
        }
    }
}
