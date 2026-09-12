//! HTTP must read the same branded workspace configuration as the CLI.

use std::process::Command;

#[test]
fn http_honors_environment_and_cli_workspace_layout() {
    for via_cli in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        let workspace = root.path().join("workspace");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(workspace.join(".aos")).unwrap();
        // A public bind is rejected before token lookup or daemon startup.
        // Ignoring this branded config instead reports a missing token.
        std::fs::write(
            workspace.join(".aos/config.toml"),
            "[gateway.mcp_http]\nlisten = \"0.0.0.0:18452\"\n",
        )
        .unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_astrid"));
        command
            .current_dir(&workspace)
            .env("ASTRID_HOME", &home)
            .env("ASTRID_RUN_DIR", root.path().join("run"))
            .env_remove("ASTRID_CONFIG")
            .env_remove("ASTRID_WORKSPACE_STATE_DIR");
        if via_cli {
            command.args(["--workspace-state-dir", ".aos"]);
        } else {
            command.env("ASTRID_WORKSPACE_STATE_DIR", ".aos");
        }
        let output = command.args(["mcp", "http"]).output().unwrap();
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("MCP HTTP must bind to loopback"),
            "{stderr}"
        );
        assert!(!root.path().join("run/system.sock").exists());
    }
}
