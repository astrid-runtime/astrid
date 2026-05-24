//! End-to-end tests: spawn `astrid mcp bridge` as a subprocess and
//! drive it with an in-test rmcp client over its stdio.
//!
//! All tests below are `#[ignore]` because the bridge now connects to
//! the live daemon at startup (Task 6+) — there is no useful offline
//! mode left to assert against. Run with:
//!
//!   cargo test -p astrid-mcp-bridge --test integration -- --ignored
//!
//! The `astrid` binary lives in `astrid-cli`, not this crate, so we
//! locate it via the workspace target directory derived from
//! `CARGO_MANIFEST_DIR`.

use std::path::{Path, PathBuf};
use std::process::Stdio;

use rmcp::ServiceExt;
use rmcp::model::{CallToolRequestParams, RawContent};
use tokio::process::Command;

/// Locate the `astrid` binary in the workspace target directory.
fn find_astrid_binary() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest
        .ancestors()
        .find(|p| p.join("Cargo.toml").is_file() && p.join("target").is_dir())
        .expect("workspace root with target/ not found");
    let target = workspace_root.join("target");

    let exe = if cfg!(windows) { "astrid.exe" } else { "astrid" };
    for profile in ["debug", "release"] {
        let candidate = target.join(profile).join(exe);
        if candidate.is_file() {
            return candidate;
        }
    }
    panic!(
        "could not locate `astrid` binary under {}/{{debug,release}}. \
         Run `cargo build -p astrid` first.",
        target.display()
    );
}

#[tokio::test]
#[ignore = "requires running astrid daemon"]
async fn initialize_returns_server_info() -> anyhow::Result<()> {
    let bin = find_astrid_binary();
    assert!(
        Path::new(&bin).is_file(),
        "astrid binary not found at {}",
        bin.display()
    );

    let mut cmd = Command::new(&bin);
    cmd.args(["mcp", "bridge"])
        .stdout(Stdio::piped())
        .stdin(Stdio::piped())
        .stderr(Stdio::inherit());

    let transport = rmcp::transport::child_process::TokioChildProcess::new(cmd)?;
    let service = ().serve(transport).await?;

    let server_info = service
        .peer_info()
        .expect("peer_info available after initialize");
    assert_eq!(server_info.server_info.name, "astrid-mcp-bridge");

    let _ = service.cancel().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires running astrid daemon"]
async fn bridge_connects_to_daemon() -> anyhow::Result<()> {
    let _conn = astrid_mcp_bridge::daemon::DaemonConnection::connect("default").await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires running astrid daemon with capsule-system + capsule-shell installed"]
async fn live_tools_list_includes_shell() -> anyhow::Result<()> {
    let bin = find_astrid_binary();

    let mut cmd = Command::new(&bin);
    cmd.args(["mcp", "bridge"])
        .stdout(Stdio::piped())
        .stdin(Stdio::piped())
        .stderr(Stdio::inherit());

    let transport = rmcp::transport::child_process::TokioChildProcess::new(cmd)?;
    let service = ().serve(transport).await?;

    let tools = service.list_tools(Option::default()).await?;
    let names: Vec<&str> = tools.tools.iter().map(|t| t.name.as_ref()).collect();
    eprintln!("catalog: {names:?}");

    assert!(
        names.iter().any(|n| n.starts_with("shell.")),
        "expected at least one shell.* tool; got: {names:?}"
    );

    let _ = service.cancel().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires running astrid daemon with capsule-shell installed"]
async fn live_call_shell_tool() -> anyhow::Result<()> {
    let bin = find_astrid_binary();

    let mut cmd = Command::new(&bin);
    cmd.args(["mcp", "bridge"])
        .stdout(Stdio::piped())
        .stdin(Stdio::piped())
        .stderr(Stdio::inherit());

    let transport = rmcp::transport::child_process::TokioChildProcess::new(cmd)?;
    let service = ().serve(transport).await?;

    // Build argument map: { "command": "echo hello-astrid" }
    let mut arguments = serde_json::Map::new();
    arguments.insert(
        "command".into(),
        serde_json::Value::String("echo hello-astrid".into()),
    );

    let result = service
        .call_tool(CallToolRequestParams {
            meta: None,
            name: "shell.run_shell_command".into(),
            arguments: Some(arguments),
            task: None,
        })
        .await?;

    // Content is Vec<Content> where Content is Annotated<RawContent>;
    // pattern-match the RawContent::Text variant via Deref.
    let combined: String = result
        .content
        .iter()
        .filter_map(|c| match &c.raw {
            RawContent::Text(t) => Some(t.text.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("");

    assert!(
        combined.contains("hello-astrid"),
        "expected hello-astrid in output; got: {combined:?}; is_error={:?}",
        result.is_error,
    );

    let _ = service.cancel().await?;
    Ok(())
}
