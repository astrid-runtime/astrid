//! End-to-end test: spawn `astrid mcp bridge` as a subprocess, drive
//! it with an in-test rmcp client over its stdio, verify
//! `initialize` returns the right server info and `tools/list` is empty.
//!
//! The `astrid` binary lives in `astrid-cli`, not this crate, so we
//! locate it via the workspace target directory derived from
//! `CARGO_MANIFEST_DIR` and the executable's own path. We try (in
//! order) the current build profile's directory, then `debug`, then
//! `release` — whichever has a recent `astrid` binary.

use std::path::{Path, PathBuf};
use std::process::Stdio;

use rmcp::ServiceExt;
use tokio::process::Command;

/// Locate the `astrid` binary in the workspace target directory.
///
/// `CARGO_MANIFEST_DIR` points at this crate; walk up to the workspace
/// root (containing `Cargo.toml` + `target/`) and probe `target/debug`
/// and `target/release`.
fn find_astrid_binary() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // crates/astrid-mcp-bridge -> walk up to workspace root.
    let workspace_root = manifest
        .ancestors()
        .find(|p| p.join("Cargo.toml").is_file() && p.join("target").is_dir())
        .expect("workspace root with target/ not found");
    let target = workspace_root.join("target");

    // Prefer debug (test default), fall back to release.
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
async fn initialize_returns_server_info_and_empty_tools_list() -> anyhow::Result<()> {
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
        .stderr(Stdio::null());

    let transport = rmcp::transport::child_process::TokioChildProcess::new(cmd)?;
    let service = ().serve(transport).await?;

    let server_info = service
        .peer_info()
        .expect("peer_info available after initialize");
    assert_eq!(server_info.server_info.name, "astrid-mcp-bridge");

    let tools = service.list_tools(Option::default()).await?;
    assert!(
        tools.tools.is_empty(),
        "expected empty catalog, got {:?}",
        tools.tools
    );

    let _ = service.cancel().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires running astrid daemon"]
async fn bridge_connects_to_daemon() -> anyhow::Result<()> {
    let _conn = astrid_mcp_bridge::daemon::DaemonConnection::connect("default").await?;
    Ok(())
}
