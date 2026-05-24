//! `astrid mcp` subcommand group — bridges Astrid capsule tools to
//! external MCP clients (e.g. Claude Code).

use std::process::ExitCode;

use anyhow::Result;
use clap::Subcommand;

use astrid_mcp_bridge::{BridgeConfig, run_stdio};

#[derive(Subcommand)]
pub(crate) enum McpCommand {
    /// Run the MCP bridge over stdio. Intended to be spawned by an
    /// MCP client (e.g. Claude Code via .mcp.json) — not invoked
    /// interactively.
    Bridge,
}

pub(crate) async fn run(command: McpCommand) -> Result<ExitCode> {
    match command {
        McpCommand::Bridge => {
            run_stdio(BridgeConfig::default()).await?;
            Ok(ExitCode::SUCCESS)
        },
    }
}
