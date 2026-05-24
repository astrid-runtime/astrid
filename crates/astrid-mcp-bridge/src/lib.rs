//! MCP server bridge: speaks MCP over stdio, translates to/from
//! Astrid IPC messages routed through `capsule-cli`'s external API.

#![allow(clippy::missing_errors_doc)]

pub mod catalog;
pub mod daemon;
pub mod debug;
pub mod error;
pub mod mcp;

pub use error::BridgeError;

/// Configuration for a single bridge run.
#[derive(Debug, Clone)]
pub struct BridgeConfig {
    /// Principal to attribute tool calls to. v1: always "default".
    pub principal: String,
    /// Default per-tool-call timeout.
    pub tool_timeout: std::time::Duration,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            principal: "default".into(),
            tool_timeout: std::time::Duration::from_secs(60),
        }
    }
}

/// Run the bridge: connect to the daemon, build the tool catalog by
/// introspecting installed capsules, then accept MCP traffic on stdio.
/// Returns when stdin closes or a fatal error occurs.
pub async fn run_stdio(config: BridgeConfig) -> Result<(), BridgeError> {
    use rmcp::{ServiceExt, transport::stdio};

    debug::log(format_args!("run_stdio: starting, principal={}", config.principal));
    let daemon = daemon::DaemonConnection::connect(&config.principal).await?;
    debug::log(format_args!("run_stdio: daemon connected"));
    let server = mcp::AstridMcpServer::new(daemon).await?;
    debug::log(format_args!("run_stdio: catalog built, serving over stdio"));
    let service = server
        .serve(stdio())
        .await
        .map_err(|e| BridgeError::Mcp(anyhow::anyhow!("serve: {e}")))?;
    service
        .waiting()
        .await
        .map_err(|e| BridgeError::Mcp(anyhow::anyhow!("waiting: {e}")))?;
    Ok(())
}
