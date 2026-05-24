//! Bridge error type.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum BridgeError {
    #[error("not yet implemented: {0}")]
    NotYetImplemented(&'static str),

    #[error("daemon connection failed: {0}")]
    DaemonConnect(#[source] anyhow::Error),

    #[error("daemon disconnected mid-session")]
    DaemonDisconnected,

    #[error("tool call timed out after {0:?}")]
    ToolTimeout(std::time::Duration),

    #[error("tool '{name}' not found in catalog")]
    UnknownTool { name: String },

    #[error("MCP protocol error: {0}")]
    Mcp(#[source] anyhow::Error),

    #[error("internal: {0}")]
    Internal(#[source] anyhow::Error),
}
