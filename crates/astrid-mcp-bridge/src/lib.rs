//! MCP server bridge: speaks MCP over stdio, translates to/from
//! Astrid IPC messages routed through `capsule-cli`'s external API.

#![allow(clippy::missing_errors_doc)]

pub mod error;
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

/// Run the bridge: accept MCP traffic on stdio, translate to/from
/// the Astrid daemon. Returns when stdin closes or a fatal error
/// occurs.
pub async fn run_stdio(config: BridgeConfig) -> Result<(), BridgeError> {
    let _ = config;
    Err(BridgeError::NotYetImplemented("run_stdio"))
}
