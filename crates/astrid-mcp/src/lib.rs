//! Astrid MCP - MCP client with server lifecycle management.
//!
//! This crate provides:
//! - MCP server configuration and lifecycle management
//! - MCP client for tool calling
//! - Secure client with capability-based authorization
//!
//! # Architecture
//!
//! The MCP layer wraps the official `rmcp` SDK with:
//! - Server configuration from TOML files
//! - Process lifecycle management (start/stop/restart)
//! - Binary hash verification before execution
//! - Integration with capability-based authorization
//!
//! # Example
//!
//! ```rust,no_run
//! use astrid_mcp::{McpClient, ServersConfig, ServerConfig};
//!
//! # async fn example() -> Result<(), astrid_mcp::McpError> {
//! // Create configuration
//! let mut config = ServersConfig::default();
//! config.add(
//!     ServerConfig::stdio("filesystem", "npx")
//!         .with_args(["-y", "@anthropics/mcp-server-filesystem", "/tmp"])
//!         .auto_start()
//! )?;
//!
//! // Create client
//! let client = McpClient::with_config(config);
//!
//! // Connect to server
//! client.connect("filesystem").await?;
//!
//! // List available tools
//! let tools = client.list_tools().await?;
//! for tool in tools {
//!     println!("Tool: {}:{}", tool.server, tool.name);
//! }
//!
//! // Call a tool
//! let result = client.call_tool(
//!     "filesystem",
//!     "read_file",
//!     serde_json::json!({"path": "/tmp/test.txt"})
//! ).await?;
//!
//! println!("Result: {}", result.text_content());
//! # Ok(())
//! # }
//! ```

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![deny(unreachable_pub)]
#![deny(clippy::unwrap_used)]
#![cfg_attr(test, allow(clippy::unwrap_used))]

pub mod prelude;
/// Test helpers for constructing [`SecureMcpClient`] in test contexts.
/// Requires the `test-support` feature.
#[cfg(any(test, feature = "test-support"))]
pub mod testing;

pub(crate) mod capabilities;
mod client;
mod config;
mod error;
mod secure;
mod server;
mod server_process;
mod types;

pub use client::McpClient;
pub use config::{RestartPolicy, ServerConfig, ServersConfig, Transport, validate_server_name};
pub use error::{McpError, McpResult};
pub use secure::{SecureMcpClient, ToolAuthorization};
pub use server::ServerManager;
pub use types::{ToolContent, ToolDefinition, ToolResult};

// Re-export canonical elicitation types from astrid-core for convenience.
// These are the single source of truth — no duplicates in astrid-mcp.
pub use astrid_core::{
    ElicitationRequest, ElicitationResponse, ElicitationSchema, UrlElicitationRequest,
    UrlElicitationResponse, UrlElicitationType,
};
