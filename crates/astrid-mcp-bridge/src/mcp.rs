//! MCP server-side implementation. Stateless for Task 4 — returns
//! correct `server_info` and an empty tool catalog. Tool dispatch
//! lands in Task 6+.

use rmcp::{
    ServerHandler,
    handler::server::tool::ToolRouter,
    model::{Implementation, ServerCapabilities, ServerInfo},
    tool_handler, tool_router,
};

/// MCP server exposed by `astrid mcp bridge`.
///
/// Holds a `ToolRouter<Self>` populated by `#[tool_router]`. For
/// Task 4 the router is empty; later tasks will register one tool
/// method per capsule-exposed tool.
#[derive(Clone)]
pub struct AstridMcpServer {
    tool_router: ToolRouter<Self>,
}

impl AstridMcpServer {
    #[must_use]
    pub fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }
}

impl Default for AstridMcpServer {
    fn default() -> Self {
        Self::new()
    }
}

// Tool methods are added inside this impl in later tasks.
#[tool_router]
impl AstridMcpServer {
    // (empty for Task 4)
}

#[tool_handler]
impl ServerHandler for AstridMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            server_info: Implementation {
                name: "astrid-mcp-bridge".into(),
                version: env!("CARGO_PKG_VERSION").into(),
                ..Default::default()
            },
            instructions: Some(
                "Bridges Astrid OS capsule tools to MCP clients. \
                 All tool calls go through Astrid's capability, \
                 audit, and approval layer."
                    .into(),
            ),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }
}
