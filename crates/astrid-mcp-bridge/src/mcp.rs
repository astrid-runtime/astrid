//! MCP server-side implementation.
//!
//! Task 6: holds a connected `DaemonConnection` plus a catalog of
//! tools built at startup via capsule-system introspection. The
//! catalog is returned verbatim from `list_tools`. Tool dispatch
//! (`call_tool` -> capsule IPC) lands in Task 7.
//!
//! We implement `ServerHandler` manually rather than via the
//! `#[tool_handler]` macro because that macro always injects its own
//! `list_tools`/`call_tool`/`get_tool` that delegate to the
//! `tool_router` — we want our catalog from capsule introspection
//! instead, and dispatch will route through IPC, not the router.

use std::sync::Arc;

use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler,
    model::{
        CallToolRequestParams, CallToolResult, Implementation, ListToolsResult,
        PaginatedRequestParams, ServerCapabilities, ServerInfo, Tool,
    },
    service::RequestContext,
};
use tokio::sync::Mutex;

use crate::daemon::DaemonConnection;
use crate::error::BridgeError;

/// MCP server exposed by `astrid mcp bridge`.
///
/// Cloneable (`rmcp` requires `Clone` on the handler): the daemon
/// connection sits behind an `Arc<Mutex<_>>` so we can serialize
/// writes from concurrent tool calls, and the catalog is an
/// `Arc<Vec<Tool>>` so clones share storage.
#[derive(Clone)]
pub struct AstridMcpServer {
    catalog: Arc<Vec<Tool>>,
    #[allow(dead_code)] // Used by Task 7's call_tool implementation.
    daemon: Arc<Mutex<DaemonConnection>>,
}

impl AstridMcpServer {
    /// Connect to the daemon, build the catalog by introspecting
    /// every installed capsule, then return a ready-to-serve handler.
    ///
    /// # Errors
    /// Propagates any [`BridgeError`] from catalog construction
    /// (timeout reaching capsule-system, malformed responses, etc.).
    pub async fn new(mut daemon: DaemonConnection) -> Result<Self, BridgeError> {
        let catalog = crate::catalog::build_catalog(&mut daemon).await?;
        Ok(Self {
            catalog: Arc::new(catalog),
            daemon: Arc::new(Mutex::new(daemon)),
        })
    }
}

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

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        Ok(ListToolsResult {
            meta: None,
            next_cursor: None,
            tools: (*self.catalog).clone(),
        })
    }

    async fn call_tool(
        &self,
        _request: CallToolRequestParams,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        // Tool dispatch is Task 7. Until then, surface a clear error.
        Err(McpError::method_not_found::<rmcp::model::CallToolRequestMethod>())
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        self.catalog.iter().find(|t| t.name == name).cloned()
    }
}
