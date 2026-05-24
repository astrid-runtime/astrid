//! MCP server-side implementation.
//!
//! Task 6: holds a connected `DaemonConnection` plus a catalog of
//! tools built at startup via capsule-system introspection. The
//! catalog is returned verbatim from `list_tools`.
//!
//! Task 7: `call_tool` translates the MCP request into an Astrid
//! `ToolExecuteRequest`, round-trips through capsule-cli to the
//! owning capsule, and maps the returned `ToolCallResult` to an
//! MCP `CallToolResult`.
//!
//! We implement `ServerHandler` manually rather than via the
//! `#[tool_handler]` macro because that macro always injects its own
//! `list_tools`/`call_tool`/`get_tool` that delegate to the
//! `tool_router` — we want our catalog from capsule introspection
//! instead, and dispatch routes through IPC, not the router.

use std::sync::Arc;
use std::time::Duration;

use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler,
    model::{
        CallToolRequestParams, CallToolResult, Content, Implementation, ListToolsResult,
        PaginatedRequestParams, ServerCapabilities, ServerInfo, Tool,
    },
    service::RequestContext,
};
use tokio::sync::Mutex;

use crate::daemon::DaemonConnection;
use crate::error::BridgeError;

/// Per-call timeout for forwarded tool execution. Mirrors the default
/// Claude Code expects; capsule-side operations longer than this will
/// surface as timeout errors back to the MCP client.
const TOOL_CALL_TIMEOUT: Duration = Duration::from_secs(60);

/// MCP server exposed by `astrid mcp bridge`.
///
/// Cloneable (`rmcp` requires `Clone` on the handler): the daemon
/// connection sits behind an `Arc<Mutex<_>>` so we can serialize
/// writes from concurrent tool calls, and the catalog is an
/// `Arc<Vec<Tool>>` so clones share storage.
#[derive(Clone)]
pub struct AstridMcpServer {
    catalog: Arc<Vec<Tool>>,
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
        request: CallToolRequestParams,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        // 1. Validate the tool exists in our cached catalog. The
        //    catalog exposes tools as `<short_capsule>.<tool_name>`
        //    (built in catalog::build_catalog), so the MCP-facing
        //    name always carries that prefix.
        let mcp_name = request.name.as_ref();
        if !self.catalog.iter().any(|t| t.name == mcp_name) {
            return Err(McpError::internal_error(
                format!("unknown tool: {mcp_name}"),
                None,
            ));
        }

        // 2. Recover the on-bus tool name by stripping the capsule
        //    prefix. The Astrid IPC topic is `tool.v1.execute.<tool_name>`
        //    and capsule tools register under just `<tool_name>`.
        let internal_name = mcp_name.split_once('.').map(|(_, rest)| rest).ok_or_else(|| {
            McpError::internal_error(format!("malformed catalog entry: {mcp_name}"), None)
        })?;

        // 3. MCP gives us arguments as Option<JsonObject> (a
        //    serde_json::Map); wrap as Value::Object for the IPC
        //    payload. Missing arguments → empty object (matches what
        //    capsules expect from their argument deserializers).
        let args = serde_json::Value::Object(request.arguments.unwrap_or_default());

        // 4. Round-trip through the daemon. Hold the lock only for
        //    the duration of the send + recv loop — other tool calls
        //    on the same connection serialize behind us.
        let result = {
            let mut daemon = self.daemon.lock().await;
            daemon
                .call_tool_round_trip(internal_name, args, TOOL_CALL_TIMEOUT)
                .await
        }
        .map_err(|e| McpError::internal_error(format!("{e}"), None))?;

        // 5. Map the Astrid ToolCallResult to MCP CallToolResult.
        //    The capsule already discriminated success vs error via
        //    is_error; preserve that flag verbatim.
        Ok(CallToolResult {
            content: vec![Content::text(result.content)],
            structured_content: None,
            is_error: Some(result.is_error),
            meta: None,
        })
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        self.catalog.iter().find(|t| t.name == name).cloned()
    }
}
