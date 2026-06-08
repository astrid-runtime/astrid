//! MCP client implementation.
//!
//! Provides a high-level interface for interacting with MCP servers.

use rmcp::model::CallToolRequestParams;
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::capabilities::{CapabilitiesHandler, ServerNotice};
use crate::config::{ServerConfig, ServersConfig};
use crate::error::{McpError, McpResult};
use crate::server::ServerManager;
use crate::types::{ToolDefinition, ToolResult};

use tokio::sync::mpsc;

/// MCP client for interacting with MCP servers.
pub struct McpClient {
    /// Server manager.
    servers: Arc<ServerManager>,
    /// Cached tools from all servers.
    tools_cache: Arc<RwLock<Vec<ToolDefinition>>>,
    /// Capabilities handler for server-initiated requests.
    capabilities: Arc<CapabilitiesHandler>,
    /// Sender for server notifications (tools changed, etc.).
    ///
    /// Cloned into every `AstridClientHandler` so that `on_tool_list_changed`
    /// can push refreshed tools back here.
    notice_tx: mpsc::UnboundedSender<ServerNotice>,
}

impl McpClient {
    /// Create a new MCP client.
    #[must_use]
    pub fn new(servers: ServerManager) -> Self {
        let servers = Arc::new(servers);
        let tools_cache = Arc::new(RwLock::new(Vec::new()));

        let (notice_tx, notice_rx) = mpsc::unbounded_channel();

        let client = Self {
            servers: Arc::clone(&servers),
            tools_cache: Arc::clone(&tools_cache),
            capabilities: Arc::new(CapabilitiesHandler::new()),
            notice_tx,
        };

        // Spawn the background listener that processes server notifications.
        Self::spawn_notice_listener(notice_rx, Arc::clone(&servers), tools_cache);

        client
    }

    /// Create from default configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration cannot be loaded.
    pub fn from_default_config() -> McpResult<Self> {
        let servers = ServerManager::from_default_config()?;
        Ok(Self::new(servers))
    }

    /// Create with custom configuration.
    #[must_use]
    pub fn with_config(config: ServersConfig) -> Self {
        let servers = ServerManager::new(config);
        Self::new(servers)
    }

    /// Spawn a background task that listens for `ServerNotice` messages and
    /// updates the server manager + tools cache accordingly.
    fn spawn_notice_listener(
        mut rx: mpsc::UnboundedReceiver<ServerNotice>,
        servers: Arc<ServerManager>,
        tools_cache: Arc<RwLock<Vec<ToolDefinition>>>,
    ) {
        tokio::spawn(async move {
            while let Some(notice) = rx.recv().await {
                match notice {
                    ServerNotice::ToolsRefreshed { server_name, tools } => {
                        // Update the individual server's tool list.
                        if let Err(e) = servers.set_server_tools(&server_name, tools).await {
                            warn!(
                                server = %server_name,
                                error = %e,
                                "Failed to update server tools from notification"
                            );
                            continue;
                        }
                        // Rebuild the global tools cache.
                        let all = servers.all_tools().await;
                        let mut cache = tools_cache.write().await;
                        *cache = all;
                        info!(
                            server = %server_name,
                            "Tools cache refreshed from server notification"
                        );
                    },
                    ServerNotice::UplinksRegistered { server_name, .. } => {
                        // Uplink registrations are handled by McpPlugin
                        // via its own notice channel. Log and move on.
                        tracing::debug!(
                            server = %server_name,
                            "Ignoring UplinksRegistered in McpClient listener"
                        );
                    },
                }
            }
        });
    }

    /// Start a server and connect via the MCP protocol.
    ///
    /// # Errors
    ///
    /// Returns an error if the server cannot be started or connected.
    pub async fn connect(&self, server_name: &str) -> McpResult<()> {
        // Register the server if not already running
        if !self.servers.is_running(server_name).await {
            self.servers.start(server_name).await?;
        }

        // Establish the actual MCP connection
        self.servers
            .connect_server(
                server_name,
                self.capabilities.clone(),
                Some(self.notice_tx.clone()),
            )
            .await?;

        info!(server = server_name, "MCP connection established");

        // Refresh tools cache
        self.refresh_tools_cache().await?;

        Ok(())
    }

    /// Dynamically connect a new server using a provided configuration.
    ///
    /// # Errors
    /// Returns an error if the server is already running or cannot be started.
    pub async fn connect_dynamic(&self, name: &str, config: ServerConfig) -> McpResult<()> {
        self.servers.add_server(name, config).await?;

        self.servers
            .connect_server(
                name,
                self.capabilities.clone(),
                Some(self.notice_tx.clone()),
            )
            .await?;

        info!(server = name, "Dynamic MCP connection established");

        self.refresh_tools_cache().await?;

        Ok(())
    }

    /// Disconnect from a server.
    ///
    /// # Errors
    ///
    /// Returns an error if the server cannot be stopped.
    pub async fn disconnect(&self, server_name: &str) -> McpResult<()> {
        self.servers.stop(server_name).await?;
        self.refresh_tools_cache().await?;
        Ok(())
    }

    /// Connect to all auto-start servers.
    ///
    /// Returns the number of servers successfully connected.
    ///
    /// # Errors
    ///
    /// Returns an error only if refreshing the tools cache fails.
    /// Individual server connection failures are logged but do not abort
    /// the remaining servers.
    pub async fn connect_auto_servers(&self) -> McpResult<usize> {
        let names = self.servers.list_auto_start_names();
        let mut connected: usize = 0;

        for name in &names {
            match self.connect(name).await {
                Ok(()) => connected = connected.saturating_add(1),
                Err(e) => {
                    warn!(server = %name, error = %e, "Failed to auto-connect server");
                },
            }
        }

        self.refresh_tools_cache().await?;
        Ok(connected)
    }

    /// Disconnect from all servers.
    ///
    /// # Errors
    ///
    /// Returns an error if servers cannot be stopped.
    pub async fn disconnect_all(&self) -> McpResult<()> {
        self.servers.stop_all().await?;
        {
            let mut cache = self.tools_cache.write().await;
            cache.clear();
        }
        Ok(())
    }

    /// Shut down the client, disconnecting from all servers.
    ///
    /// # Errors
    ///
    /// Returns an error if disconnection fails.
    pub async fn shutdown(&self) -> McpResult<()> {
        self.disconnect_all().await
    }

    /// List all available tools.
    ///
    /// # Errors
    ///
    /// Returns an error if tools cannot be listed (currently infallible).
    pub async fn list_tools(&self) -> McpResult<Vec<ToolDefinition>> {
        let cache = self.tools_cache.read().await;
        Ok(cache.clone())
    }

    /// Get a specific tool definition.
    ///
    /// # Errors
    ///
    /// Returns an error if the tool cannot be retrieved (currently infallible).
    pub async fn get_tool(&self, server: &str, tool: &str) -> McpResult<Option<ToolDefinition>> {
        let cache = self.tools_cache.read().await;
        Ok(cache
            .iter()
            .find(|t| t.server == server && t.name == tool)
            .cloned())
    }

    /// Call a tool on a server.
    ///
    /// This is the low-level call without security checks.
    /// Use `SecureMcpClient` for authorized calls.
    ///
    /// # Errors
    ///
    /// Returns an error if the server is not running or the tool call fails.
    pub async fn call_tool(&self, server: &str, tool: &str, args: Value) -> McpResult<ToolResult> {
        // Verify server is running
        if !self.servers.is_running(server).await {
            return Err(McpError::ServerNotRunning {
                name: server.to_string(),
            });
        }

        debug!(server = server, tool = tool, "Calling MCP tool");

        // Get the peer and make the call
        let peer = self.servers.get_peer(server).await?;

        let arguments = match args {
            Value::Object(map) => Some(map),
            Value::Null => None,
            other => {
                // Wrap non-object values
                let mut map = serde_json::Map::new();
                map.insert("value".to_string(), other);
                Some(map)
            },
        };

        let mut params = CallToolRequestParams::new(tool.to_string());
        params.arguments = arguments;

        let result = peer
            .call_tool(params)
            .await
            .map_err(|e| McpError::ToolCallFailed {
                server: server.to_string(),
                tool: tool.to_string(),
                reason: e.to_string(),
            })?;

        info!(server = server, tool = tool, "Tool call completed");

        Ok(ToolResult::from(result))
    }

    /// Refresh the tools cache from all running servers.
    async fn refresh_tools_cache(&self) -> McpResult<()> {
        let tools = self.servers.all_tools().await;
        let mut cache = self.tools_cache.write().await;
        *cache = tools;
        Ok(())
    }

    /// List running servers.
    pub async fn list_servers(&self) -> Vec<String> {
        self.servers.list_running().await
    }

    /// Check if a server is running.
    pub async fn is_server_running(&self, name: &str) -> bool {
        self.servers.is_running(name).await
    }

    /// Get the server manager.
    #[must_use]
    pub fn server_manager(&self) -> &ServerManager {
        &self.servers
    }

    /// Reconnect a server (stop → start → connect).
    ///
    /// # Errors
    ///
    /// Returns an error if the server fails to restart or the tools cache
    /// cannot be refreshed.
    pub async fn reconnect(&self, name: &str) -> McpResult<()> {
        self.servers
            .restart(
                name,
                self.capabilities.clone(),
                Some(self.notice_tx.clone()),
            )
            .await?;
        self.refresh_tools_cache().await?;
        Ok(())
    }

    /// Atomically check the restart policy and reconnect if allowed.
    ///
    /// Returns `Ok(true)` if the server was restarted, `Ok(false)` if the
    /// restart policy forbids it.
    ///
    /// Prefer this over separate `should_restart()` + `reconnect()` calls to
    /// avoid TOCTOU races on the restart count.
    ///
    /// # Errors
    ///
    /// Returns an error if the restart itself fails.
    pub async fn try_reconnect(&self, name: &str) -> McpResult<bool> {
        let restarted = self
            .servers
            .restart_if_allowed(
                name,
                self.capabilities.clone(),
                Some(self.notice_tx.clone()),
            )
            .await?;
        if restarted {
            self.refresh_tools_cache().await?;
        }
        Ok(restarted)
    }

    /// Send a custom JSON-RPC notification to a running MCP server.
    ///
    /// This is fire-and-forget — notifications have no response. Used by the
    /// `McpHostEngine` to deliver hook events (e.g. `notifications/astrid.hookEvent`)
    /// to Tier 2 capsule processes.
    ///
    /// # Errors
    ///
    /// Returns an error if the server is not running or the notification cannot be sent.
    pub async fn send_notification(
        &self,
        server: &str,
        method: &str,
        params: Option<Value>,
    ) -> McpResult<()> {
        let peer = self.servers.get_peer(server).await?;

        let notification = rmcp::model::CustomNotification::new(method.to_string(), params);

        peer.send_notification(notification.into())
            .await
            .map_err(|e| McpError::ToolCallFailed {
                server: server.to_string(),
                tool: method.to_string(),
                reason: format!("failed to send notification: {e}"),
            })?;

        debug!(
            server = server,
            method = method,
            "Sent custom notification to MCP server"
        );

        Ok(())
    }
}

/// `McpClient` is cheaply cloneable — all fields are `Arc`-wrapped (or
/// cloneable senders), so clones share the same underlying `ServerManager`,
/// tools cache, capabilities handler, and notice channel.
impl Clone for McpClient {
    fn clone(&self) -> Self {
        Self {
            servers: Arc::clone(&self.servers),
            tools_cache: Arc::clone(&self.tools_cache),
            capabilities: Arc::clone(&self.capabilities),
            notice_tx: self.notice_tx.clone(),
        }
    }
}

impl std::fmt::Debug for McpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("McpClient")
            .field("servers", &self.servers)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_client_creation() {
        let config = ServersConfig::default();
        let client = McpClient::with_config(config);

        assert!(client.list_tools().await.unwrap().is_empty());
        assert!(client.list_servers().await.is_empty());
    }

    #[tokio::test]
    async fn test_tool_not_found() {
        let config = ServersConfig::default();
        let client = McpClient::with_config(config);

        let result = client.get_tool("server", "tool").await.unwrap();
        assert!(result.is_none());
    }
}
