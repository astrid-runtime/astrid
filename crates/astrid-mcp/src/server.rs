//! MCP server lifecycle management.
//!
//! Handles starting, stopping, and managing MCP server processes.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use astrid_core::retry::RetryConfig;

use rmcp::service::{Peer, RoleClient, RunningService};
use rmcp::{ClientCacheConfig, ClientServiceExt};

use crate::capabilities::CapabilitiesHandler;
use crate::capabilities::{AstridClientHandler, ServerNotice};
use crate::config::{RestartPolicy, ServerConfig, ServersConfig, Transport};
use crate::error::{McpError, McpResult};
use crate::process_transport::OwnedProcessTransport;
use crate::server_process::{
    build_unsandboxed_command, mcp_client_lifecycle, today_date_string, wrap_process_tree,
};
use crate::types::{ServerInfo, ToolDefinition};

use tokio::sync::mpsc;

/// Type alias for a running MCP client service.
type McpService = RunningService<RoleClient, AstridClientHandler>;

/// A running MCP server instance.
pub(crate) struct RunningServer {
    /// Server configuration.
    pub config: ServerConfig,
    /// Running rmcp service (handles child process lifecycle).
    service: Option<McpService>,
    /// Server info after initialization.
    pub info: Option<ServerInfo>,
    /// Available tools.
    pub tools: Vec<ToolDefinition>,
    /// Whether the server is connected and ready.
    pub ready: bool,
    /// How many times this server has been restarted.
    pub restart_count: u32,
    /// When the last restart attempt was made (for backoff calculations).
    pub last_restart_attempt: Option<Instant>,
}

impl RunningServer {
    /// Create a new (not-yet-connected) running server.
    fn new(config: ServerConfig) -> Self {
        Self {
            config,
            service: None,
            info: None,
            tools: Vec::new(),
            ready: false,
            restart_count: 0,
            last_restart_attempt: None,
        }
    }

    /// Check if the server is still connected.
    pub(crate) fn is_alive(&self) -> bool {
        match &self.service {
            Some(svc) => !svc.is_closed(),
            None => false,
        }
    }

    /// Get a cloneable peer handle for making requests.
    pub(crate) fn peer(&self) -> Option<Peer<RoleClient>> {
        self.service.as_ref().map(|svc| svc.peer().clone())
    }
}

/// Manages MCP server lifecycles.
pub struct ServerManager {
    /// Server configurations.
    configs: ServersConfig,
    /// Running servers.
    running: Arc<RwLock<HashMap<String, RunningServer>>>,
    /// Warning threshold for a graceful shutdown that remains owned until done.
    shutdown_timeout: std::time::Duration,
    /// Workspace root for sandbox writable directory.
    ///
    /// When `None`, sandboxing falls back to `config.cwd` or a temp directory.
    workspace_root: Option<PathBuf>,
    /// Directory for capsule stderr log files.
    ///
    /// When set, MCP capsule server stderr is redirected to
    /// `{capsule_log_dir}/{capsule-name}.log`. When `None`, stderr is inherited.
    capsule_log_dir: Option<PathBuf>,
    /// Override for the sandbox availability policy.
    ///
    /// When `None`, [`ProcessSandboxConfig`] reads `ASTRID_SANDBOX_POLICY`
    /// from the environment (defaulting to [`SandboxPolicy::Required`]).
    /// Tests that exercise non-sandbox code paths set this to
    /// [`SandboxPolicy::Off`] so they don't depend on host `bwrap` /
    /// `AppArmor` state.
    sandbox_policy_override: Option<astrid_workspace::SandboxPolicy>,
}

impl ServerManager {
    /// Create a new server manager.
    #[must_use]
    pub fn new(configs: ServersConfig) -> Self {
        let shutdown_timeout = configs.shutdown_timeout;
        Self {
            configs,
            running: Arc::new(RwLock::new(HashMap::new())),
            shutdown_timeout,
            workspace_root: None,
            capsule_log_dir: None,
            sandbox_policy_override: None,
        }
    }

    /// Override the sandbox-availability policy for every command this
    /// manager builds. Intended for tests that need deterministic
    /// behaviour regardless of host `bwrap` / `AppArmor` state — production
    /// code paths should let [`ProcessSandboxConfig::new`] resolve the
    /// policy from `ASTRID_SANDBOX_POLICY`.
    #[must_use]
    pub fn with_sandbox_policy(mut self, policy: astrid_workspace::SandboxPolicy) -> Self {
        self.sandbox_policy_override = Some(policy);
        self
    }

    /// Set the workspace root directory for sandbox writable access.
    ///
    /// When sandboxing is active (`trusted: false`), the sandboxed process
    /// will have write access to this directory. If not set, falls back
    /// to the server's `cwd` or a system temp directory.
    #[must_use]
    pub fn with_workspace_root(mut self, root: PathBuf) -> Self {
        self.workspace_root = Some(root);
        self
    }

    /// Set the directory for capsule stderr log files.
    ///
    /// MCP capsule stderr will be redirected to `{dir}/{capsule-name}.log`.
    #[must_use]
    pub fn with_capsule_log_dir(mut self, dir: PathBuf) -> Self {
        self.capsule_log_dir = Some(dir);
        self
    }

    /// Create from default configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration cannot be loaded.
    pub fn from_default_config() -> McpResult<Self> {
        let configs = ServersConfig::load_default()?;
        Ok(Self::new(configs))
    }

    /// Get server configuration by name.
    #[must_use]
    pub fn get_config(&self, name: &str) -> Option<&ServerConfig> {
        self.configs.get(name)
    }

    /// List all configured servers.
    #[must_use]
    pub fn list_configured(&self) -> Vec<&str> {
        self.configs.list()
    }

    /// List running servers.
    pub async fn list_running(&self) -> Vec<String> {
        let running = self.running.read().await;
        running.keys().cloned().collect()
    }

    /// Check if a server is running.
    pub async fn is_running(&self, name: &str) -> bool {
        let running = self.running.read().await;
        running.contains_key(name)
    }

    /// Register a server in the running map (validates config, verifies binary).
    ///
    /// This does NOT establish the MCP connection; call `connect_server` for that.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The server is already running
    /// - The server configuration is not found
    /// - Binary verification fails
    pub async fn start(&self, name: &str) -> McpResult<()> {
        crate::config::validate_server_name(name)?;

        // Check if already running
        {
            let running = self.running.read().await;
            if running.contains_key(name) {
                return Err(McpError::ServerAlreadyRunning {
                    name: name.to_string(),
                });
            }
        }

        // Get configuration
        let config = self
            .configs
            .get(name)
            .ok_or_else(|| McpError::ServerNotFound {
                name: name.to_string(),
            })?
            .clone();

        info!(server = name, "Registering MCP server");

        // Verify binary hash if configured
        if let Err(e) = config.verify_binary() {
            error!(server = name, error = %e, "Binary verification failed");
            return Err(e);
        }

        // Store in running map (not yet connected)
        {
            let mut running = self.running.write().await;
            running.insert(name.to_string(), RunningServer::new(config));
        }

        Ok(())
    }

    /// Add a server configuration dynamically and register it.
    ///
    /// # Errors
    /// Returns an error if the server is already running.
    pub async fn add_server(&self, name: &str, config: ServerConfig) -> McpResult<()> {
        crate::config::validate_server_name(name)?;
        if name != config.name {
            return Err(McpError::ConfigError(format!(
                "server name mismatch: key '{name}' does not match config name '{}'",
                config.name
            )));
        }

        let mut running = self.running.write().await;
        if running.contains_key(name) {
            return Err(McpError::ServerAlreadyRunning {
                name: name.to_string(),
            });
        }

        info!(server = name, "Dynamically registering MCP server");

        if let Err(e) = config.verify_binary() {
            error!(server = name, error = %e, "Binary verification failed");
            return Err(e);
        }

        running.insert(name.to_string(), RunningServer::new(config));
        Ok(())
    }

    /// Establish the actual MCP connection for a registered server.
    ///
    /// Spawns the child process, performs the MCP handshake, and fetches
    /// the tool list from the server.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The server is not registered
    /// - The transport cannot be created
    /// - The MCP handshake fails
    pub(crate) async fn connect_server(
        &self,
        name: &str,
        handler: Arc<CapabilitiesHandler>,
        notice_tx: Option<mpsc::UnboundedSender<ServerNotice>>,
    ) -> McpResult<()> {
        let config = {
            let running = self.running.read().await;
            let server = running
                .get(name)
                .ok_or_else(|| McpError::ServerNotRunning {
                    name: name.to_string(),
                })?;
            server.config.clone()
        };

        let connected = match config.transport {
            Transport::Stdio => {
                self.connect_stdio_server(name, &config, handler, notice_tx)
                    .await
            },
            Transport::Sse => Err(McpError::ConfigError(
                "SSE transport not yet supported; enable `transport-streamable-http-client` \
                     feature in rmcp"
                    .to_string(),
            )),
        };

        if let Err(error) = connected {
            if let Err(cleanup_error) = self.stop(name).await {
                error!(
                    server = name,
                    connection_error = %error,
                    cleanup_error = %cleanup_error,
                    "Failed to clean up partially connected MCP server"
                );
            }
            return Err(error);
        }

        Ok(())
    }

    /// Connect to a stdio server via `TokioChildProcess`.
    async fn connect_stdio_server(
        &self,
        name: &str,
        config: &ServerConfig,
        handler: Arc<CapabilitiesHandler>,
        notice_tx: Option<mpsc::UnboundedSender<ServerNotice>>,
    ) -> McpResult<()> {
        let command = config.command.as_ref().ok_or_else(|| {
            McpError::ConfigError(format!("No command specified for stdio server {name}"))
        })?;

        let mut cmd = if config.trusted {
            build_unsandboxed_command(name, command, config)
        } else {
            self.build_sandboxed_command(name, command, config)?
        };

        // Redirect capsule stderr to a per-capsule daily log file if configured.
        if let Some(ref log_dir) = self.capsule_log_dir {
            let capsule_name = name.strip_prefix("capsule:").unwrap_or(name);
            let capsule_log_dir = log_dir.join(capsule_name);
            let _ = std::fs::create_dir_all(&capsule_log_dir);
            let today = today_date_string();
            let log_path = capsule_log_dir.join(format!("{today}.log"));
            if let Ok(file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_path)
            {
                cmd.stderr(file);
                info!(server = name, log = %log_path.display(), "Redirecting capsule stderr to log file");
            }
        }

        // Create transport (spawns the child process)
        let transport = OwnedProcessTransport::new(wrap_process_tree(cmd)).map_err(|e| {
            McpError::ServerStartFailed {
                name: name.to_string(),
                reason: e.to_string(),
            }
        })?;

        // Create the client handler and negotiate the newest lifecycle both
        // sides support, falling back only when the peer proves it is legacy.
        let mut client_handler = AstridClientHandler::new(name, handler);
        if let Some(tx) = notice_tx {
            client_handler = client_handler.with_notice_tx(tx);
        }
        let service = client_handler
            .serve_with_lifecycle(transport, mcp_client_lifecycle())
            .await
            .map_err(|e| {
                McpError::InitializationFailed(format!(
                    "MCP lifecycle negotiation failed for {name}: {e}"
                ))
            })?;

        // Astrid owns tool-inventory caching and invalidation. rmcp 3 enables
        // a response cache with stale-on-error fallback by default; disable it
        // so a server failure cannot resurrect a stale tool or capability view.
        service
            .peer()
            .set_response_cache_config(ClientCacheConfig::disabled())
            .await;

        // Read the protocol-neutral peer information negotiated by either the
        // legacy initialize handshake or modern server discovery lifecycle.
        let server_info = service
            .peer_info()
            .as_deref()
            .map(|info| ServerInfo::from_rmcp(info, name));

        // Fetch available tools
        let rmcp_tools = service.list_all_tools().await.map_err(McpError::from)?;
        let tools: Vec<ToolDefinition> = rmcp_tools
            .iter()
            .map(|t| ToolDefinition::from_rmcp(t, name))
            .collect();

        info!(
            server = name,
            tool_count = tools.len(),
            "MCP connection established"
        );

        // Store everything
        {
            let mut running = self.running.write().await;
            if let Some(server) = running.get_mut(name) {
                server.service = Some(service);
                server.info = server_info;
                server.tools = tools;
                server.ready = true;
            }
        }

        Ok(())
    }

    /// Build a sandboxed `tokio::process::Command` for an untrusted server.
    ///
    /// Applies OS-level sandboxing (bwrap on Linux, sandbox-exec on macOS),
    /// scrubs inherited environment variables, and hides `~/.astrid/`.
    #[allow(clippy::too_many_lines)]
    fn build_sandboxed_command(
        &self,
        name: &str,
        command: &str,
        config: &ServerConfig,
    ) -> McpResult<tokio::process::Command> {
        use astrid_workspace::ProcessSandboxConfig;

        // config.cwd doubles as both the sandbox writable root and the process CWD.
        // When set, the sandboxed process can write to its own working directory.
        // Fallback order: config.cwd > workspace_root > temp_dir/astrid-mcp/<name>
        let writable_root = config
            .cwd
            .as_ref()
            .or(self.workspace_root.as_ref())
            .cloned()
            .unwrap_or_else(|| std::env::temp_dir().join("astrid-mcp").join(name));

        // Validate writable_root and astrid_home against double-quote injection
        // (paths are interpolated into macOS Seatbelt SBPL profiles).
        Self::validate_sandbox_path(&writable_root, "writable_root (cwd)")?;

        // Ensure the writable root exists before bwrap tries to bind-mount it.
        std::fs::create_dir_all(&writable_root).map_err(|e| McpError::ServerStartFailed {
            name: name.to_string(),
            reason: format!(
                "Failed to create writable root {}: {e}",
                writable_root.display()
            ),
        })?;

        // Resolve ~/.astrid/ path - this is mandatory for untrusted servers.
        let astrid_home = Self::resolve_astrid_home()?;
        Self::validate_sandbox_path(&astrid_home, "astrid_home")?;

        // Build sandbox config
        let mut sandbox_config = ProcessSandboxConfig::new(&writable_root)
            .with_network(config.allow_network)
            .with_hidden(astrid_home);
        if let Some(policy) = self.sandbox_policy_override {
            sandbox_config = sandbox_config.with_policy(policy);
        }

        // Add config-specified extra paths. Validated for:
        // 1. Absolute (avoid ambiguity about which directory they resolve relative to)
        // 2. No double-quotes (prevent SBPL profile injection on macOS)
        for path in &config.allowed_read_paths {
            Self::validate_sandbox_path(path, "allowed_read_paths")?;
            sandbox_config = sandbox_config.with_extra_read(path);
        }
        for path in &config.allowed_write_paths {
            Self::validate_sandbox_path(path, "allowed_write_paths")?;
            sandbox_config = sandbox_config.with_extra_write(path);
        }

        // Add common package manager cache dirs as read-only so npm/cargo
        // don't re-download on every server start. Validate each path for
        // consistency (skip silently on failure - these are optional).
        if let Ok(home) = std::env::var("HOME") {
            for cache_dir in &[".npm", ".nvm", ".cargo", ".rustup"] {
                let cache_path = std::path::PathBuf::from(&home).join(cache_dir);
                if cache_path.exists()
                    && Self::validate_sandbox_path(&cache_path, "package manager cache").is_ok()
                {
                    sandbox_config = sandbox_config.with_extra_read(cache_path);
                }
            }
        }

        // Resolve absolute binary path so the sandbox doesn't depend on PATH.
        // The sandbox uses a fixed, minimal PATH that won't include nvm/pyenv/etc.
        // Resolution happens before sandbox_prefix() so we can add the binary's
        // parent directory to the sandbox read allowlist.
        let resolved_command = which::which(command).map_err(|e| McpError::ServerStartFailed {
            name: name.to_string(),
            reason: format!("Cannot resolve binary '{command}': {e}"),
        })?;
        Self::validate_sandbox_path(&resolved_command, "resolved binary")?;

        // Ensure the binary's parent directory is readable inside the sandbox.
        // On Linux bwrap --ro-bind / / covers all host paths, but macOS Seatbelt
        // only allows a fixed set of directories. Binaries from nvm/pyenv/etc.
        // live under $HOME which isn't in the default allowlist.
        // Canonicalize to follow symlinks so the real target's directory is allowed,
        // not just the symlink's directory.
        let canonical = match resolved_command.canonicalize() {
            Ok(path) => path,
            Err(e) => {
                warn!(
                    server = name,
                    path = %resolved_command.display(),
                    error = %e,
                    "Failed to canonicalize binary path; \
                     falling back to original. Sandbox may not have access to the binary."
                );
                resolved_command.clone()
            },
        };
        if let Some(bin_dir) = canonical.parent()
            && Self::validate_sandbox_path(bin_dir, "binary parent dir").is_ok()
        {
            sandbox_config = sandbox_config.with_extra_read(bin_dir);
        }

        // Get sandbox prefix (bwrap/sandbox-exec args).
        //
        // Under the default `SandboxPolicy::Required` policy this errors
        // out when the OS sandbox is unavailable — the error carries the
        // operator-facing remediation hint (sysctl command on Ubuntu
        // 24.04+, package-install on other distros, or explicit policy
        // override). We surface that message verbatim instead of wrapping
        // it in a misleading "path validation failed" label.
        //
        // Under `Off` the call returns `Ok(None)` silently. Either
        // way we don't double-log here.
        let sandbox_prefix =
            sandbox_config
                .sandbox_prefix()
                .map_err(|e| McpError::ServerStartFailed {
                    name: name.to_string(),
                    reason: e.to_string(),
                })?;

        // Build the command
        let mut cmd = if let Some(prefix) = sandbox_prefix {
            let mut cmd = tokio::process::Command::new(&prefix.program);
            for arg in &prefix.args {
                cmd.arg(arg);
            }
            cmd.arg(&resolved_command);
            cmd.args(&config.args);
            cmd
        } else {
            // Reached only when the operator explicitly opted into
            // `Off`, which is intentionally silent.
            let mut cmd = tokio::process::Command::new(&resolved_command);
            cmd.args(&config.args);
            cmd
        };

        // Environment scrubbing: clear inherited env, re-add safe vars.
        cmd.env_clear();

        // Use a fixed PATH so the parent process can't influence binary
        // resolution inside the sandbox. HOME/USER/SHELL/TERM/LANG are
        // identity/locale vars that are safe to forward from the parent.
        cmd.env("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin");
        for var in &["HOME", "USER", "SHELL", "TERM", "LANG"] {
            if let Ok(val) = std::env::var(var) {
                cmd.env(var, val);
            }
        }

        // Apply config env vars (filtered through blocklist)
        for (key, value) in &config.env {
            if astrid_core::env_policy::is_blocked_spawn_env(key) {
                warn!(
                    server = %name,
                    key = %key,
                    "Ignoring blocked env var from server config"
                );
                continue;
            }
            cmd.env(key, value);
        }

        // Always set CWD to the writable_root. If config.cwd was set, it was
        // used as writable_root (highest priority). Otherwise, the fallback
        // (workspace or temp dir) is used. This ensures the process CWD is
        // always a directory that exists and is accessible inside the sandbox.
        cmd.current_dir(&writable_root);

        info!(
            server = name,
            writable_root = %writable_root.display(),
            allow_network = config.allow_network,
            "Spawning sandboxed MCP server"
        );

        Ok(cmd)
    }

    /// Validate a path for use in sandbox configuration.
    ///
    /// Rejects relative paths, non-UTF-8 paths, and paths containing
    /// double-quote or null characters (which would break or bypass macOS
    /// Seatbelt SBPL profile syntax).
    fn validate_sandbox_path(path: &std::path::Path, field: &str) -> McpResult<()> {
        if !path.is_absolute() {
            return Err(McpError::ConfigError(format!(
                "{field} must be absolute, got: {}",
                path.display()
            )));
        }
        let s = path.to_str().ok_or_else(|| {
            McpError::ConfigError(format!("{field} is not valid UTF-8: {}", path.display()))
        })?;
        if s.contains(['"', '\0']) {
            return Err(McpError::ConfigError(format!(
                "{field} contains forbidden characters (double-quote or null): {}",
                path.display()
            )));
        }
        Ok(())
    }

    /// Resolve the `~/.astrid/` directory path.
    ///
    /// This is mandatory for untrusted servers - if we can't determine
    /// the path, we refuse to start the server rather than running it
    /// with `~/.astrid/` exposed.
    fn resolve_astrid_home() -> McpResult<std::path::PathBuf> {
        astrid_core::dirs::AstridHome::resolve()
            .map(|home| home.root().to_path_buf())
            .map_err(|_| McpError::ServerStartFailed {
                name: "sandbox".to_string(),
                reason: "Cannot determine ~/.astrid/ path for sandbox hiding. \
                         Set $HOME or $ASTRID_HOME, or mark the server as trusted."
                    .to_string(),
            })
    }

    /// Get a cloneable peer handle for a running server.
    ///
    /// # Errors
    ///
    /// Returns an error if the server is not running or not connected.
    pub async fn get_peer(&self, name: &str) -> McpResult<Peer<RoleClient>> {
        let running = self.running.read().await;
        let server = running
            .get(name)
            .ok_or_else(|| McpError::ServerNotRunning {
                name: name.to_string(),
            })?;

        server.peer().ok_or_else(|| {
            McpError::ConnectionFailed(format!("Server {name} is registered but not connected"))
        })
    }

    /// Stop a server.
    ///
    /// Performs a graceful shutdown on the MCP session before dropping the
    /// `RunningServer`. The configured timeout is only a warning threshold:
    /// after it elapses this method keeps owning and awaiting the same close
    /// future, because that future owns rmcp's process-tree termination.
    ///
    /// # Errors
    ///
    /// Returns an error if the server is not running.
    pub async fn stop(&self, name: &str) -> McpResult<()> {
        let server = {
            let mut running = self.running.write().await;
            running
                .remove(name)
                .ok_or_else(|| McpError::ServerNotRunning {
                    name: name.to_string(),
                })?
        };

        self.stop_owned(name, server).await
    }

    /// Close a server already removed from the running map.
    ///
    /// The map entry is removed before close so a slow process-tree teardown
    /// cannot make the old generation appear available for restart.
    async fn stop_owned(&self, name: &str, mut server: RunningServer) -> McpResult<()> {
        info!(server = name, "Stopping MCP server");

        // Gracefully close the MCP session before dropping. Never abandon this
        // future on a timeout: rmcp closes the transport here, and its child
        // transport is what kills and waits for the platform process tree.
        if let Some(ref mut service) = server.service {
            let close = service.close();
            tokio::pin!(close);
            let result = if self.shutdown_timeout.is_zero() {
                close.await
            } else {
                tokio::select! {
                    result = &mut close => result,
                    () = tokio::time::sleep(self.shutdown_timeout) => {
                        warn!(
                            server = name,
                            threshold_secs = self.shutdown_timeout.as_secs(),
                            "MCP session close exceeded warning threshold; continuing to await owned cleanup"
                        );
                        close.await
                    }
                }
            };
            match result {
                Ok(reason) => info!(server = name, ?reason, "MCP session closed gracefully"),
                Err(error) => {
                    return Err(McpError::ConnectionFailed(format!(
                        "MCP session close task failed for {name}: {error}"
                    )));
                },
            }
        }

        drop(server);

        Ok(())
    }

    /// Restart a server: stop → start → connect.
    ///
    /// Increments the restart counter for the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the server fails to start or connect.
    pub(crate) async fn restart(
        &self,
        name: &str,
        handler: Arc<CapabilitiesHandler>,
        notice_tx: Option<mpsc::UnboundedSender<ServerNotice>>,
    ) -> McpResult<()> {
        // Remember the previous restart count.
        let prev_count = {
            let running = self.running.read().await;
            running.get(name).map_or(0, |s| s.restart_count)
        };

        // Stop if running.
        if self.is_running(name).await {
            self.stop(name).await?;
        }

        // Register + connect.
        self.start(name).await?;
        self.connect_server(name, handler, notice_tx).await?;

        // Restore and increment restart count.
        let new_count = prev_count.saturating_add(1);
        {
            let mut running = self.running.write().await;
            if let Some(server) = running.get_mut(name) {
                server.restart_count = new_count;
            }
        }

        info!(server = name, restart_count = new_count, "Server restarted");
        Ok(())
    }

    /// Stop all servers.
    ///
    /// # Errors
    ///
    /// Returns `Ok(())` even if individual servers fail to stop (warnings are logged).
    pub async fn stop_all(&self) -> McpResult<()> {
        let names: Vec<String> = {
            let running = self.running.read().await;
            running.keys().cloned().collect()
        };

        for name in names {
            if let Err(e) = self.stop(&name).await {
                warn!(server = name, error = %e, "Failed to stop server");
            }
        }

        Ok(())
    }

    /// Start all auto-start servers.
    ///
    /// # Errors
    ///
    /// Returns `Ok(())` even if individual servers fail to start (warnings are logged).
    pub async fn start_auto_servers(&self) -> McpResult<()> {
        let auto_servers = self.configs.auto_start_servers();

        for config in auto_servers {
            if let Err(e) = self.start(&config.name).await {
                warn!(
                    server = config.name,
                    error = %e,
                    "Failed to auto-start server"
                );
            }
        }

        Ok(())
    }

    /// Update server tools after connection.
    ///
    /// # Errors
    ///
    /// Returns an error if the server is not running.
    pub async fn set_server_tools(&self, name: &str, tools: Vec<ToolDefinition>) -> McpResult<()> {
        let mut running = self.running.write().await;
        let server = running
            .get_mut(name)
            .ok_or_else(|| McpError::ServerNotRunning {
                name: name.to_string(),
            })?;

        server.tools = tools;

        Ok(())
    }

    /// Get all tools from all running servers.
    pub async fn all_tools(&self) -> Vec<ToolDefinition> {
        let running = self.running.read().await;
        running.values().flat_map(|s| s.tools.clone()).collect()
    }

    /// Check health of all running servers.
    pub async fn health_check(&self) -> HashMap<String, bool> {
        let running = self.running.read().await;
        let mut health = HashMap::new();

        for (name, server) in running.iter() {
            health.insert(name.clone(), server.is_alive());
        }

        health
    }

    /// Backoff configuration for restart attempts.
    ///
    /// Uses 30 s base delay, 5 min cap, exponential base 2.
    fn restart_backoff() -> RetryConfig {
        RetryConfig::new(
            u32::MAX, // max_attempts handled by RestartPolicy, not RetryConfig
            std::time::Duration::from_secs(30),
            std::time::Duration::from_mins(5),
            2.0,
        )
    }

    /// Check whether a dead server should be restarted based on its `RestartPolicy`.
    ///
    /// Also accounts for backoff cooldown — if the cooldown period for the
    /// current restart count has not elapsed, returns `false`.
    ///
    /// **Note:** This is a read-only query. For actual restarts, prefer
    /// [`restart_if_allowed`] which atomically checks the policy and
    /// performs the restart, avoiding TOCTOU races on `restart_count`.
    pub async fn should_restart(&self, name: &str) -> bool {
        let Some(config) = self.configs.get(name) else {
            return false;
        };

        let (restart_count, last_attempt) = {
            let running = self.running.read().await;
            running
                .get(name)
                .map_or((0, None), |s| (s.restart_count, s.last_restart_attempt))
        };

        let allowed = match &config.restart_policy {
            RestartPolicy::Never => false,
            RestartPolicy::OnFailure { max_retries } => restart_count < *max_retries,
            RestartPolicy::Always => true,
        };

        if !allowed {
            return false;
        }

        // Check backoff cooldown.
        if let Some(last) = last_attempt {
            let backoff = Self::restart_backoff();
            // restart_count is 0-indexed for attempts that already happened,
            // but delay_for_attempt(0) = ZERO, so use restart_count directly
            // (it represents the next attempt number).
            let required_delay = backoff.delay_for_attempt(restart_count);
            if last.elapsed() < required_delay {
                return false;
            }
        }

        true
    }

    /// Atomically check the restart policy and restart if allowed.
    ///
    /// Holds the write lock during the policy check *and* server removal,
    /// so concurrent callers cannot both pass the retry-limit check.
    /// The lock is released before I/O (process spawn, MCP handshake).
    ///
    /// Returns `Ok(true)` if the server was restarted, `Ok(false)` if the
    /// policy forbids it.
    ///
    /// # Errors
    ///
    /// Returns an error if the restart itself fails (start or connect).
    pub(crate) async fn restart_if_allowed(
        &self,
        name: &str,
        handler: Arc<CapabilitiesHandler>,
        notice_tx: Option<mpsc::UnboundedSender<ServerNotice>>,
    ) -> McpResult<bool> {
        let Some(config) = self.configs.get(name) else {
            return Ok(false);
        };

        let backoff = Self::restart_backoff();

        // Atomic: check policy + backoff + remove server under a single write lock.
        let (prev_count, previous_server) = {
            let mut running = self.running.write().await;
            let Some(server) = running.get(name) else {
                return Ok(false);
            };
            let count = server.restart_count;
            let last_attempt = server.last_restart_attempt;

            let allowed = match &config.restart_policy {
                RestartPolicy::Never => false,
                RestartPolicy::OnFailure { max_retries } => count < *max_retries,
                RestartPolicy::Always => true,
            };

            if !allowed {
                return Ok(false);
            }

            // Check backoff cooldown: if the required delay has not elapsed
            // since the last restart attempt, skip this restart.
            if let Some(last) = last_attempt {
                let required_delay = backoff.delay_for_attempt(count);
                if last.elapsed() < required_delay {
                    return Ok(false);
                }
            }

            let Some(server) = running.remove(name) else {
                return Ok(false);
            };
            // Removing while holding the lock prevents concurrent callers from
            // claiming the same retry slot; the owned server is closed after
            // the lock is released so teardown never blocks peer operations.
            (count, server)
        };
        self.stop_owned(name, previous_server).await?;
        // Write lock released. The server entry is gone, so any concurrent
        // caller will see restart_count = 0 (map_or default) but the server
        // is absent, and `start()` will re-register it fresh.

        // Re-register (validates config, verifies binary hash).
        self.start(name).await?;

        // Establish MCP connection (process spawn + handshake).
        if let Err(e) = self.connect_server(name, handler, notice_tx).await {
            // Clean up the registered-but-not-connected entry.
            let _ = self.stop(name).await;
            return Err(e);
        }

        // Set the incremented restart count and record the attempt timestamp.
        let new_count = prev_count.saturating_add(1);
        {
            let mut running = self.running.write().await;
            if let Some(server) = running.get_mut(name) {
                server.restart_count = new_count;
                server.last_restart_attempt = Some(Instant::now());
            }
        }

        info!(
            server = name,
            restart_count = new_count,
            "Server restarted (policy-allowed)"
        );
        Ok(true)
    }

    /// List names of servers configured for auto-start.
    #[must_use]
    pub fn list_auto_start_names(&self) -> Vec<String> {
        self.configs
            .auto_start_servers()
            .iter()
            .map(|c| c.name.clone())
            .collect()
    }

    /// Number of running servers.
    pub async fn running_count(&self) -> usize {
        self.running.read().await.len()
    }

    /// Number of configured servers.
    #[must_use]
    pub fn configured_count(&self) -> usize {
        self.configs.servers.len()
    }
}

impl std::fmt::Debug for ServerManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerManager")
            .field("configured_servers", &self.configs.list())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
#[path = "server_tests.rs"]
mod tests;
