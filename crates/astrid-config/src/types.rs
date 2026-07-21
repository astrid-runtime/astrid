//! Configuration types for the Astrid runtime.
//!
//! All types in this module are self-contained with no dependencies on other
//! internal astrid crates. Domain types are mirrored here and converted at
//! the boundary. Every struct implements [`Default`] with sensible production
//! defaults so that a bare `[section]` header in TOML produces a working
//! configuration.

use std::collections::HashMap;

use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Top-level Config
// ---------------------------------------------------------------------------

/// Root configuration for the Astrid runtime.
///
/// Loaded from layered TOML files (global, project, local) with environment
/// variable overrides. Every section defaults to safe, production-ready values.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// LLM model selection and pricing.
    pub model: ModelConfig,
    /// Runtime behaviour (context limits, summarisation).
    pub runtime: RuntimeSection,
    /// Signature requirements and approval timeout.
    pub security: SecurityConfig,
    /// Operator ceilings for the `astrid:http` host (timeouts, redirect/stream
    /// caps, buffered-body limit).
    pub http: HttpSection,
    /// Budget limits for sessions and individual actions.
    pub budget: BudgetSection,
    /// Rate-limiting knobs for elicitation and pending requests.
    pub rate_limits: RateLimitsConfig,
    /// Named MCP server definitions.
    pub servers: HashMap<String, ServerSection>,
    /// Audit log storage configuration.
    pub audit: AuditConfig,
    /// Paths to cryptographic key material.
    pub keys: KeysConfig,
    /// Workspace boundary and escape policy.
    pub workspace: WorkspaceSection,
    /// Git integration settings (branch strategy, auto-test).
    pub git: GitConfig,
    /// Hook execution policy.
    pub hooks: HooksSection,
    /// Logging level, format, and per-crate directives.
    pub logging: LoggingSection,
    /// Gateway daemon settings.
    pub gateway: GatewaySection,
    /// Timeout budgets for various operations.
    pub timeouts: TimeoutsSection,
    /// Session management limits and persistence.
    pub sessions: SessionsSection,
    /// Sub-agent pool limits.
    pub subagents: SubagentsSection,
    /// Capsule runtime concurrency ceilings (host-call semaphores, etc.).
    pub capsule: CapsuleSection,
    /// Retry behaviour for transient failures.
    pub retry: RetrySection,
    /// Agent identity seed (static fallback for spark.toml).
    pub spark: SparkSection,
    /// Pre-declared uplink plugins to validate at startup.
    pub uplinks: Vec<UplinkConfig>,
    /// Pre-configured platform identity links applied at every startup.
    pub identity: IdentitySection,
}

// ---------------------------------------------------------------------------
// ModelConfig
// ---------------------------------------------------------------------------

/// LLM provider selection, endpoint, and token pricing.
#[derive(Clone, Deserialize)]
#[serde(default)]
pub struct ModelConfig {
    /// Provider identifier (e.g. `"claude"`, `"openai"`).
    pub provider: String,
    /// Model name sent to the provider API.
    pub model: String,
    /// API key. Prefer environment variables over storing this in a file.
    #[serde(skip_serializing)]
    pub api_key: Option<String>,
    /// Base URL for the provider API (overrides the default endpoint).
    #[serde(skip_serializing)]
    pub api_url: Option<String>,
    /// Maximum tokens to request per completion.
    pub max_tokens: usize,
    /// Sampling temperature.
    pub temperature: f64,
    /// Context window size in tokens. When set, overrides the provider's
    /// built-in default for the model. Useful for OpenAI-compatible providers
    /// where the model name is not recognized.
    pub context_window: Option<usize>,
    /// Token pricing used for budget tracking.
    pub pricing: PricingConfig,
}

impl std::fmt::Debug for ModelConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModelConfig")
            .field("provider", &self.provider)
            .field("model", &self.model)
            .field("has_api_key", &self.api_key.is_some())
            .field("has_api_url", &self.api_url.is_some())
            .field("max_tokens", &self.max_tokens)
            .field("temperature", &self.temperature)
            .field("context_window", &self.context_window)
            .field("pricing", &self.pricing)
            .finish()
    }
}

impl Serialize for ModelConfig {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("ModelConfig", 6)?;
        state.serialize_field("provider", &self.provider)?;
        state.serialize_field("model", &self.model)?;
        // api_key and api_url are intentionally omitted.
        state.serialize_field("max_tokens", &self.max_tokens)?;
        state.serialize_field("temperature", &self.temperature)?;
        state.serialize_field("context_window", &self.context_window)?;
        state.serialize_field("pricing", &self.pricing)?;
        state.end()
    }
}

impl Default for ModelConfig {
    fn default() -> Self {
        Self {
            provider: "unknown".to_owned(),
            model: "unknown".to_owned(),
            api_key: None,
            api_url: None,
            max_tokens: 4096,
            temperature: 0.7,
            context_window: None,
            pricing: PricingConfig::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// PricingConfig
// ---------------------------------------------------------------------------

/// Per-token pricing used to compute spend against budget limits.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PricingConfig {
    /// USD cost per 1 million input tokens.
    pub input_per_million: f64,
    /// USD cost per 1 million output tokens.
    pub output_per_million: f64,
}

impl Default for PricingConfig {
    fn default() -> Self {
        Self {
            input_per_million: 3.0,
            output_per_million: 15.0,
        }
    }
}

// ---------------------------------------------------------------------------
// RuntimeSection
// ---------------------------------------------------------------------------

/// Runtime behaviour settings (context management, summarisation).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RuntimeSection {
    /// Maximum context window size in tokens before summarisation kicks in.
    pub max_context_tokens: usize,
    /// System prompt prepended to every conversation.
    pub system_prompt: String,
    /// Whether to automatically summarise older messages when the context
    /// window fills up.
    pub auto_summarize: bool,
    /// Number of recent messages to always keep verbatim (not summarised).
    pub keep_recent_count: usize,
}

impl Default for RuntimeSection {
    fn default() -> Self {
        Self {
            max_context_tokens: 100_000,
            system_prompt: String::new(),
            auto_summarize: true,
            keep_recent_count: 10,
        }
    }
}

// ---------------------------------------------------------------------------
// SecurityConfig
// ---------------------------------------------------------------------------

/// Top-level security settings (signatures, approval timeout).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SecurityConfig {
    /// Require ed25519 signatures for capability tokens and audit entries.
    pub require_signatures: bool,
    /// How long (in seconds) to wait for a human to respond to an approval
    /// request before timing out.
    pub approval_timeout_secs: u64,
    /// Operator-approved per-capsule local-egress allowlist.
    ///
    /// Maps a capsule id (the `Capsule.toml` `package.name`) to a list of
    /// `host:port` / `host:*` endpoints that are exempt from the host
    /// `astrid:http` SSRF airlock **for that capsule only** — the sanctioned
    /// way to let a specific capsule reach a loopback/private LLM endpoint
    /// (e.g. LM Studio on `127.0.0.1:1234`, Ollama on a LAN address). `host`
    /// may be an IP literal or a hostname; `port` is a decimal `u16` or `*`.
    ///
    /// Default empty = no exemptions (fail-closed). This is **operator
    /// config**: a capsule's own (untrusted) `Capsule.toml` cannot set it, and
    /// a project/workspace config layer cannot widen it (enforced in
    /// `merge::restrict`). It only *exempts* endpoints from the airlock; it
    /// never grants network access a capsule's manifest `net` allowlist
    /// doesn't already declare.
    pub capsule_local_egress: HashMap<String, Vec<String>>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            require_signatures: false,
            approval_timeout_secs: 300,
            capsule_local_egress: HashMap::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// HttpSection
// ---------------------------------------------------------------------------

/// Operator HTTP host policy for `astrid:http` (the SSRF-airlocked outbound HTTP
/// surface every capsule shares).
///
/// This is **operator policy**, set by the trust root: the operator MAY raise or
/// lower the soft limits (timeouts, redirect/stream caps) — raising them is
/// legitimate, not a violation. The fields play three distinct roles for a
/// per-request `request-options` value:
/// - the four **timeout fields** are per-request DEFAULTS, applied only when the
///   caller sets no corresponding `*-ms`; an explicit caller value OVERRIDES the
///   default and MAY be LARGER (e.g. a longer `total-ms` for a big download) —
///   they are not ceilings;
/// - `max_redirects` and `max_concurrent_streams` ARE caller ceilings — a caller
///   is clamped to them (may request fewer, never more);
/// - `max_response_bytes` is both a default and a caller ceiling, and is itself
///   hard-clamped by the request path to the absolute `MAX_GUEST_PAYLOAD_LEN`
///   payload limit — the one hard cap that even the operator cannot exceed.
///
/// The defaults reproduce the host's historical hardcoded constants exactly, so
/// an absent `[http]` section changes nothing.
///
/// **Operator config only.** Like `[security.capsule_local_egress]`, a
/// project/workspace config layer cannot set or widen these (enforced in
/// `merge::restrict`) — only the operator (the trust root) sets host HTTP policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct HttpSection {
    /// Default whole-request timeout (seconds) for the buffered path when the
    /// caller sets no `total-ms`. A per-request `total-ms` overrides it (and
    /// may be longer, for large downloads). Default: 30.
    pub default_timeout_secs: u64,
    /// Connect timeout (seconds) applied to the streaming path when the caller
    /// sets no `connect-ms`. Default: 30.
    pub stream_connect_timeout_secs: u64,
    /// Per-chunk read timeout (seconds) for streaming responses when the caller
    /// sets no `between-bytes-ms`. Default: 120.
    pub stream_read_timeout_secs: u64,
    /// Time-to-first-byte (header) deadline floor (seconds), applied on the
    /// streaming path when the caller set neither `first-byte-ms` nor a total
    /// timeout — bounds a server that accepts then hangs before sending
    /// headers, without cutting a slow-TTFT LLM stream. Default: 120.
    pub header_deadline_secs: u64,
    /// Maximum redirect hops the host will follow. A per-request
    /// `max-redirects` may request fewer, never more (it is clamped to this
    /// ceiling). Default: 10.
    pub max_redirects: u32,
    /// Per-capsule ceiling on concurrent HTTP streaming responses. The
    /// `max-active-http-streams` quota is checked per principal and globally
    /// against this value. Default: 4.
    pub max_concurrent_streams: u32,
    /// Default and caller ceiling (bytes) on a buffered response body. A
    /// per-request `max-response-bytes` may request a smaller cap, never a
    /// larger one. This operator value is itself hard-clamped by the request
    /// path to the host's absolute `MAX_GUEST_PAYLOAD_LEN` payload limit — the
    /// one hard cap the operator cannot exceed (raising this above it has no
    /// effect). Default: `10485760` (10 mebibytes).
    pub max_response_bytes: u64,
}

impl Default for HttpSection {
    /// The host's historical hardcoded constants — an absent `[http]` section
    /// reproduces today's behaviour exactly.
    fn default() -> Self {
        Self {
            default_timeout_secs: 30,
            stream_connect_timeout_secs: 30,
            stream_read_timeout_secs: 120,
            header_deadline_secs: 120,
            max_redirects: 10,
            max_concurrent_streams: 4,
            max_response_bytes: 10 * 1024 * 1024,
        }
    }
}

// ---------------------------------------------------------------------------
// BudgetSection
// ---------------------------------------------------------------------------

/// Spending limits that prevent runaway costs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BudgetSection {
    /// Maximum USD spend allowed for a single session.
    pub session_max_usd: f64,
    /// Maximum USD spend allowed for a single tool invocation.
    pub per_action_max_usd: f64,
    /// Percentage of `session_max_usd` at which to emit a warning.
    pub warn_at_percent: u8,
    /// Maximum cumulative USD spend across all sessions in a workspace.
    /// `None` means unlimited.
    pub workspace_max_usd: Option<f64>,
}

impl Default for BudgetSection {
    fn default() -> Self {
        Self {
            session_max_usd: 100.0,
            per_action_max_usd: 10.0,
            warn_at_percent: 80,
            workspace_max_usd: None,
        }
    }
}

// ---------------------------------------------------------------------------
// RateLimitsConfig
// ---------------------------------------------------------------------------

/// Rate-limiting settings to prevent server abuse and request floods.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RateLimitsConfig {
    /// Maximum elicitation requests allowed per MCP server per minute.
    pub elicitation_per_server_per_min: u32,
    /// Maximum number of pending (unanswered) approval requests across all
    /// servers.
    pub max_pending_requests: u32,
}

impl Default for RateLimitsConfig {
    fn default() -> Self {
        Self {
            elicitation_per_server_per_min: 10,
            max_pending_requests: 50,
        }
    }
}

// ---------------------------------------------------------------------------
// ServerSection
// ---------------------------------------------------------------------------

/// Policy for restarting a server when it dies (config-layer mirror).
///
/// This mirrors the domain `RestartPolicy` from `astrid-mcp` so that the
/// config crate stays dependency-free. The runtime config bridge converts
/// this into the domain type.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestartPolicyConfig {
    /// Never restart (default).
    #[default]
    Never,
    /// Restart on failure, up to `max_retries` times.
    OnFailure {
        /// Maximum number of restart attempts.
        #[serde(default = "default_max_retries")]
        max_retries: u32,
    },
    /// Always restart (no retry limit).
    Always,
}

fn default_max_retries() -> u32 {
    3
}

/// Configuration for a single MCP server.
#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerSection {
    /// Transport type (`"stdio"`, `"sse"`, `"streamable-http"`).
    pub transport: String,
    /// Command to launch the server (stdio transport).
    pub command: Option<String>,
    /// Arguments passed to `command`.
    pub args: Vec<String>,
    /// URL for network-based transports (SSE / streamable-http).
    pub url: Option<String>,
    /// Expected BLAKE3 hash of the server binary. When set, the runtime
    /// verifies the hash before launching.
    pub binary_hash: Option<String>,
    /// Extra environment variables passed to the server process.
    #[serde(skip_serializing)]
    pub env: HashMap<String, String>,
    /// Working directory for the server process.
    pub cwd: Option<String>,
    /// Whether to start the server automatically when the runtime boots.
    pub auto_start: bool,
    /// Human-readable description of what this server provides.
    pub description: Option<String>,
    /// Whether this server is trusted (runs natively with OS sandbox) or
    /// untrusted (must run in WASM).
    pub trusted: bool,
    /// Restart policy when the server process dies.
    pub restart_policy: RestartPolicyConfig,
}

impl std::fmt::Debug for ServerSection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let redacted_env: HashMap<&String, &str> = self.env.keys().map(|k| (k, "***")).collect();
        f.debug_struct("ServerSection")
            .field("transport", &self.transport)
            .field("command", &self.command)
            .field("args", &self.args)
            .field("url", &self.url)
            .field("binary_hash", &self.binary_hash)
            .field("env", &redacted_env)
            .field("cwd", &self.cwd)
            .field("auto_start", &self.auto_start)
            .field("description", &self.description)
            .field("trusted", &self.trusted)
            .field("restart_policy", &self.restart_policy)
            .finish()
    }
}

impl Default for ServerSection {
    fn default() -> Self {
        Self {
            transport: "stdio".to_owned(),
            command: None,
            args: Vec::new(),
            url: None,
            binary_hash: None,
            env: HashMap::new(),
            cwd: None,
            auto_start: false,
            description: None,
            trusted: false,
            restart_policy: RestartPolicyConfig::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// AuditConfig
// ---------------------------------------------------------------------------

/// Audit log storage settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AuditConfig {
    /// Path to the on-disk audit log. `None` means in-memory only.
    pub path: Option<String>,
    /// Maximum size of the audit log in megabytes before rotation.
    pub max_size_mb: u64,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            path: None,
            max_size_mb: 100,
        }
    }
}

// ---------------------------------------------------------------------------
// KeysConfig
// ---------------------------------------------------------------------------

/// Paths to cryptographic key material used for signatures and verification.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct KeysConfig {
    /// Path to the user's ed25519 private key file.
    pub user_key_path: Option<String>,
    /// Path to a directory or file containing trusted public keys.
    pub trusted_keys_path: Option<String>,
}

// ---------------------------------------------------------------------------
// WorkspaceSection
// ---------------------------------------------------------------------------

/// Operational workspace boundary and escape policy.
///
/// The workspace defines where the agent is allowed to operate by default.
/// Accesses outside the workspace boundary are governed by `escape_policy`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WorkspaceSection {
    /// Workspace mode: `"safe"` (default, ask for everything outside
    /// workspace), `"guided"` (auto-allow reads, ask for writes),
    /// `"autonomous"` (no restrictions), or `"yolo"` (alias for autonomous,
    /// for daring Astrinauts).
    pub mode: String,
    /// What to do when the agent tries to escape the workspace: `"ask"`
    /// (prompt the human), `"deny"` (always refuse), or `"allow"` (always
    /// permit).
    pub escape_policy: String,
    /// Path globs that are automatically allowed for read access without
    /// approval.
    pub auto_allow_read: Vec<String>,
    /// Path globs that are automatically allowed for write access without
    /// approval.
    pub auto_allow_write: Vec<String>,
    /// Paths that are never accessible regardless of mode or escape policy.
    pub never_allow: Vec<String>,
}

impl Default for WorkspaceSection {
    fn default() -> Self {
        Self {
            mode: "safe".to_owned(),
            escape_policy: "ask".to_owned(),
            auto_allow_read: Vec::new(),
            auto_allow_write: Vec::new(),
            never_allow: vec![
                "/etc".to_owned(),
                "/var".to_owned(),
                "/usr".to_owned(),
                "/bin".to_owned(),
                "/sbin".to_owned(),
                "/boot".to_owned(),
                "/root".to_owned(),
            ],
        }
    }
}

// ---------------------------------------------------------------------------
// GitConfig
// ---------------------------------------------------------------------------

/// Git integration settings controlling how completed work is delivered.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GitConfig {
    /// Completion strategy: `"merge"` (merge into target branch), `"pr"`
    /// (open a pull request), or `"branch-only"` (leave on feature branch).
    pub completion: String,
    /// Whether to run the project test suite automatically after changes.
    pub auto_test: bool,
    /// Whether to squash commits when completing work.
    pub squash: bool,
}

impl Default for GitConfig {
    fn default() -> Self {
        Self {
            completion: "merge".to_owned(),
            auto_test: false,
            squash: false,
        }
    }
}

// ---------------------------------------------------------------------------
// HooksSection
// ---------------------------------------------------------------------------

/// Hook execution policy. Controls which kinds of hooks are permitted and
/// global limits on hook execution.
#[expect(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct HooksSection {
    /// Master switch: when `false`, no hooks run at all.
    pub enabled: bool,
    /// Default timeout for hook execution in seconds.
    pub default_timeout_secs: u64,
    /// Maximum number of hooks that can be registered.
    pub max_hooks: usize,
    /// Allow hooks to run asynchronously (non-blocking).
    pub allow_async_hooks: bool,
    /// Allow hooks compiled to WASM.
    pub allow_wasm_hooks: bool,
    /// Allow hooks that spawn sub-agents.
    pub allow_agent_hooks: bool,
    /// Allow hooks that make HTTP requests.
    pub allow_http_hooks: bool,
    /// Allow hooks that execute shell commands.
    pub allow_command_hooks: bool,
}

impl Default for HooksSection {
    fn default() -> Self {
        Self {
            enabled: true,
            default_timeout_secs: 30,
            max_hooks: 100,
            allow_async_hooks: true,
            allow_wasm_hooks: false,
            allow_agent_hooks: false,
            allow_http_hooks: true,
            allow_command_hooks: true,
        }
    }
}

// ---------------------------------------------------------------------------
// LoggingSection
// ---------------------------------------------------------------------------

/// Logging and tracing configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggingSection {
    /// Global log level filter (`"trace"`, `"debug"`, `"info"`, `"warn"`,
    /// `"error"`).
    pub level: String,
    /// Output format: `"pretty"` (human-friendly), `"compact"` (one-line),
    /// `"json"` (structured), or `"full"` (verbose).
    pub format: String,
    /// Per-crate tracing directives (e.g. `["astrid_mcp=debug",
    /// "hyper=warn"]`).
    pub directives: Vec<String>,
}

impl Default for LoggingSection {
    fn default() -> Self {
        Self {
            level: "info".to_owned(),
            format: "compact".to_owned(),
            directives: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// GatewaySection
// ---------------------------------------------------------------------------

/// Gateway daemon configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GatewaySection {
    /// Directory for gateway runtime state (PID file, socket). `None` uses
    /// the platform default (e.g. `$XDG_STATE_HOME/astrid`).
    pub state_dir: Option<String>,
    /// Path to a secrets file for credential management.
    pub secrets_file: Option<String>,
    /// Whether to watch configuration files and reload on change.
    pub hot_reload: bool,
    /// Whether to watch plugin directories and hot-reload on file changes.
    pub watch_plugins: bool,
    /// Interval (in seconds) between health checks for managed servers.
    pub health_interval_secs: u64,
    /// Grace period (in seconds) for a clean shutdown before force-killing
    /// child processes.
    pub shutdown_timeout_secs: u64,
    /// Idle shutdown grace period (in seconds) for ephemeral mode. When all
    /// clients disconnect and the daemon remains idle for this duration, it
    /// shuts down automatically.
    pub idle_shutdown_secs: u64,
    /// Interval (in seconds) between stale session cleanup sweeps.
    pub session_cleanup_interval_secs: u64,
    /// When `true`, `send_input` publishes a `user.prompt` IPC event to the
    /// capsule pipeline instead of running the monolithic runtime turn.
    /// Default: `false`. Use for testing the capsule pipeline.
    pub use_capsule_pipeline: bool,
}

impl Default for GatewaySection {
    fn default() -> Self {
        Self {
            state_dir: None,
            secrets_file: None,
            hot_reload: true,
            watch_plugins: true,
            health_interval_secs: 30,
            shutdown_timeout_secs: 30,
            idle_shutdown_secs: 30,
            session_cleanup_interval_secs: 60,
            use_capsule_pipeline: false,
        }
    }
}

// ---------------------------------------------------------------------------
// TimeoutsSection
// ---------------------------------------------------------------------------

/// Timeout budgets for various operations. All values are in seconds.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TimeoutsSection {
    /// Maximum time for a single LLM request.
    pub request_secs: u64,
    /// Maximum time for a single tool invocation.
    pub tool_secs: u64,
    /// Maximum time for a sub-agent to complete its task.
    pub subagent_secs: u64,
    /// Maximum time to wait when connecting to an MCP server.
    pub mcp_connect_secs: u64,
    /// Maximum time to wait for a human to respond to an approval request.
    pub approval_secs: u64,
    /// Time after which an idle session is automatically closed.
    pub idle_secs: u64,
}

impl Default for TimeoutsSection {
    fn default() -> Self {
        Self {
            request_secs: 120,
            tool_secs: 60,
            subagent_secs: 300,
            mcp_connect_secs: 10,
            approval_secs: 300,
            idle_secs: 3600,
        }
    }
}

// ---------------------------------------------------------------------------
// SessionsSection
// ---------------------------------------------------------------------------

/// Session management limits and persistence settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SessionsSection {
    /// Maximum number of concurrent sessions per user.
    pub max_per_user: usize,
    /// Maximum number of messages retained in session history.
    pub history_limit: usize,
    /// Interval (in seconds) between automatic session state saves.
    pub save_interval_secs: u64,
    /// Whether to persist session state to disk across restarts.
    pub persist: bool,
}

impl Default for SessionsSection {
    fn default() -> Self {
        Self {
            max_per_user: 10,
            history_limit: 100,
            save_interval_secs: 60,
            persist: true,
        }
    }
}

// ---------------------------------------------------------------------------
// SubagentsSection
// ---------------------------------------------------------------------------

/// Sub-agent pool limits and defaults.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SubagentsSection {
    /// Maximum number of sub-agents running concurrently.
    pub max_concurrent: usize,
    /// Maximum nesting depth for recursive sub-agent delegation.
    pub max_depth: usize,
    /// Default timeout for a sub-agent task in seconds.
    pub timeout_secs: u64,
}

impl Default for SubagentsSection {
    fn default() -> Self {
        Self {
            max_concurrent: 5,
            max_depth: 3,
            timeout_secs: 300,
        }
    }
}

// ---------------------------------------------------------------------------
// CapsuleSection
// ---------------------------------------------------------------------------

/// Capsule runtime tuning knobs (host-call concurrency ceilings).
///
/// Every field is `Option`: `None` means "use the host-derived default" (the
/// daemon reads CPU cores / the file-descriptor limit at boot). An explicit
/// value overrides that default. This is the config-file layer of the
/// precedence chain CLI flag > config file > `ASTRID_CAPSULE_*` env > host
/// default; the daemon merges the layers and hands the resolved ceilings to the
/// kernel.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct CapsuleSection {
    /// Ceiling on concurrent **blocking** host calls (`block_in_place` +
    /// `block_on`: KV, identity, sys, fs, the net/process security gates, DNS,
    /// sockets). `None` → roughly `cores - 2`. Keep this near the worker-pool
    /// size; too high and blocking host work starves the tokio scheduler.
    pub host_blocking_concurrency: Option<usize>,
    /// Ceiling on concurrent **async-I/O** host calls (HTTP, `ipc::recv` —
    /// calls that `.await` real I/O and free the worker). `None` →
    /// cores-scaled, clamped by half the process file-descriptor limit. This is
    /// the outbound-throughput gate the LLM path rides on; sizing it well above
    /// the blocking ceiling is the point of the split.
    pub host_io_concurrency: Option<usize>,
    /// **Max** size of a capsule's dynamic instance pool — the ceiling on its
    /// concurrent interceptor invocations. `None` → cores-scaled (replacing the
    /// old fixed 16). The pool warm-starts well below this and grows lazily, so
    /// this bounds the peak, not the resting footprint. (Run-loop and
    /// `host_process` capsules stay single-Store regardless.)
    pub instance_pool_size: Option<usize>,
    /// Aggregate generic compute workers per principal across all capsules.
    /// `None` adds no operator cap; the principal profile still applies.
    pub compute_max_workers_per_principal: Option<u32>,
    /// Aggregate generic compute shared memory per principal, in bytes.
    /// `None` adds no operator cap; the principal profile still applies.
    pub compute_max_shared_memory_bytes_per_principal: Option<u64>,
    /// Maximum Wasmtime fuel for one generic compute job. `None` leaves jobs
    /// uncapped by Astrid policy; cancellation remains epoch-interruptible.
    pub compute_max_job_fuel: Option<u64>,
    /// Workers admitted across all principals and capsules in this daemon.
    /// `None` derives the pool from the host's available parallelism.
    pub compute_host_max_workers: Option<u32>,
    /// Shared-memory bytes admitted across all principals and capsules in this
    /// daemon. `None` derives the pool from host RAM with a safety reserve.
    pub compute_host_max_shared_memory_bytes: Option<u64>,
}

// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// RetrySection
// ---------------------------------------------------------------------------

/// Retry behaviour for transient failures (LLM and MCP requests).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RetrySection {
    /// Maximum retry attempts for LLM requests.
    pub llm_max_attempts: u32,
    /// Maximum retry attempts for MCP connections.
    pub mcp_max_attempts: u32,
    /// Initial retry delay in milliseconds.
    pub initial_delay_ms: u64,
    /// Maximum retry delay in milliseconds.
    pub max_delay_ms: u64,
}

impl Default for RetrySection {
    fn default() -> Self {
        Self {
            llm_max_attempts: 3,
            mcp_max_attempts: 5,
            initial_delay_ms: 100,
            max_delay_ms: 10_000,
        }
    }
}

// ---------------------------------------------------------------------------
// SparkSection
// ---------------------------------------------------------------------------

/// Agent identity seed configuration.
///
/// Provides a static fallback for the living `spark.toml` file. Fields set here
/// are used when no `spark.toml` exists yet. Once the agent evolves its spark,
/// `spark.toml` takes priority.
///
/// All fields default to empty strings (no identity configured).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SparkSection {
    /// Agent's name (e.g. "Stellar", "Nova", "Orion").
    pub callsign: String,
    /// Role archetype (e.g. "navigator", "engineer", "sentinel").
    pub class: String,
    /// Personality energy (e.g. "calm", "sharp", "warm", "analytical").
    pub aura: String,
    /// Communication style (e.g. "formal", "concise", "casual", "poetic").
    pub signal: String,
    /// Soul/philosophy — free-form values, learned patterns, personality depth.
    pub core: String,
}

impl SparkSection {
    /// Returns `true` when all fields are empty (no identity configured).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.callsign.is_empty()
            && self.class.is_empty()
            && self.aura.is_empty()
            && self.signal.is_empty()
            && self.core.is_empty()
    }
}

// ---------------------------------------------------------------------------
// UplinkConfig
// ---------------------------------------------------------------------------

/// Pre-declared uplink plugin entry.
///
/// Entries in `[[uplinks]]` declare which uplink plugins should be
/// available and which behavioural profile they should expose. At startup, the
/// daemon validates that each declared plugin is loaded and exposes a uplink
/// with the expected profile.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct UplinkConfig {
    /// Plugin ID (e.g. `"telegram-uplink"`).
    pub plugin: String,
    /// Expected uplink profile: `"chat"`, `"interactive"`, `"notify"`, or
    /// `"bridge"`. Unknown values are logged and default to `"chat"`.
    pub profile: String,
}

// ---------------------------------------------------------------------------
// IdentitySection
// ---------------------------------------------------------------------------

/// Pre-configured platform identity links.
///
/// Entries in `[[identity.links]]` are applied on every daemon startup, making
/// config-driven identity links effectively persistent across restarts without
/// requiring manual re-pairing.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct IdentitySection {
    /// Identity links to apply on startup.
    pub links: Vec<IdentityLinkConfig>,
}

/// A single pre-configured identity link.
///
/// Maps a platform-specific user ID to a canonical Astrid user identity.
/// Applied at daemon startup via admin linking.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct IdentityLinkConfig {
    /// Platform identifier (e.g. `"telegram"`, `"discord"`).
    pub platform: String,
    /// Platform-specific user ID (e.g. a Telegram numeric ID as a string).
    pub platform_user_id: String,
    /// Astrid user to link — UUID string or display name.
    pub astrid_user: String,
    /// Link verification method. Only `"admin"` is currently supported.
    /// Defaults to `"admin"` when omitted.
    #[serde(default = "default_link_method")]
    pub method: String,
}

fn default_link_method() -> String {
    "admin".to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restart_policy_config_default_is_never() {
        let policy = RestartPolicyConfig::default();
        assert_eq!(policy, RestartPolicyConfig::Never);
    }

    #[test]
    fn restart_policy_config_parse_never() {
        let toml = r#"
[servers.test]
command = "cmd"
restart_policy = "never"
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert_eq!(
            cfg.servers["test"].restart_policy,
            RestartPolicyConfig::Never
        );
    }

    #[test]
    fn restart_policy_config_parse_always() {
        let toml = r#"
[servers.test]
command = "cmd"
restart_policy = "always"
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert_eq!(
            cfg.servers["test"].restart_policy,
            RestartPolicyConfig::Always
        );
    }

    #[test]
    fn restart_policy_config_parse_on_failure() {
        let toml = r#"
[servers.test]
command = "cmd"

[servers.test.restart_policy]
on_failure = { max_retries = 7 }
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert_eq!(
            cfg.servers["test"].restart_policy,
            RestartPolicyConfig::OnFailure { max_retries: 7 }
        );
    }

    #[test]
    fn restart_policy_config_on_failure_default_retries() {
        let toml = r#"
[servers.test]
command = "cmd"

[servers.test.restart_policy]
on_failure = {}
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert_eq!(
            cfg.servers["test"].restart_policy,
            RestartPolicyConfig::OnFailure { max_retries: 3 }
        );
    }

    #[test]
    fn restart_policy_config_omitted_defaults_to_never() {
        let toml = r#"
[servers.test]
command = "cmd"
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert_eq!(
            cfg.servers["test"].restart_policy,
            RestartPolicyConfig::Never
        );
    }

    #[test]
    fn server_section_default_has_restart_policy_never() {
        let section = ServerSection::default();
        assert_eq!(section.restart_policy, RestartPolicyConfig::Never);
    }

    #[test]
    fn spark_section_default_is_empty() {
        let spark = SparkSection::default();
        assert!(spark.is_empty());
    }

    #[test]
    fn spark_section_parses_from_config() {
        let toml = r#"
[spark]
callsign = "Stellar"
class = "navigator"
aura = "calm"
signal = "concise"
core = "I value clarity."
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert_eq!(cfg.spark.callsign, "Stellar");
        assert_eq!(cfg.spark.class, "navigator");
        assert_eq!(cfg.spark.aura, "calm");
        assert_eq!(cfg.spark.signal, "concise");
        assert_eq!(cfg.spark.core, "I value clarity.");
        assert!(!cfg.spark.is_empty());
    }

    #[test]
    fn spark_section_omitted_defaults_to_empty() {
        let toml = "[model]\nprovider = \"claude\"\n";
        let cfg: Config = toml::from_str(toml).unwrap();
        assert!(cfg.spark.is_empty());
    }

    #[test]
    fn test_uplinks_parse() {
        let toml = r#"
[[uplinks]]
plugin = "telegram-uplink"
profile = "chat"

[[uplinks]]
plugin = "discord-uplink"
profile = "bridge"
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert_eq!(cfg.uplinks.len(), 2);
        assert_eq!(cfg.uplinks[0].plugin, "telegram-uplink");
        assert_eq!(cfg.uplinks[0].profile, "chat");
        assert_eq!(cfg.uplinks[1].plugin, "discord-uplink");
        assert_eq!(cfg.uplinks[1].profile, "bridge");
    }

    #[test]
    fn test_identity_links_parse() {
        let toml = r#"
[[identity.links]]
platform = "telegram"
platform_user_id = "123456"
astrid_user = "josh"
method = "admin"
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert_eq!(cfg.identity.links.len(), 1);
        let link = &cfg.identity.links[0];
        assert_eq!(link.platform, "telegram");
        assert_eq!(link.platform_user_id, "123456");
        assert_eq!(link.astrid_user, "josh");
        assert_eq!(link.method, "admin");
    }

    #[test]
    fn test_backward_compat_no_new_sections() {
        let toml = "[model]\nprovider = \"claude\"\n";
        let cfg: Config = toml::from_str(toml).unwrap();
        assert!(cfg.uplinks.is_empty());
        assert!(cfg.identity.links.is_empty());
    }

    #[test]
    fn test_default_link_method() {
        let toml = r#"
[[identity.links]]
platform = "discord"
platform_user_id = "999"
astrid_user = "alice"
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert_eq!(cfg.identity.links[0].method, "admin");
    }

    #[test]
    fn test_http_section_defaults_match_host_constants() {
        // An absent [http] section must reproduce the host's historical
        // hardcoded constants exactly (defaults change nothing).
        let cfg: Config = toml::from_str("[model]\nprovider = \"claude\"\n").unwrap();
        let h = &cfg.http;
        assert_eq!(h.default_timeout_secs, 30);
        assert_eq!(h.stream_connect_timeout_secs, 30);
        assert_eq!(h.stream_read_timeout_secs, 120);
        assert_eq!(h.header_deadline_secs, 120);
        assert_eq!(h.max_redirects, 10);
        assert_eq!(h.max_concurrent_streams, 4);
        assert_eq!(h.max_response_bytes, 10 * 1024 * 1024);
        // The struct Default and the serde(default) for an absent section agree.
        let d = HttpSection::default();
        assert_eq!(d.default_timeout_secs, h.default_timeout_secs);
        assert_eq!(d.max_response_bytes, h.max_response_bytes);
    }

    #[test]
    fn test_http_section_parses_operator_overrides() {
        let toml = "[http]\ndefault_timeout_secs = 5\nmax_redirects = 3\n\
                    max_concurrent_streams = 2\nmax_response_bytes = 4096\n";
        let cfg: Config = toml::from_str(toml).unwrap();
        assert_eq!(cfg.http.default_timeout_secs, 5);
        assert_eq!(cfg.http.max_redirects, 3);
        assert_eq!(cfg.http.max_concurrent_streams, 2);
        assert_eq!(cfg.http.max_response_bytes, 4096);
        // Unset fields keep their defaults (partial [http] section).
        assert_eq!(cfg.http.stream_read_timeout_secs, 120);
        assert_eq!(cfg.http.header_deadline_secs, 120);
    }
}
