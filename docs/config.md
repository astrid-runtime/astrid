# Configuration Reference

Astrid uses a layered configuration system powered by TOML. Configuration is loaded in the following order (each layer overrides the previous):

1. **Defaults** (Embedded in binary — safe production values)
2. **System Config** (`/etc/astrid/config.toml`)
3. **User Config** (`~/.astrid/config.toml` or `$ASTRID_HOME/config.toml`)
4. **Workspace Config** (`.astrid/config.toml` in the project root — can only **tighten** security, never loosen)
5. **Environment Variables** (`ASTRID_*`, `ANTHROPIC_*` — fill in unset fields only, do not override)

## Connectors

Pre-declare connectors to be validated at startup. This ensures that essential communication channels (like Telegram or Discord bots) are loaded and ready.

```toml
[[connectors]]
plugin = "telegram-uplink"
profile = "chat"

[[connectors]]
plugin = "discord-uplink"
profile = "bridge"
```

| Field | Type | Description |
|---|---|---|
| `plugin` | string | The ID of the plugin providing the connector (e.g., `"telegram-uplink"`). |
| `profile` | string | The expected behavioral profile: `"chat"`, `"interactive"`, `"notify"`, or `"bridge"`. |

## Identity Links

Pre-configure identity links to map platform-specific user IDs to Astrid identities. These are applied at startup, making them effectively persistent even if the underlying identity store is in-memory.

```toml
[[identity.links]]
platform = "telegram"
platform_user_id = "123456789"
astrid_user = "josh"
method = "admin"
```

| Field | Type | Description |
|---|---|---|
| `platform` | string | The platform identifier (e.g., `"telegram"`, `"discord"`). |
| `platform_user_id` | string | The user ID on the external platform. |
| `astrid_user` | string | The Astrid identity to link to. Can be a UUID or a display name (which will be resolved or created). |
| `method` | string | Verification method. Currently only `"admin"` is supported. |

## Model

Configure the LLM provider and model parameters.

```toml
[model]
provider = "claude"
model = "claude-sonnet-4-20250514"
max_tokens = 4096
temperature = 0.7
# api_key = ""  # Optional: use env var ANTHROPIC_API_KEY instead
# api_url = ""  # Optional: custom endpoint for proxies or local models
# context_window = 200000  # Optional: override provider's context window size

[model.pricing]
input_per_million = 3.0
output_per_million = 15.0
```

| Field | Type | Description |
|---|---|---|
| `provider` | string | The model provider (e.g., `"claude"`). |
| `model` | string | The model identifier sent to the API. |
| `max_tokens` | integer | Maximum tokens to generate per response. |
| `temperature` | float | Sampling temperature (0.0 - 1.0). |
| `api_key` | string | (Optional) API key. Prefer env var `ANTHROPIC_API_KEY`. |
| `api_url` | string | (Optional) Base URL for proxies or alternative endpoints. |
| `context_window` | integer | (Optional) Override the provider's default context window size. |
| `pricing.input_per_million` | float | USD per million input tokens (for budget tracking). |
| `pricing.output_per_million` | float | USD per million output tokens (for budget tracking). |

## Runtime

Control context management and summarization behavior.

```toml
[runtime]
max_context_tokens = 100000
system_prompt = ""  # Leave empty to use the dynamic prompt
auto_summarize = true
keep_recent_count = 10
```

## Security & Policy

Define the security boundary for the agent.

```toml
[security]
require_signatures = false
approval_timeout_secs = 300

[security.policy]
blocked_tools = ["rm -rf /", "sudo"]
approval_required_tools = []
allowed_paths = []
denied_paths = ["/etc/**", "/boot/**", "/sys/**"]
allowed_hosts = []
denied_hosts = []
require_approval_for_delete = true
require_approval_for_network = true
max_argument_size = 1048576
```

| Field | Type | Description |
|---|---|---|
| `require_signatures` | bool | Require ed25519 signatures on user inputs. |
| `approval_timeout_secs` | integer | Seconds before an unanswered approval request is denied. |
| `policy.blocked_tools` | list | Tool invocations that are always blocked. |
| `policy.approval_required_tools` | list | Tools that always require approval, even with capability tokens. |
| `policy.allowed_paths` | list | Filesystem paths the agent may access (glob patterns). |
| `policy.denied_paths` | list | Filesystem paths the agent is denied from accessing (glob patterns). |
| `policy.allowed_hosts` | list | Network hosts the agent may contact (glob patterns). |
| `policy.denied_hosts` | list | Network hosts the agent is denied from contacting (glob patterns). |
| `policy.max_argument_size` | integer | Maximum size of a single tool argument in bytes. |
| `policy.require_approval_for_delete` | bool | Whether file deletion requires approval. |
| `policy.require_approval_for_network` | bool | Whether network access requires approval. |

## Budget

Set spending limits to control costs.

```toml
[budget]
session_max_usd = 100.0
per_action_max_usd = 10.0
warn_at_percent = 80
# workspace_max_usd = 50.0  # Optional: total workspace spend cap
```

## Rate Limits

Prevent abuse by limiting request rates.

```toml
[rate_limits]
elicitation_per_server_per_min = 10
max_pending_requests = 50
```

## Audit

Configure audit log storage.

```toml
[audit]
# path = "~/.local/share/astrid/audit.db"  # Optional: omit for in-memory only
max_size_mb = 100
```

## Keys

Paths to cryptographic key material.

```toml
[keys]
# user_key_path = "~/.astrid/id_ed25519"      # Only needed if require_signatures = true
# trusted_keys_path = "~/.astrid/trusted_keys" # For verifying signatures from others
```

## Workspace

Control the agent's access to the filesystem.

```toml
[workspace]
mode = "safe"          # "safe", "guided", or "autonomous"
escape_policy = "ask"  # "ask", "deny", or "allow"
auto_allow_read = []
auto_allow_write = []
never_allow = ["/etc", "/var", "/usr", "/bin", "/sbin", "/boot", "/root"]
```

## Git

Configure Git integration for completed work.

```toml
[git]
completion = "merge" # "merge", "pr", or "branch-only"
auto_test = false
squash = false
```

## Hooks

Control user-defined hook execution.

```toml
[hooks]
enabled = true
default_timeout_secs = 30
max_hooks = 100
allow_async_hooks = true
allow_wasm_hooks = false
allow_agent_hooks = false
allow_http_hooks = true
allow_command_hooks = true
```

## Logging

Configure logging output and verbosity.

```toml
[logging]
level = "info"     # "trace", "debug", "info", "warn", "error"
format = "compact" # "pretty", "compact", "json", "full"
directives = []    # e.g. ["astrid_mcp=debug"]
```

## Gateway

Configure the daemon process.

```toml
[gateway]
# state_dir = "~/.astrid/state"  # Optional: defaults to ~/.astrid/state/
# secrets_file = ""               # Optional: path to credential management file
hot_reload = true
watch_plugins = true
health_interval_secs = 30
shutdown_timeout_secs = 30
idle_shutdown_secs = 30
session_cleanup_interval_secs = 60
```

## Timeouts

Set maximum durations for various operations.

```toml
[timeouts]
request_secs = 120
tool_secs = 60
subagent_secs = 300
mcp_connect_secs = 10
approval_secs = 300
idle_secs = 3600
```

## Sessions

Manage session persistence and limits.

```toml
[sessions]
max_per_user = 10
history_limit = 100
save_interval_secs = 60
persist = true
```

## Subagents

Configure the sub-agent pool.

```toml
[subagents]
max_concurrent = 5
max_depth = 3
timeout_secs = 300
```

## Retry

Configure retry behavior for transient failures.

```toml
[retry]
llm_max_attempts = 3
mcp_max_attempts = 5
initial_delay_ms = 100
max_delay_ms = 10000
```

## Telegram

Configure the Telegram bot frontend.

```toml
[telegram]
# bot_token = ""  # Optional: use env var TELEGRAM_BOT_TOKEN
# daemon_url = "ws://127.0.0.1:3100"  # Optional: auto-discovers from ~/.astrid/daemon.port
allowed_user_ids = []
# workspace_path = "/path/to/workspace"
embedded = true
```

## Spark (Agent Identity)

Define the agent's personality and role. This serves as a static fallback for `spark.toml`. Once the agent evolves its spark, `spark.toml` takes priority.

```toml
[spark]
callsign = "Stellar"
class = "navigator"
aura = "calm"
signal = "concise"
core = "I value clarity and precision."
```

## Servers (MCP)

Configure Model Context Protocol servers.

```toml
[servers.filesystem]
transport = "stdio"
command = "npx"
args = ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
auto_start = true
trusted = false
restart_policy = "never"
# binary_hash = "sha256:abc123..."  # Optional: verify binary integrity
# cwd = "/path/to/working/dir"     # Optional: working directory for the process
# description = "Filesystem access" # Optional: human-readable description

[servers.filesystem.env]
NODE_ENV = "production"
```

| Field | Type | Description |
|---|---|---|
| `transport` | string | `"stdio"`, `"sse"`, or `"streamable-http"`. |
| `command` | string | Executable to run (for stdio transport). |
| `args` | list | Arguments for the command. |
| `url` | string | URL for network transports (`sse`, `streamable-http`). |
| `env` | table | Environment variables to pass to the process. |
| `cwd` | string | (Optional) Working directory for the server process. |
| `binary_hash` | string | (Optional) Expected hash for binary integrity verification (e.g., `"sha256:..."`). |
| `description` | string | (Optional) Human-readable description of this server. |
| `trusted` | bool | Whether this server is trusted (affects capability defaults). |
| `auto_start` | bool | Start automatically with the daemon. |
| `restart_policy` | string | `"never"`, `"always"`, or `{ on_failure = { max_retries = N } }`. |
