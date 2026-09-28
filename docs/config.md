# Configuration Reference

Astrid uses a layered configuration system powered by TOML. Configuration is loaded in the following order (each layer overrides the previous):

1. **Defaults** (Embedded in binary — safe production values)
2. **System Config** (`/etc/astrid/config.toml`)
3. **User Config** (`~/.astrid/config.toml` or `$ASTRID_HOME/config.toml`)
4. **Workspace Config** (`.astrid/config.toml` in the project root — can only **tighten** security, never loosen)
5. **Environment Variables** (`ASTRID_*` — fill in unset fields only, do not override)

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

Host configuration has no model section. Model selection and provider execution are owned by principal-scoped capsules. Configure capsule-specific provider settings in that capsule's `[env]`, then select and discover models through the model registry.

Legacy host `[model]` configuration is rejected with migration guidance. It is not silently ignored, and provider credentials are never loaded into core host configuration.

## Runtime

Control context management and summarization behavior.

```toml
[runtime]
max_context_tokens = 100000
system_prompt = ""  # Leave empty to use the dynamic prompt
auto_summarize = true
keep_recent_count = 10
```

## Security

Define the security boundary for the agent.

```toml
[security]
require_signatures = false
approval_timeout_secs = 300
```

| Field | Type | Description |
|---|---|---|
| `require_signatures` | bool | Require ed25519 signatures on user inputs. |
| `approval_timeout_secs` | integer | Seconds before an unanswered approval request is denied. |

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
entry_format = "v1"  # "v1" (default) or "v2"
```

`entry_format` selects the signed layout of new audit entries.

- `v1` keeps the original layout: signed by the runtime key and verified
  against the key embedded in each entry.
- `v2` signs a canonical CBOR body that covers every field. The body
  includes a per-chain sequence number, nanosecond time, the full outcome,
  and salted commitments to every field value. v2 entries are signed by a
  separate audit key, `keys/audit.key`, and verified against a cross-signed
  key registry kept in the audit store. The byte-level format is specified in the
  `astrid_audit::entry_v2` crate documentation.

When the daemon first boots with `v2`, it:

1. creates `keys/audit.key`;
2. writes the key registry, which binds the audit key and records the runtime
   key as the capability, build and v1-audit key.

Existing v1 entries are kept unchanged. The next entry of each chain starts
a v2 chain linked to the last v1 entry. From then on, verification also
requires v1 entries to be signed by the registered v1-audit key (the runtime
key at enablement), so a v1 chain re-signed under another key is reported. v1
entries signed by an earlier runtime key, for example one replaced before v2
was enabled, are reported the same way.

Enabling v2 is one-way for a node. Once the registry exists:

- the daemon keeps writing v2 even if `entry_format` is set back to `v1`,
  because a v1 entry after a v2 entry would reopen a chain under the weaker
  format;
- `keys/audit.key` must be kept: the daemon refuses to boot if it is missing
  or replaced, since only the registered key can authorize its successor.

If the configuration cannot be read, the daemon refuses to start rather than
assume `v1`, unless the node is already on v2.

Once v2 is enabled, going back to an Astrid release without v2 support is
not supported: such a release cannot verify v2 entries and would append v1
entries after them.

Only the operator's own configuration can set `entry_format`. A workspace
`.astrid/config.toml` cannot. The daemon applies the setting at boot; an
embedder that builds the kernel around its own audit log (such as the browser
profile) enables v2 with `AuditLog::enable_entry_v2`.

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
daemon_ready_secs = 600
```

Capsule HTTP controls remain independent. `[http].default_timeout_secs` sets
the buffered request default; a capsule request's `total-ms` sets that
request's whole-response budget. `[http].header_deadline_secs` and
`first-byte-ms` cover time to response headers, while
`[http].stream_read_timeout_secs` and `between-bytes-ms` cover gaps between
response bytes.

## Client Configuration

`astrid run`'s no-message idle timeout is client behavior, not runtime policy.
It loads from an isolated pre-mount TOML file and never parses the full runtime
configuration. The canonical AOS location is
`~/.aos/etc/astrid/client.toml`; set `ASTRID_CLIENT_CONFIG_PATH` to select a
different absolute path. The path must be a current-user-owned, mode `0600`
regular file with no redirects.

```toml
run_idle_secs = 120
```

The default remains 120 seconds and values must be between 1 and 86400
seconds. `--idle-timeout-secs` has the highest precedence and bypasses client
file parsing. Workspace and runtime configuration cannot set or raise this
timeout.

The idle deadline applies only to gaps between messages belonging to the active
run. Chat responses and `agent.v1.stream.delta` frames must carry the matching
session; unattributed control frames cannot extend the run. Headless approval
requests cannot be correlated in production, so they are ignored without an
approval response and cannot extend the run. `--yes`, `--yolo`, and
`--autonomous` are rejected before headless execution. Disconnect and approval
sends use a bounded best-effort budget so a wedged socket cannot defer the
established timeout result indefinitely.

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
# Replace with the local command's complete lowercase BLAKE3 digest.
# binary_hash = "blake3:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
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
| `binary_hash` | string | (Optional) Exact `blake3:<64 lowercase hex>` content hash for a local command. Other forms are rejected; network transports with no local `command` have no binary to verify. |
| `description` | string | (Optional) Human-readable description of this server. |
| `trusted` | bool | Whether this server is trusted (affects capability defaults). |
| `auto_start` | bool | Start automatically with the daemon. |
| `restart_policy` | string | `"never"`, `"always"`, or `{ on_failure = { max_retries = N } }`. |
