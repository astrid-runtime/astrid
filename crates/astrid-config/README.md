# astrid-config

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](../../LICENSE-MIT)
[![MSRV: 1.94](https://img.shields.io/badge/MSRV-1.94-blue)](https://www.rust-lang.org)

**The layered configuration system.**

An operating system must load configuration from untrusted sources without letting those sources escalate privileges. `git clone` a hostile project and its `.astrid/config.toml` sits inside the workspace. This crate merges five config layers into a single `Config`, then enforces a hard invariant: the workspace layer can only tighten security, never loosen it.

This crate has zero dependencies on other internal astrid crates. It depends only on `serde`, `toml`, `serde_json`, `thiserror`, `tracing`, and `directories`. Conversion to domain types happens at the integration boundary.

## Precedence

From highest to lowest priority:

1. **Workspace** (`{workspace}/.astrid/config.toml`) - untrusted input, restricted
2. **User** (`~/.astrid/config.toml`)
3. **System** (`/etc/astrid/config.toml`)
4. **Environment variables** (`ASTRID_*`, `ANTHROPIC_*`) - fallback only, applied to fields no config file set
5. **Embedded defaults** (`defaults.toml` compiled into the binary)

## Workspace restriction enforcement

After merging the workspace layer, a hard enforcement pass runs against the pre-workspace baseline:

- **Budgets can only decrease.** `session_max_usd` and `per_action_max_usd` are clamped to the baseline value.
- **Security can only tighten.** `require_signatures` can only become true; `approval_timeout_secs` can only decrease; `workspace.mode` and `escape_policy` can only move to a stricter level.
- **Deny-lists can only grow.** Workspace can add to `workspace.never_allow` but cannot remove entries.
- **Allow-lists cannot expand.** Workspace cannot add entries to `workspace.auto_allow_read` or `auto_allow_write`.
- **API keys cannot be overridden.** `model.api_key` and `model.api_url` from workspace are reverted.
- **Server injection blocked.** Workspace cannot add new MCP server definitions.

Violations are logged and silently reverted. The agent never sees the hostile values.

## Variable expansion

`${VAR}` references in workspace config are restricted to `ASTRID_*` and `ANTHROPIC_*` prefixes. `${AWS_SECRET_ACCESS_KEY}` is left unresolved. This prevents a workspace config from exfiltrating arbitrary environment variables into fields the agent can read.

## Validation

Post-merge validation checks: supported providers (`claude`, `openai`, `openai-compat`, `zai`, `unknown`), temperature range (0.0-1.0), token bounds (1-16M), budget invariants (per-action cannot exceed session), zero-value timeout guards, and valid enum strings.

## Credential redaction

`ModelConfig` has a custom `Serialize` that omits `api_key` and `api_url`. `Debug` replaces credential values with presence booleans. `ServerSection` redacts environment variable values. Credentials never appear in logs, config dumps, or serialized output.

## Field-level provenance

`ResolvedConfig` wraps `Config` with a `FieldSources` map recording which layer last wrote every dotted field path. `config show` annotates each value with `[defaults]`, `[system]`, `[user]`, `[workspace]`, or `[env]`. Output formats: TOML with inline source annotations, or JSON.

## Key types

| Type | Role |
|---|---|
| `Config` | Root struct. 21 sections: model, runtime, security, budget, rate_limits, servers, audit, keys, workspace, git, hooks, logging, gateway, timeouts, sessions, subagents, retry, spark, uplinks, identity. |
| `Config::load(workspace_root)` | Full precedence chain with restriction enforcement and validation. |
| `Config::load_with_home(workspace_root, astrid_home)` | Explicit home override for tests and containers. |
| `ResolvedConfig` | `Config` + `FieldSources` + list of loaded file paths. |
| `ConfigLayer` | `Defaults`, `System`, `User`, `Workspace`, `Environment`. |
| `ConfigError` | `ReadError`, `ParseError`, `ValidationError`, `EnvError`, `RestrictionViolation`, `NoHomeDir`. |

## Development

```bash
cargo test -p astrid-config
```

## License

Dual MIT/Apache-2.0. See [LICENSE-MIT](../../LICENSE-MIT) and [LICENSE-APACHE](../../LICENSE-APACHE).
