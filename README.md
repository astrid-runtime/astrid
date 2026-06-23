# Astrid

**An operating system for AI agents.**

[![CI](https://github.com/unicity-astrid/astrid/actions/workflows/ci.yml/badge.svg)](https://github.com/unicity-astrid/astrid/actions)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)
[![MSRV](https://img.shields.io/badge/MSRV-1.94-blue)](https://www.rust-lang.org)
[![Rust 2024](https://img.shields.io/badge/Rust-2024_edition-orange)](https://www.rust-lang.org)

---

Astrid is a user-space microkernel that treats AI agents the way Linux treats processes. It has a kernel with a boot sequence, a virtual filesystem with copy-on-write overlay, ed25519 capability tokens, an IPC event bus, WASM process isolation, and a cryptographic audit trail where each entry hashes the previous.

The kernel is fixed. Everything else is a swappable **capsule**: providers, orchestrators, tools, frontends, interceptors. You do not fork Astrid to customize it. You compose capsules into a configuration that fits your use case. Same core OS, different capsule sets, infinite configurations.

Currently v0.5.0. Runs in user space. The only frontend today is the built-in CLI (`astrid chat`). The architecture is designed for unikernel deployment.

## Why capsules matter

Most agent frameworks bake their assumptions into the code. The LLM provider is a library import. The orchestration loop is a hardcoded function. The tool set is a static list. Changing any of these means forking the framework, understanding its internals, and maintaining a divergent copy.

Astrid inverts this. The kernel provides sandboxing, IPC, a filesystem, capability tokens, budget enforcement, and audit. Everything above that boundary is a capsule: an isolated WASM process described by a `Capsule.toml` manifest. Capsules declare what they provide and what they require via typed `[imports]`/`[exports]` tables. The kernel resolves dependencies via topological sort and boots them in order.

This is not a plugin system bolted onto an application. It is the application's architecture.

### What this makes possible

**Run completely offline.** Swap the provider capsule for one that talks to Ollama or vLLM. Everything else works identically. The orchestrator does not know or care which model backend is running.

**Build novel agent architectures.** Write a custom orchestrator capsule: a debate system, a Monte Carlo tree search planner, a chain-of-verification loop. Agent architecture is the frontier of AI research. Astrid gives researchers a production runtime where sandboxing, budget enforcement, and audit are already solved.

**Cut LLM costs with transparent caching.** Install a caching capsule as middleware between orchestrator and provider. Seen this prompt before? Return the cached response. Neither orchestrator nor provider needs modification.

**Autonomous agents that work overnight.** Replace the default orchestrator with an autonomous worker capsule. It generates code, runs tests, reads errors, self-corrects, and loops until green. The difference between a chatbot and an autonomous agent is the orchestration logic, and that logic is a swappable capsule.

**Mix and match providers.** Run multiple provider capsules simultaneously. A routing capsule examines each request and picks the best provider by complexity, cost, or latency. Every provider speaks the same IPC event schema.

**Self-modifying agents.** The agent can write a new capsule — Rust source, `Capsule.toml`, tests — build it via `astrid-build`, install it with `capsule install`, and exercise it by publishing to its IPC topics. It can extend its own OS at runtime: add new tools, new interceptors, new capabilities. It can also modify its own existing configuration, environment, and persistent state across sessions. The identity capsule already does this in miniature — the LLM rewrites its own `spark.toml` during onboarding. The full picture is an agent that writes, tests, and deploys its own capsules — evolving its own harness within the capability sandbox.

**Ship custom distros.** Package a `Distro.toml` plus capsules. Enterprise A gets an approval-gated orchestrator. Startup B gets an autonomous worker with a local model. Security patches ship to everyone simultaneously.

> These scenarios are architecturally possible today. The kernel, IPC bus, capsule manifest system, and dependency resolver all exist and are tested. What varies is how many capsules have been built on top of this foundation so far.

## The agent has agency. The human has authority.

Traditional computing puts the human at the center. AI agents invert this relationship. The agent operates, reasons, and acts. The human supervises, approves, and steers. Astrid is built for this inverted model from the ground up.

The kernel enforces boundaries so the agent can act freely within them. The approval gates keep humans in the loop at moments that matter, not at every step. The audit trail provides cryptographic accountability for every action. The capability system lets trust expand gradually as the agent proves reliable.

How much authority you keep is up to you. `mode = "safe"` asks before every action outside the workspace. `mode = "guided"` auto-allows reads, asks for writes. `mode = "autonomous"` takes the guardrails off. And for daring Astrinauts: `mode = "yolo"`.

## The security model

Astrid's security is **decomposed**: there is no single gate every action funnels through. A capsule has no ambient authority, and authorization is enforced by independent, per-area mechanisms — each fail-closed, each enforced where the effect actually happens.

```text
A capsule has no ambient authority — every effect is a host call.

  [WASM sandbox]   No syscalls, no file descriptors, no host memory.
                   Every external resource is a capability-checked host function.

  [Manifest gate]  Every host call is checked against the capsule's declared
                   allowlist (fs / net / process), fail-closed (empty = deny-all),
                   with path-traversal and SSRF defenses. A jailbroken or
                   prompt-injected capsule still cannot exceed its manifest.

  [IPC ACL]        Publish/subscribe authorized by the manifest's
                   [publish]/[subscribe] keys, with per-principal routing.

  [Capability]     ed25519 tokens scoped to resource patterns (globset),
                   principal-bound, expiry-checked, globally revocable.

  [Budget]         Per-action and per-session limits, enforced atomically.
                   Dual-budget: session AND workspace must both allow.
                   Reservation-based: cost held during approval, refunded on denial.

  [Approval]       Human-in-the-loop for sensitive actions.
                   Allow Once / Session / Workspace / Always / Deny.
                   "Allow Always" mints a capability token; "Allow Session"
                   creates a scoped allowance. Human unavailable? It queues,
                   it does not silently skip.

  [OS sandbox]     Spawned native subprocesses run under bwrap/seatbelt with
                   the operator's credential directories masked.

  [Audit]          Admin actions are logged on a hash-chained, ed25519-signed
                   audit log; break the chain and tampering shows. (Per-action
                   audit coverage for every host call is a tracked follow-up.)
```

These mechanisms are real and independently tested. There is no unified interceptor orchestrating them — an earlier prototype of that idea was removed because it never ran (see issue #991); the decomposed model above is canonical.

## Two sandboxes

**WASM sandbox.** Capsules run in WebAssembly via Extism/Wasmtime. No syscalls, no file descriptors, no host memory access. Every external resource (filesystem, network, IPC, KV storage) is gated behind a capability-checked host function. The host ABI exposes 49 functions across filesystem, IPC, storage, network, identity, lifecycle, process management, approval, hooks, and clock subsystems. Hard limits: 64 MB memory ceiling, 5-minute wall-clock timeout, BLAKE3 hash verification on capsule binaries (no hash or wrong hash means no load).

**VFS overlay.** The agent operates against a copy-on-write filesystem. The workspace is the read-only lower layer. Writes go into an ephemeral upper layer backed by a temp directory. Session ends: commit the diff to the workspace, or drop the temp directory to discard. Path traversal (`../../etc/passwd`) is rejected at the VFS layer before reaching the host filesystem. File handles use capability-based `DirHandle`/`FileHandle` types.

## The host ABI

The WASM-to-host boundary is a flat syscall table. WASM guests cannot import arbitrary host functions.

| Subsystem | Syscalls |
|---|---|
| **Filesystem** | `astrid_fs_exists`, `astrid_read_file`, `astrid_write_file`, `astrid_fs_mkdir`, `astrid_fs_readdir`, `astrid_fs_stat`, `astrid_fs_unlink` |
| **IPC** | `astrid_ipc_publish`, `astrid_ipc_subscribe`, `astrid_ipc_recv` (blocking), `astrid_ipc_poll` (non-blocking), `astrid_ipc_unsubscribe` |
| **Uplinks** | `astrid_uplink_register`, `astrid_uplink_send` |
| **Storage** | `astrid_kv_get`, `astrid_kv_set`, `astrid_kv_delete`, `astrid_kv_list_keys`, `astrid_kv_clear_prefix` |
| **HTTP** | `astrid_http_request`, `astrid_http_stream_start`, `astrid_http_stream_read`, `astrid_http_stream_close` |
| **Network** | `astrid_net_bind_unix`, `astrid_net_accept`, `astrid_net_poll_accept`, `astrid_net_read`, `astrid_net_write`, `astrid_net_close_stream` |
| **Identity** | `astrid_identity_resolve`, `astrid_identity_link`, `astrid_identity_unlink`, `astrid_identity_create_user`, `astrid_identity_list_links` |
| **Lifecycle** | `astrid_elicit` (user input during install), `astrid_has_secret`, `astrid_signal_ready`, `astrid_get_caller`, `astrid_get_config` |
| **Process** | `astrid_spawn_host`, `astrid_spawn_background_host`, `astrid_read_process_logs_host`, `astrid_kill_process_host` |
| **Approval** | `astrid_request_approval` (blocks guest until human responds or timeout) |
| **Security** | `astrid_check_capsule_capability` |
| **Hooks** | `astrid_trigger_hook`, `astrid_get_interceptor_handles` |
| **Clock** | `astrid_clock_ms` |
| **Logging** | `astrid_log` |

Every parameter crosses the boundary as raw bytes. The [SDK](https://github.com/unicity-astrid/sdk-rust) adds typed ergonomics on top, mirroring `std` module layout (`fs`, `net`, `process`, `env`, `time`, `log`) plus Astrid-specific modules (`ipc`, `kv`, `http`, `hooks`, `uplink`, `identity`, `approval`, `runtime`).

## Capsules

Capsules are processes in the OS model: isolated execution units described by a `Capsule.toml` manifest. A capsule can combine multiple engines:

- **WASM** — compiled sandbox, full host ABI access via syscalls
- **MCP** — native subprocess proxied via JSON-RPC (MCP 2025-11-25 spec, wraps `rmcp`)
- **Static** — declarative context injection (files, prompts)

A manifest declares the capsule's `[imports]` (what it needs from other capsules) and `[exports]` (what it provides to the system), using namespaced interface names with semver version requirements. Dependencies between capsules are resolved via topological sort at boot. The kernel validates that all required imports are satisfied before any capsule starts.

A manifest can also declare commands, skills, interceptors, IPC topics, MCP servers, and uplinks.

```rust
use astrid_sdk::prelude::*;

#[derive(Default)]
pub struct MyTools;

#[capsule]
impl MyTools {
    #[astrid::tool]
    fn search_issues(&self, args: SearchArgs) -> Result<SearchResult, SysError> {
        let token = env::var("GITHUB_TOKEN")?;
        let resp = http::get(&format!(
            "https://api.github.com/search/issues?q={}", args.query
        ))?;
        // ...
    }
}
```

The `#[capsule]` proc macro generates all WASM ABI boilerplate: `extern "C"` exports, JSON serialization across the boundary, and dispatch routing for tools, commands, hooks, install, and upgrade entry points. Capsule authors depend on `astrid-sdk` and `serde`.

## Interceptors

Capsules can register interceptors on IPC topics — eBPF-style middleware that fires before (or instead of) the core handler. Interceptors return `Continue`, `Final`, or `Deny` to control the chain. A guard at priority 10 can veto an event before the core handler at priority 100 ever sees it. Tools are an IPC convention: tool capsules intercept `tool.v1.execute.<name>` and `tool.v1.request.describe` topics. The router capsule handles discovery and dispatch. The kernel has no knowledge of tool schemas.

## Quick start

**Prerequisites:** Rust 1.94+. An LLM provider (e.g. Anthropic API key) is needed for the default distro but not for the kernel itself.

```bash
# Install from crates.io (installs both astrid and astrid-daemon binaries)
cargo install astrid

# Initialize — fetches the default distro, installs capsules, sets up PATH
astrid init

# Start a session (daemon boots automatically on first use)
ANTHROPIC_API_KEY=sk-... astrid chat

# Or build from source
git clone https://github.com/unicity-astrid/astrid.git
cd astrid
cargo build --release
./target/release/astrid init
```

Three binaries work together: `astrid` (CLI frontend), `astrid-daemon` (kernel process), and `astrid-build` (capsule compiler). When you run `astrid chat`, the CLI auto-starts the daemon as a background process, connects over a Unix domain socket, and renders streaming events. The daemon manages the VFS, capsules, IPC, audit, and security. The CLI manages input and display.

### Headless / scripting mode

```bash
# Single-prompt, non-interactive — prints response and exits
astrid -p "summarize the git log"

# Pipe stdin
git diff HEAD~1 | astrid -p "write a commit message for this diff"

# Multi-turn scripted conversation
SESSION=$(astrid -p "start a task" --print-session 2>&1 | tail -1)
astrid -p "continue the task" --session "$SESSION"

# Autonomous mode (auto-approve all tool requests)
astrid -p "fix all failing tests" --yes
```

### Daemon lifecycle

```bash
astrid start     # Start a persistent daemon (survives terminal close)
astrid status    # Show PID, uptime, connected clients, loaded capsules
astrid stop      # Graceful shutdown
astrid self-update  # Download the latest release binary to ~/.astrid/bin/
```

## The distro system

A **distro** is a `Distro.toml` manifest that describes a curated set of capsules for a particular use case. `astrid init` fetches the manifest, presents a multi-select provider group picker, resolves `{{ var }}` template variables via interactive prompts, and installs all selected capsules with progress bars. A `Distro.lock` is written atomically with BLAKE3 hashes of every installed capsule for reproducible deployments.

```bash
# Install the default distro (astralis)
astrid init

# Install a custom distro
astrid init --distro @myorg/my-distro

# Install from a local Distro.toml
astrid init --distro ./path/to/Distro.toml
```

## Capsule management

```bash
# Install from GitHub (downloads pre-built .wasm release asset, falls back to build from source)
astrid capsule install @org/capsule-name

# Install from a local path
astrid capsule install ./path/to/capsule

# List installed capsules with capability metadata
astrid capsule list
astrid capsule list --verbose

# Show the imports/exports dependency graph
astrid capsule tree

# Update a specific capsule (or all capsules)
astrid capsule update my-capsule
astrid capsule update

# Remove a capsule (checks dependents before removing)
astrid capsule remove my-capsule
astrid capsule remove my-capsule --force  # bypass dependency check
```

Content-addressed WASM binaries are stored in `~/.astrid/bin/` using BLAKE3 hashes. Capsule removal cleans up the binary from `bin/` when no other capsule references the same hash. The binary store itself (`bin/` and `wit/`) is append-only; `astrid gc` for explicit cleanup is planned.

## Directory layout

Astrid uses a Linux FHS-aligned layout under `~/.astrid/` (overridable via `$ASTRID_HOME`):

```text
~/.astrid/
├── etc/
│   ├── config.toml          deployment config
│   ├── servers.toml         MCP server config
│   ├── gateway.toml         daemon config
│   └── hooks/               system hooks
├── var/
│   └── state.db/            system KV (SurrealKV, persistent)
├── run/                     ephemeral runtime state
│   ├── system.sock          Unix domain socket
│   ├── system.token         session authentication token
│   └── system.ready         daemon readiness sentinel
├── log/                     system logs
├── keys/
│   └── runtime.key          ed25519 signing key
├── bin/                     content-addressed WASM binaries (BLAKE3-named)
├── wit/                     content-addressed WIT interface definitions
└── home/
    └── {principal}/         per-principal isolation
        ├── .local/
        │   ├── capsules/    user-installed capsules
        │   ├── kv/          capsule KV data
        │   ├── log/         capsule logs (daily rotation, 7-day retention)
        │   ├── audit/       per-principal audit chain
        │   ├── tokens/      capability tokens
        │   └── tmp/         VFS /tmp mount
        └── .config/
            └── env/         capsule env config overrides

<project>/.astrid/           workspace-level config (committable)
├── workspace-id             UUID linking project to global state
└── ASTRID.md                project-level agent instructions
```

Configuration follows a precedence chain: workspace > user > system > env vars > compiled defaults. Workspace configs can only **tighten** security settings, never loosen them.

## Multi-principal support

Each principal (user identity) gets fully isolated capsules, KV data, audit chain, capability tokens, and logs under `home/{principal}/`. The acting principal is carried transparently through every IPC message chain — capsules never see or touch principal routing. KV namespace format: `{principal}:capsule:{name}`. Per-invocation principal resolution means cross-user invocations write to the correct principal's audit log and KV.

## Architecture

Astrid follows a strict kernel/user-space divide. The kernel (native Rust daemon) owns all privileged resources. Capsules (WASM guests) have zero ambient authority and must request everything through the host ABI.

### Kernel crates

| Crate | Role |
|---|---|
| `astrid-kernel` | Boots the runtime. Owns VFS, IPC bus, capsule registry, MCP client, audit log, KV store. Listens on Unix socket for CLI connections. |
| `astrid-approval` | Human-in-the-loop approval: `SensitiveAction`, allowance store, approval manager, budget tracker. |
| `astrid-capabilities` | Ed25519-signed capability tokens with glob resource patterns and time bounds. |
| `astrid-audit` | Chain-linked cryptographic audit log. Each entry is signed and hashes the previous. SurrealKV-backed with chain verification. Per-principal chain splitting. |
| `astrid-vfs` | Copy-on-write overlay filesystem. `Vfs` trait with `HostVfs` and `OverlayVfs` implementations. Capability-based `DirHandle`/`FileHandle`. |
| `astrid-events` | IPC event bus. Broadcast-based with async receivers and synchronous subscriber callbacks. Types re-exported from `astrid-types`. |
| `astrid-types` | Shared data types: IPC payloads, LLM schemas, kernel API. Minimal deps, WASM-compatible. Used by both kernel and SDK. |
| `astrid-capsule` | Capsule runtime: manifest parsing, WASM/MCP/static engines, dependency resolution via toposort, capsule registry, hot-reload watcher. |
| `astrid-mcp` | MCP client/server lifecycle. Wraps `rmcp` with binary hash verification, capability gating, and elicitation support. |
| `astrid-crypto` | Ed25519 key pairs (via `ed25519-dalek`), BLAKE3 content hashing, signatures. Keys are zeroized on drop. |
| `astrid-storage` | Two-tier persistence. Tier 1: raw KV via embedded SurrealKV. Tier 2: full SurrealDB query engine with SurrealQL. |
| `astrid-config` | Layered TOML configuration: workspace > user > system > env > defaults. Workspace configs can only tighten security, never loosen it. |
| `astrid-workspace` | Workspace boundary detection and process sandbox configuration. |
| `astrid-hooks` | Hook system for session lifecycle, tool calls, and approval flows. Handlers: command, HTTP, WASM. |
| `astrid-core` | Foundation types: `SessionId`, `PrincipalId`, `Permission`, identity primitives, elicitation types, session tokens. |

### User-space crates

| Crate | Role |
|---|---|
| [`astrid-sdk`](https://github.com/unicity-astrid/sdk-rust) | Safe Rust SDK for capsule authors. Mirrors `std` layout. Includes `astrid-sys` (syscall table) and `astrid-sdk-macros` (`#[capsule]` proc macro). Standalone repo. |

### Binaries

| Binary | Crate | Role |
|---|---|---|
| `astrid` | `astrid-cli` | Terminal frontend. Connects to daemon over Unix socket. TUI rendering, headless/scripting mode, capsule management, distro init, daemon lifecycle commands. |
| `astrid-daemon` | `astrid-daemon` | Background kernel process. Boots the kernel, loads capsules, serves IPC requests. `--ephemeral` flag for CLI-spawned instances. |
| `astrid-build` | `astrid-build` | Capsule compiler and packager. Handles Rust and legacy MCP projects. Invoked by CLI as a companion binary. |

### Infrastructure crates

| Crate | Role |
|---|---|
| `astrid-telemetry` | Structured logging with `tracing`. JSON and human-readable outputs. File-based output with daily rotation. |
| `astrid-prelude` | Common re-exports for internal crates. |

## Storage

Two tiers, one API surface:

| Deployment | KV backend | DB backend |
|---|---|---|
| Dev / single-agent | SurrealKV (embedded) | SurrealDB (embedded, SurrealKV) |
| Production / multi-node | SurrealKV (embedded) | SurrealDB (over TiKV, Raft) |

Capsule KV stores are namespace-scoped per principal and per capsule. The kernel, audit log, capability store, and identity system use the DB tier. Scaling from embedded to distributed is a config change.

## v0.5.0 highlights

The major changes in this release:

- **FHS directory layout** — `~/.astrid/` restructured to `etc/`, `var/`, `run/`, `log/`, `keys/`, `bin/`, `home/`. Existing `~/.astrid/` must be deleted before upgrading (no migration path).
- **Multi-principal isolation** — each principal gets isolated capsules, KV, audit chain, tokens, and config under `home/{principal}/`.
- **Tools are a pure IPC convention** — the kernel no longer parses or manages tool schemas. Tool capsules use IPC interceptors. The router capsule handles discovery and dispatch.
- **LLM providers are a pure IPC convention** — `[[llm_provider]]` and `LlmProviderDef` removed from the manifest. LLM capsules self-describe via interceptors.
- **`[imports]`/`[exports]` manifest format** — replaces the old string-array `[dependencies]` with namespaced TOML tables, semver version requirements, optional imports, and namespace/interface name validation.
- **`astrid self-update`** — downloads platform-specific binaries from GitHub releases to `~/.astrid/bin/`, no sudo required. Startup update banner (cached 24h).
- **`astrid init` distro system** — fetches `Distro.toml`, multi-select provider groups, `{{ var }}` template resolution, atomic `Distro.lock` writes with BLAKE3 hashes.
- **Export conflict detection** — `astrid capsule install` detects when a new capsule exports interfaces already provided by an installed capsule and prompts to replace.
- **Interceptor priority** — optional `priority` on a `[subscribe]` handler entry enables layered interception chains (lower fires first).
- **Short-circuit interceptors** — `Continue`, `Final`, or `Deny` wire format controls the middleware chain.
- **Per-principal audit chains** — independently verifiable via `verify_principal_chain()`.
- **`astrid capsule tree`** — renders the imports/exports dependency graph.
- **`--snapshot-tui`** — renders the full TUI to stdout for automated smoke testing without an interactive terminal.

See [CHANGELOG.md](CHANGELOG.md) for the complete list of changes, fixes, and breaking changes.

## Current state

**v0.5.0.** The core runtime works end-to-end:

- Kernel boots, discovers and loads capsules, manages VFS overlay, listens on Unix socket
- Decomposed security floor: WASM sandbox, fail-closed manifest allowlist gate, IPC ACL, capability tokens, atomic budgets, and human-in-the-loop approval (session/workspace allowances, "Allow Always" token minting)
- WASM sandbox with 49 host functions, 64 MB memory ceiling, 5-minute tool timeout
- Chain-linked audit log with ed25519 signatures and per-principal chain integrity verification
- MCP client (2025-11-25 spec) via `rmcp` with capability gating and binary hash verification
- IPC event bus with broadcast subscribers and capability-scoped publish/subscribe ACLs
- Capsule dependency resolution via topological sort with semver-versioned interface matching
- Capsule manifest supporting commands, skills, interceptors, IPC topics, MCP servers, and uplinks
- CLI with TUI, streaming responses, session persistence, headless mode, capsule management
- Distro system with `Distro.toml` manifests and `Distro.lock` for reproducible installs
- Layered configuration with workspace-level security tightening
- `astrid self-update` downloading from GitHub releases

**Not yet done:** Multi-node SurrealDB (TiKV/Raft). WASM Component Model migration (Extism to WIT bindings). Additional frontends beyond CLI. Capsule registry for distribution.

## Development

```bash
# Build
cargo build --workspace

# Test
cargo test --workspace -- --quiet

# Lint
cargo clippy --workspace --all-features -- -D warnings
cargo fmt --all -- --check
```

All crates enforce `#![deny(unsafe_code)]` except `astrid-sys` and `astrid-sdk` (WASM FFI requires it). Clippy runs at pedantic level. Integer arithmetic overflow is a lint error (`clippy::arithmetic_side_effects = "deny"`).

Release binaries for macOS (x86_64, aarch64) and Linux (x86_64, aarch64) are built automatically on tag push via the [release workflow](.github/workflows/release.yml).

## Operator documentation

- [Gateway deployment runbook](docs/gateway-deployment.md) — setting up the HTTP admin gateway behind a reverse proxy or with native TLS, monitoring, key rotation, troubleshooting.
- [Generating a gateway API client](docs/gateway-client.md) — building a browser/native client against the HTTP admin API from the OpenAPI spec, and why it doesn't belong in the capsule SDKs.
- [Unified config schema](docs/config.md) — `astrid.toml` reference.
- [SDK ergonomics notes](docs/sdk-ergonomics.md) — capsule-author guidance.

## Contributing

Contributions are welcome. Astrid uses a tiered contributor system to protect security-critical code while keeping the door open for new contributors. Every PR must be linked to a GitHub issue. See [CONTRIBUTING.md](CONTRIBUTING.md) for the full process, including issue-first workflow, tier descriptions, and security-critical crate restrictions.

## License

Dual-licensed under [MIT](LICENSE-MIT) and [Apache 2.0](LICENSE-APACHE).

Copyright (c) 2025-2026 Joshua J. Bouw and Unicity Labs.
