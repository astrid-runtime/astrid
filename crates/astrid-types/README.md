# astrid-types

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)
[![MSRV: 1.94](https://img.shields.io/badge/MSRV-1.94-blue)](https://www.rust-lang.org)

**Shared data types for the [Astrid](https://github.com/astrid-runtime/astrid) secure agent runtime.**

This crate is the single source of truth for the types that cross boundaries in Astrid: between the host kernel and WASM capsule guests over IPC, between the runtime and LLM provider capsules, and between frontends and the kernel management API. Both the kernel (`astrid-events`) and the user-space SDK (`astrid-sdk`) depend on it — nothing else does.

## Modules

### `ipc` — Cross-boundary messaging

`IpcMessage` is the envelope for every event published on the Astrid event bus. Its `IpcPayload` enum covers the full protocol surface:

| Variant | Direction | Purpose |
|---|---|---|
| `UserInput` | frontend → kernel | Raw text from CLI, Telegram, etc. |
| `AgentResponse` | kernel → frontend | Agent output (streaming or final) |
| `LlmRequest` | kernel → LLM capsule | Dispatch a generation request |
| `LlmStreamEvent` | LLM capsule → kernel | Incremental token/tool-call events |
| `LlmResponse` | LLM capsule → kernel | Final non-streaming response |
| `ToolExecuteRequest` | kernel → tool router | Execute a named tool |
| `ToolExecuteResult` | tool router → kernel | Tool output or error |
| `ToolCancelRequest` | kernel → tool router | Cancel in-flight tool calls |
| `ApprovalRequired` | capsule → frontend | Request user capability approval |
| `ApprovalResponse` | frontend → capsule | User's approve/deny decision |
| `OnboardingRequired` | capsule → frontend | Request missing env vars |
| `SelectionRequired` | capsule → frontend | Ask user to pick from a list |
| `ElicitRequest` | capsule → frontend | Prompt for a single runtime input |
| `ElicitResponse` | frontend → capsule | User's input value |
| `Connect` / `Disconnect` | frontend ↔ kernel | Session lifecycle |
| `Custom` | any | Escape hatch for unstructured plugins |

Unknown variant tags from newer protocol versions deserialize to `IpcPayload::Unknown` rather than failing — capsules built against an older `astrid-types` stay forward-compatible.

Messages carry an optional `signature: Option<Vec<u8>>` for stateless verification across a distributed swarm.

### `llm` — LLM message and streaming types

Provider-agnostic types that every LLM capsule speaks:

- **`Message`** — conversation turn with `MessageRole` (system/user/assistant/tool) and `MessageContent` (text, tool calls, tool results, or multipart)
- **`LlmToolDefinition`** — tool schema passed to the model
- **`ToolCall`** / **`ToolCallResult`** — structured call and response with `call_id` correlation; `ToolCall::parse_name()` splits `"server:tool"` routing prefixes
- **`StreamEvent`** — incremental streaming lifecycle: `TextDelta`, `ToolCallStart/Delta/End`, `ReasoningDelta` (for chain-of-thought models), `Usage`, `Done`, `Error`
- **`LlmResponse`** — final non-streaming response with `StopReason` and token `Usage`

### `kernel` — Management API

Types for the out-of-band control channel between frontends and the core daemon:

- **`KernelRequest`** — `InstallCapsule`, `ApproveCapability`, `ListCapsules`, `ReloadCapsules`, `GetCommands`, `GetCapsuleMetadata`
- **`KernelResponse`** — `Success`, `Commands`, `CapsuleMetadata`, `Error`, `ApprovalRequired`
- **`SYSTEM_SESSION_UUID`** — the well-known `source_id` (`00000000-0000-0000-0000-000000000000`) used by all kernel-internal IPC messages; capsules that verify message provenance compare against this constant

## Usage

```toml
[dependencies]
astrid-types = "0.2"
```

```rust
use astrid_types::{IpcMessage, IpcPayload, Message, StreamEvent};
use uuid::Uuid;

// Build an outbound IPC message
let msg = IpcMessage::new(
    "llm.v1.request.generate.anthropic",
    IpcPayload::LlmRequest {
        request_id: Uuid::new_v4(),
        model: "claude-3-5-sonnet".into(),
        messages: vec![Message::user("Hello!")],
        tools: vec![],
        system: "You are a helpful assistant.".into(),
    },
    Uuid::new_v4(), // source_id
);

// Deserialize a payload received from the event bus
let payload = IpcPayload::from_json_value(raw_json);
```

## Design notes

- **WASM-compatible.** Dependencies are limited to `serde`, `serde_json`, `uuid`, `chrono`, and `thiserror`. No OS-specific crates, no `std`-only I/O.
- **Forward-compatible IPC.** `IpcPayload` uses `#[serde(other)]` so capsules compiled against an older schema degrade gracefully when they receive unfamiliar variants.
- **No reverse dependencies.** Kernel crates depend on `astrid-types`; `astrid-types` depends on nothing in the Astrid workspace. This keeps the dependency graph acyclic and the crate publishable independently.
- **Strict lints.** `deny(unsafe_code)`, `deny(missing_docs)`, `deny(clippy::unwrap_used)`.

## Development

```bash
# From the workspace root
cargo test -p astrid-types -- --quiet
```

## License

Dual-licensed under [MIT](LICENSE-MIT) and [Apache 2.0](LICENSE-APACHE).

Copyright (c) 2025-2026 Joshua J. Bouw and Unicity Labs.
