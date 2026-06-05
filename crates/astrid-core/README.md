# astrid-core

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](../../LICENSE-MIT)
[![MSRV: 1.94](https://img.shields.io/badge/MSRV-1.94-blue)](https://www.rust-lang.org)

**The shared vocabulary.**

Every crate in the workspace depends on this one. It defines the identifiers, approval primitives, uplink abstractions, elicitation protocol, capsule ABI types, session authentication, directory layout, and environment variable security policy that all enforcement points agree on. If a type crosses crate boundaries, it lives here.

This crate exists because the kernel, the capsule runtime, the approval system, the CLI, and the SDK all need to agree on what a `SessionId` is, what an `ApprovalDecision` contains, and where `~/.astrid/` lives. Duplicating those definitions would create drift. Centralizing them here makes the type system enforce consistency.

## Identifiers

`AgentId`, `SessionId`, `TokenId`, `UplinkId`, `AstridUserId`, `Timestamp`. All UUID-backed, serde-compatible, with `Display` formatting (`agent:<uuid>`, `session:<uuid>`). `SessionId::SYSTEM` is the well-known nil UUID used by the kernel for internal IPC messages.

## Approval primitives

`ApprovalRequest` and `ApprovalDecision` with five-tier `ApprovalOption`: Once, Session, Workspace, Always, Deny. `RiskLevel` is ordered: `Low < Medium < High < Critical`. Critical risk requires DM verification. `ApprovalDecision::creates_capability()` returns true for `AllowAlways`, which triggers token minting in the security interceptor.

## Uplinks

`UplinkDescriptor` (builder pattern) with `UplinkCapabilities` (flag struct: `full()`, `notify_only()`, `receive_only()` presets), `UplinkProfile` (chat, interactive, notify, bridge), and `UplinkSource` (native, WASM, Bridge). Hard limit of 32 uplinks per capsule, enforced at the type level.

## Elicitation

MCP server-initiated user input: `ElicitationRequest`/`ElicitationResponse` with text, secret, select, and confirm schemas. `UrlElicitationRequest` handles OAuth and payment flows.

## Capsule ABI types

Rust mirrors of the `astrid:capsule@0.1.0` WIT records: `CapsuleAbiContext`, `CapsuleAbiResult`, `ToolInput`, `ToolOutput`, `ToolDefinition`, `HttpResponse`, `LogLevel`. These types cross the WASM boundary as serialized bytes.

## Session authentication

`SessionToken`: 256-bit CSPRNG value. Hex encode/decode. Atomic 0o600 file write. Constant-time comparison via `subtle`. `Debug` is redacted (prints `SessionToken(***)`). `HandshakeRequest`/`HandshakeResponse` define the Unix socket wire protocol.

## Directory layout

`AstridHome` resolves `~/.astrid/` (or `$ASTRID_HOME`) with typed accessors: `socket_path()`, `token_path()`, `ready_path()`, `state_db_path()`, `capsules_dir()`, `shared_dir()`, and more. `WorkspaceDir` detects per-project `.astrid/` directories.

## Environment security policy

`is_blocked_spawn_env` enforces a blocklist of environment variables that must never be set on spawned child processes by untrusted config: library injection (`LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`), proxy interception (`HTTP_PROXY`), CA trust overrides (`SSL_CERT_FILE`).

## Development

```bash
cargo test -p astrid-core
```

## License

Dual MIT/Apache-2.0. See [LICENSE-MIT](../../LICENSE-MIT) and [LICENSE-APACHE](../../LICENSE-APACHE).
