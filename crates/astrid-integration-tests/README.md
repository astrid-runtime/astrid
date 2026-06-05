# astrid-integration-tests

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](../../LICENSE-MIT)
[![MSRV: 1.94](https://img.shields.io/badge/MSRV-1.94-blue)](https://www.rust-lang.org)

**The end-to-end proving ground for the Astrid OS.**

Contains no library code. Stitches together capabilities, capsules, MCP bridges, the approval matrix, and the audit log, then verifies they behave cohesively under hostile and concurrent conditions. Every test runs against the actual engine: real WASM payloads, real `SecurityInterceptor` pipelines, real stores. Nothing is mocked.

## Why it exists

Unit tests prove a crate works in isolation. Integration tests prove the OS works as a system. The `SecurityInterceptor` coordinates policy, budget, capabilities, allowances, approval, and audit across six crates. A unit test in `astrid-approval` cannot verify that a capability token minted via "Allow Always" in the approval flow actually persists in `astrid-capabilities` and reauthorizes the next identical action. This crate can.

## Test coverage

| File | What it proves |
|---|---|
| `wasm_e2e.rs` | WASM sandbox enforcement: memory allocation traps, IPC payload limits, VFS path traversal rejection, `home://` scheme access control, HTTP security gate (undeclared hosts denied, CRLF injection rejected). |
| `mcp_e2e.rs` | `CapsuleLoader` rejects capsules requesting binaries not listed in the manifest's `host_process` capability array. |
| `allowance_flow.rs` | Approve Once, Approve Session, Approve Workspace, and Approve Always state machine. Cross-workspace isolation verified. |
| `capability_lifecycle.rs` | "Allow Always" mints a `CapabilityToken` in the `CapabilityStore`. Subsequent identical actions hit the capability path. Tokens survive across independent interceptor instances. |
| `security_regressions.rs` | Seven targeted regressions: atomic allowance find-and-consume (max-uses:1 consumed exactly once under 10 concurrent tasks), atomic budget check-and-reserve (no overspend under 20 concurrent tasks), path traversal detection edge cases, expired allowance cleanup, audit entry correctness. |
| `lifecycle_e2e.rs` | Install and upgrade hook execution (`astrid_install`, `astrid_upgrade`), graceful skip when export is absent, elicit-request handling, KV write verification. |
| `wasm_env_e2e.rs` | `EnvDef` defaults and KV-injected values correctly surfaced to WASM tools. |

## Running

```bash
cargo test -p astrid-integration-tests
```

Tests requiring the WASM fixture (`tests/fixtures/test-all-endpoints.wasm`) skip gracefully if the file is absent.

## Development

```bash
cargo test -p astrid-integration-tests
```

This crate has `publish = false` and is not released to crates.io.

## License

Dual MIT/Apache-2.0. See [LICENSE-MIT](../../LICENSE-MIT) and [LICENSE-APACHE](../../LICENSE-APACHE).
