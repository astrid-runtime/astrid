# astrid-integration-tests

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](../../LICENSE-MIT)
[![MSRV: 1.94](https://img.shields.io/badge/MSRV-1.94-blue)](https://www.rust-lang.org)

**The end-to-end proving ground for the Astrid OS.**

Contains no library code. Stitches together capabilities, capsules, MCP bridges, the approval matrix, and the audit log, then verifies they behave cohesively under hostile and concurrent conditions. Every test runs against the actual engine: real WASM payloads, real capability and allowance stores, real budgets. Nothing is mocked.

## Why it exists

Unit tests prove a crate works in isolation. Integration tests prove the OS works as a system. Astrid's security is decomposed across several crates — capability tokens (`astrid-capabilities`), allowances and budgets (`astrid-approval`), the WASM sandbox and host gates (`astrid-capsule`) — and a unit test in any one of them cannot verify that the decomposed mechanisms hold together: that a capability token persists and reauthorizes the next identical action, that one principal's allowance never matches another's, that a single-use grant is consumed exactly once under concurrency. This crate can.

## Test coverage

| File | What it proves |
|---|---|
| `wasm_e2e.rs` | WASM sandbox enforcement: memory allocation traps, IPC payload limits, VFS path traversal rejection, `home://` scheme access control, HTTP security gate (undeclared hosts denied, CRLF injection rejected). |
| `mcp_e2e.rs` | `CapsuleLoader` rejects capsules requesting binaries not listed in the manifest's `host_process` capability array. |
| `canonical_security_model.rs` | The decomposed security floor: capability token resource/permission/principal scoping, expiry, and global revocation; allowance session/workspace/principal scoping, atomic single-use under concurrency, and `..`/shell-operator rejection at the pattern layer; atomic budget reservation (no overspend); and overlay-VFS principal isolation. |
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
