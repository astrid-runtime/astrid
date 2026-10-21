# astrid-audit

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](../../LICENSE-MIT)
[![MSRV: 1.94](https://img.shields.io/badge/MSRV-1.94-blue)](https://www.rust-lang.org)

**If it happened, it is in the chain. If it is not in the chain, it did not happen.**

In the OS model, this is the kernel's tamper-evident event log. Every security-relevant event in the Astrid runtime gets recorded as an Ed25519-signed entry that links to the BLAKE3 hash of the entry before it. MCP tool calls, file writes, capability issuance, user approvals, sub-agent spawns. Modify a historical entry and the chain breaks. Delete one and every entry after it becomes invalid.

The audit log is not advisory. The security interceptor (`astrid-approval`) refuses to execute an action if the audit write fails. The chain is the ground truth.

## How the chain works

Each `AuditEntry` contains:

- The action, authorization proof, and outcome
- A BLAKE3 `previous_hash` linking to the entry before it (genesis uses `ContentHash::zero()`)
- The runtime's Ed25519 `PublicKey` that signed this entry
- An Ed25519 `Signature` over the signing data

Verification checks three invariants per session: valid genesis (first entry has zero previous hash), valid signatures (each entry's embedded public key verifies its signature), and unbroken links (each entry's `previous_hash` matches the preceding entry's content hash). Each failure is a typed `ChainIssue`.

Format v1 entries embed the signing key, so verification works across key rotations. A log started under key A and continued under key B verifies correctly because each entry carries the key that signed it. Format v2 entries also name their key, but only as a selector: the key must be registered for the audit role (see below).

## Entry format v2

Format v1 has limits for verification outside Astrid:

- it signs a mix of binary fields and JSON;
- it signs one success bit instead of the outcome;
- it signs whole-second time;
- it has no sequence number;
- it trusts the key embedded in each entry, so anyone who can write the store
  can re-sign a rewritten chain.

Format v2 (`entry_v2`, off by default) replaces that with:

- a deterministic CBOR body (RFC 8949 §4.2.1) that covers every stored field:
  - chain id bound to the registry, session, principal UID and alias;
  - per-chain sequence number and previous hash;
  - nanosecond time;
  - acting capsule;
  - action, authorization and full outcome;
- a salted commitment for every field value, so one field can be
  disclosed without the others;
- SHA-256 entry hashes and Ed25519 signatures checked with strict
  verification, made by a dedicated audit key;
- a key registry: a cross-signed chain of records that binds keys to roles
  (audit, capability, build, v1 audit). `ChainVerifier` rejects entries
  signed by a key the registry does not list for the audit role at the
  entry's key epoch.

`AuditLog::enable_entry_v2` switches a log to v2. v1 history is kept as it is
and hash-linked into the v2 chains that follow it; after that the log refuses
v1 appends. The crate documentation of `entry_v2` is the byte-level
specification, with a known-answer test for implementations in other
languages.

## What gets audited

26 `AuditAction` variants cover: MCP tool calls, capsule tool calls, MCP resource reads, MCP prompt retrieval, MCP elicitation, MCP URL elicitation, MCP sampling, file reads, file writes, file deletes, capability creation, capability revocation, approval requests, approval grants, approval denials, session start, session end, context summarization, LLM requests, server start, server stop, elicitation sent, elicitation received, security violations, sub-agent spawns, and config reloads.

Tool call arguments are stored as BLAKE3 hashes, not raw content. Proves what happened without leaking what the arguments contained.

Six `AuthorizationProof` variants record how each action was authorized: `User`, `Capability`, `UserApproval`, `NotRequired`, `System`, `Denied`.

## Usage

```toml
[dependencies]
astrid-audit = { workspace = true }
```

```rust
use astrid_audit::{AuditLog, AuditAction, AuditOutcome, AuthorizationProof};
use astrid_core::SessionId;
use astrid_crypto::KeyPair;

let runtime_key = KeyPair::generate();
let log = AuditLog::in_memory(runtime_key);
let session_id = SessionId::new();

let entry_id = log.append(
    session_id.clone(),
    AuditAction::McpToolCall {
        server: "filesystem".into(),
        tool: "read_file".into(),
        args_hash: astrid_crypto::ContentHash::hash(b"..."),
    },
    AuthorizationProof::Capability {
        token_id: astrid_core::TokenId::new(),
        token_hash: astrid_crypto::ContentHash::hash(b"token data"),
    },
    AuditOutcome::success(),
)?;

let result = log.verify_chain(&session_id)?;
assert!(result.valid);
```

`AuditLog::open(path, key)` for SurrealKV persistence. `AuditLog::in_memory(key)` for tests.

## Development

```bash
cargo test -p astrid-audit
```

## License

Dual MIT/Apache-2.0. See [LICENSE-MIT](../../LICENSE-MIT) and [LICENSE-APACHE](../../LICENSE-APACHE).
