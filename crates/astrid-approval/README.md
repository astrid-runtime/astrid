# astrid-approval

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](../../LICENSE-MIT)
[![MSRV: 1.94](https://img.shields.io/badge/MSRV-1.94-blue)](https://www.rust-lang.org)

**Human-in-the-loop approval for sensitive agent operations.**

This crate provides the pieces Astrid uses to gate a risky action behind explicit human confirmation: a typed vocabulary of sensitive actions, scoped auto-approvals (allowances), spending budgets, and the manager that drives a request to a decision. The kernel's approval path consumes these types; the crate holds no kernel state of its own.

## Not a unified security gate

Astrid's security is **decomposed**. There is no single interceptor that every action funnels through (an unwired prototype of that idea, `SecurityInterceptor`, was removed; see issue #991, "Define the canonical security-enforcement model"). Authorization is enforced by independent, per-area mechanisms, each fail-closed:

- the **WASM sandbox**: a capsule has no ambient authority, so every effect is a host call;
- the **manifest allowlist gate** on every host call (`check_file_read` / `check_net_connect` / `check_host_process`), with path-traversal and SSRF defenses;
- the **IPC publish/subscribe ACL** and per-principal routing;
- **capability tokens** (`astrid-capabilities`), principal-scoped, expiry-checked, and globally revocable;
- the **budgets and allowances** in this crate.

This crate is the human-in-the-loop layer of that model, not the model itself.

## What's here

**`SensitiveAction`**: the typed vocabulary of gated operations (file read / delete / write-outside-sandbox, command execution, network request, data transmission, capability grant, MCP tool call, and capsule effects). Each variant carries typed context and is assigned a risk level.

**Allowances (`AllowanceStore`, `AllowancePattern`)**: scoped, user-granted auto-approvals so a repeated action is not re-prompted. They are:

- **principal-scoped**: Alice's allowance never matches Bob's invocation;
- **session- or workspace-scoped**: a workspace allowance (`session_only = false`) survives session end and is pinned to its workspace root, so an allowance granted in `/project-a` cannot match an action in `/project-b`;
- **atomic single-use** when `max_uses` is set: under concurrency exactly one caller may consume a single-use allowance;
- **traversal- and shell-safe**: a `..` path component, or a command carrying shell operators (`;`, `|`, `&&`, `$(`, backticks, redirects), is rejected at the pattern layer and forced back to explicit approval.

The nine `AllowancePattern` variants (`ExactTool`, `ServerTools`, `FilePattern`, `NetworkHost`, `CommandPattern`, `WorkspaceRelative`, `Custom`, `CapsuleCapability`, `CapsuleWildcard`) match via `globset`.

**`ApprovalManager`**: drives the flow. It consults existing allowances first, prompts a registered `ApprovalHandler` only when needed, and translates the decision into an outcome. If no human is available the action becomes a `DeferredResolution` and queues; it is never silently skipped.

**Budgets (`BudgetTracker`, `WorkspaceBudgetTracker`)**: per-action and per-session USD ceilings enforced with an atomic check-and-reserve, so two racing callers cannot both pass the check and then both debit. A cancelled future refunds automatically via a drop guard. The dual budget requires both the session and the workspace to allow.

## Decisions and their effects

`ApprovalDecision` ranges over Allow Once / Allow Session / Allow Workspace / Allow Always / Deny. The session and workspace decisions create allowances in this crate. "Allow Always" is fulfilled by the **kernel**, which holds the runtime signing key and the capability store and mints a persistent capability token; this crate only records the decision and leaves the token minting to the caller.

## Future, not shipped

Cryptographic capability **delegation** and **per-action attenuated tokens** (a child action receiving a token strictly narrower than its parent's) are a planned direction, not a current feature. Do not read the types here as providing them today.

## Usage

```toml
[dependencies]
astrid-approval = { workspace = true }
```

```rust
use astrid_approval::{ApprovalDecision, ApprovalRequest, SensitiveAction};

// Classify a risky action and wrap it in a request with context.
let action = SensitiveAction::FileDelete {
    path: "/home/user/report.txt".to_string(),
};
let request = ApprovalRequest::new(action, "removing a stale report");

// Decisions are explicit; a denial carries a reason.
let decision = ApprovalDecision::Deny {
    reason: "out of scope".to_string(),
};
assert!(!decision.is_approved());
```

Frontends implement the `ApprovalHandler` trait (`request_approval`, `is_available`) to present prompts; the kernel registers the handler on the `ApprovalManager`.

## Development

```bash
cargo test -p astrid-approval
```

## License

Dual MIT/Apache-2.0. See [LICENSE-MIT](../../LICENSE-MIT) and [LICENSE-APACHE](../../LICENSE-APACHE).
