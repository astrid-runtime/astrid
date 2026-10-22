# astrid-workspace

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](../../LICENSE-MIT)
[![MSRV: 1.94](https://img.shields.io/badge/MSRV-1.94-blue)](https://www.rust-lang.org)

**Host-level process containment. The second sandbox.**

Astrid has two sandboxes. The WASM sandbox is inescapable by design: capsule code runs in WebAssembly with zero ambient authority. But the agent also spawns native processes (npm, python, shell commands) that run outside WASM. This crate wraps those processes in OS-native containment so they cannot write outside the workspace or read sensitive host paths.

On Linux: `bwrap` (bubblewrap). On macOS: `sandbox-exec` with a generated Seatbelt profile. On other platforms: passthrough with a warning.

The WASM sandbox protects against malicious capsule code. This sandbox protects against malicious tool output that reaches native execution. They are complementary. The workspace sandbox is escapable with user approval. The WASM sandbox is not.

## How it works

`SandboxCommand` takes a `std::process::Command` and returns a new command prepended with the platform's sandbox wrapper. On Linux, it prepends `bwrap` with `--ro-bind / /` for read access, `--bind` for the writable root, `--tmpfs /tmp`, `--unshare-all`, `--share-net`, and `--die-with-parent`. On macOS, it generates an SBPL profile inline (passed via `-p`, not a temp file) that denies by default and allows reads/writes only to the workspace and `/tmp`.

`ProcessSandboxConfig` is a data-oriented builder for `tokio::process::Command` or finer control. Consume its `SandboxPrefix` through `into_command()` so verified Linux bind descriptors remain alive until Bubblewrap starts.

## Injection-safe profile generation

Every path interpolated into a Seatbelt profile is validated first. The crate rejects:

- Relative paths (must be absolute)
- Non-UTF-8 paths (lossy coercion would misalign the SBPL rule with the real path)
- Double-quote (`"`) in paths (SBPL string delimiter, allows sandbox escape)
- Backslash (`\`) in paths (SBPL escape character, silently reinterprets the path)
- Null bytes (defense in depth)

Validation runs on all platforms, not just macOS, so the API contract is consistent everywhere. The tests include an actual SBPL injection payload to verify rejection.

## Builder API

```rust
use astrid_workspace::ProcessSandboxConfig;

let config = ProcessSandboxConfig::new("/home/user/project")
    .with_network(true)
    .with_extra_read("/usr/local/share/myapp")
    .with_extra_write("/data/output")
    .with_protected_runtime_home("/home/user/.astrid");

if let Some(prefix) = config.sandbox_prefix()? {
    let mut cmd = tokio::process::Command::from(prefix.into_command());
    cmd.arg("npx").arg("@anthropic/mcp-server-filesystem");
}
```

Hidden paths are overlaid with empty tmpfs on Linux and excluded from the Seatbelt allowlist on macOS.

## Internal modules

Several modules are `pub(crate)` and consumed by higher-level Astrid crates, not directly by users:

- **Boundaries**: pre-compiled glob matching, canonical path resolution, and symlink evaluation for directory traversal prevention. Three modes: `Safe` (always ask), `Guided` (smart defaults), `Autonomous` (unrestricted).
- **Escape/airlock**: structured `EscapeRequest`/`EscapeDecision` flows with session-scoped and permanent approval memory. Remembered paths are canonicalized on store and validated on restore (relative and non-existent paths rejected).
- **Profiles**: predefined workspace configurations for `safe`, `power_user`, `autonomous` (aliased as `yolo`), and `ci` environments.
- **Worktrees**: `ActiveWorktree` creates a per-session Git branch and worktree. Auto-commits WIP on drop, then removes the physical worktree to reclaim disk space.

## Development

```bash
cargo test -p astrid-workspace
```

## License

Dual MIT/Apache-2.0. See [LICENSE-MIT](../../LICENSE-MIT) and [LICENSE-APACHE](../../LICENSE-APACHE).
