//! The `[capabilities]` block — what a capsule asks for from the OS.
//!
//! Every field is fail-closed by default (empty `Vec` or `false`). The kernel
//! security gates consult these allowlists before granting access.

use serde::{Deserialize, Serialize};

/// A collection of capabilities the capsule requests from the OS.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CapabilitiesDef {
    /// Whether the capsule acts as a long-lived uplink/daemon (e.g. the CLI proxy).
    /// When true, the WASM execution timeout is disabled.
    #[serde(default)]
    pub uplink: bool,
    /// Network domains the capsule wants to access.
    #[serde(default)]
    pub net: Vec<String>,
    /// Scoped KV store access requests.
    /// Note: KV access is inherently scoped per-capsule at runtime,
    /// so this field is currently not enforced via a security gate, but
    /// is present for future cross-capsule KV request declarations.
    #[serde(default)]
    pub kv: Vec<String>,
    /// VFS read paths.
    #[serde(default)]
    pub fs_read: Vec<String>,
    /// VFS write paths.
    #[serde(default)]
    pub fs_write: Vec<String>,
    /// Legacy host process executions (the "Airlock Override").
    #[serde(default)]
    pub host_process: Vec<String>,
    /// Unix/TCP socket bind addresses the capsule requires.
    #[serde(default)]
    pub net_bind: Vec<String>,
    /// Outbound TCP destinations the capsule is allowed to connect to.
    ///
    /// Each entry is a `"host:port"` pattern. The `host` portion is a
    /// literal DNS name or `*` (universal — see security review note
    /// before allowing). The `port` portion is a decimal `u16` or `*`
    /// (any port for the named host). Empty list → no outbound TCP
    /// (fail-closed). Gated by the `astrid:capsule/net.net-connect-tcp`
    /// host fn; the same kernel-side SSRF airlock that gates
    /// `http-request` runs on the resolved IP after the capability
    /// check passes.
    #[serde(default)]
    pub net_connect: Vec<String>,
    /// Identity operations this capsule is allowed to perform.
    ///
    /// Valid values: `"resolve"` (read-only lookups), `"link"` (create/delete
    /// links, list links), `"admin"` (create users). The hierarchy is
    /// `admin > link > resolve` - higher levels imply all lower levels.
    ///
    /// An empty list means NO identity access (fail-closed).
    #[serde(default)]
    pub identity: Vec<String>,
    /// Whether the capsule may override or modify the system prompt via the
    /// prompt builder's hook pipeline.
    ///
    /// When `false` (default), hook responses from this capsule have their
    /// `systemPrompt`, `prependSystemContext`, and `appendSystemContext`
    /// fields stripped. Only `prependContext` (user-visible context) passes
    /// through.
    ///
    /// This is a critical security boundary: unprivileged capsules cannot
    /// inject arbitrary instructions into the LLM's system prompt.
    #[serde(default)]
    pub allow_prompt_injection: bool,
}
