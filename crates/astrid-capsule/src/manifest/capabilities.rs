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

impl CapabilitiesDef {
    /// Whether a serialized capability field counts as HELD: a non-empty
    /// allowlist (`Vec` → JSON array) or an enabled flag (`bool` → JSON
    /// `true`). Any other JSON shape is fail-closed (`false`) — a future
    /// capability field whose "held" meaning is neither of those two must opt
    /// in here deliberately rather than be silently reported.
    fn value_is_held(value: &serde_json::Value) -> bool {
        match value {
            serde_json::Value::Bool(enabled) => *enabled,
            serde_json::Value::Array(allowlist) => !allowlist.is_empty(),
            _ => false,
        }
    }

    /// The capability NAMES this capsule declared in its `[capabilities]`
    /// manifest block (`host_process`, `net_connect`, `fs_read`, …) — the
    /// capability categories, NOT the scoped arguments within them
    /// (allowlists, `host:port`, paths).
    ///
    /// DERIVED from the struct itself, not a hand-maintained list: every field
    /// IS a capability, so the names are the struct's serialized field names
    /// (which are exactly the manifest TOML keys — no `#[serde(rename)]`),
    /// filtered to the ones that are held (a non-empty allowlist or an enabled
    /// flag). Adding a field to `CapabilitiesDef` therefore flows through
    /// `held_names` AND [`has`](Self::has) automatically — there is no parallel
    /// list to drift from the struct, which is the very code-vs-manifest drift
    /// this introspection surface exists to prevent. Returned sorted, so the
    /// order is deterministic and independent of serde's map ordering.
    ///
    /// Backs `astrid:sys/host.enumerate-capabilities`; `n` appears here iff
    /// [`has(n)`](Self::has) is true.
    pub fn held_names(&self) -> Vec<String> {
        let serde_json::Value::Object(fields) =
            serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
        else {
            return Vec::new();
        };
        let mut names: Vec<String> = fields
            .into_iter()
            .filter(|(_, value)| Self::value_is_held(value))
            .map(|(name, _)| name)
            .collect();
        names.sort_unstable();
        names
    }

    /// Whether this capsule holds the named capability — the per-name dual of
    /// [`held_names`](Self::held_names), derived from the same serialized form
    /// so the two cannot disagree. `has(n)` is true exactly when `n` is in
    /// `held_names()`. Unknown names are fail-closed (`false`), so this backs
    /// `astrid:sys/host.check-capsule-capability` directly.
    pub fn has(&self, name: &str) -> bool {
        let serde_json::Value::Object(fields) =
            serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
        else {
            return false;
        };
        fields.get(name).is_some_and(Self::value_is_held)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fully-populated set: every list non-empty, every bool true. Every
    /// name must be reported by `held_names` AND answer true to `has`.
    #[test]
    fn held_names_and_has_agree_when_all_held() {
        let caps = CapabilitiesDef {
            uplink: true,
            net: vec!["example.com".into()],
            kv: vec!["scope".into()],
            fs_read: vec!["/r".into()],
            fs_write: vec!["/w".into()],
            host_process: vec!["bash".into()],
            net_bind: vec!["127.0.0.1:0".into()],
            net_connect: vec!["host:443".into()],
            identity: vec!["resolve".into()],
            allow_prompt_injection: true,
        };
        let names = caps.held_names();
        let expected = [
            "allow_prompt_injection",
            "fs_read",
            "fs_write",
            "host_process",
            "identity",
            "kv",
            "net",
            "net_bind",
            "net_connect",
            "uplink",
        ];
        assert_eq!(
            names, expected,
            "deterministic, sorted order — all 10 fields"
        );
        for n in expected {
            assert!(caps.has(n), "has({n}) must agree with held_names");
        }

        // Derivation guard: with every field held, `held_names` must report
        // EVERY serialized field — not a hand-picked subset. A capability
        // added to `CapabilitiesDef` is then surfaced without editing this
        // module (and if its JSON shape is not bool/array, `value_is_held`
        // fails this on purpose, forcing a deliberate decision).
        let serde_json::Value::Object(fields) = serde_json::to_value(&caps).unwrap() else {
            panic!("CapabilitiesDef serializes to a JSON object");
        };
        assert_eq!(
            names.len(),
            fields.len(),
            "held_names must cover every serialized capability field"
        );
    }

    /// The default (fail-closed) set holds nothing.
    #[test]
    fn default_holds_nothing() {
        let caps = CapabilitiesDef::default();
        assert!(caps.held_names().is_empty());
        for n in [
            "uplink",
            "net",
            "kv",
            "fs_read",
            "fs_write",
            "host_process",
            "net_bind",
            "net_connect",
            "identity",
            "allow_prompt_injection",
        ] {
            assert!(!caps.has(n), "empty set must not report {n}");
        }
    }

    /// Unknown capability names are fail-closed.
    #[test]
    fn unknown_name_is_false() {
        let caps = CapabilitiesDef {
            host_process: vec!["bash".into()],
            ..Default::default()
        };
        assert!(!caps.has("not_a_capability"));
        assert!(!caps.has(""));
        assert!(caps.has("host_process"));
        assert_eq!(caps.held_names(), vec!["host_process".to_string()]);
    }
}
