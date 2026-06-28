//! Production [`CapsuleSecurityGate`] implementation backed by the capsule's
//! declared manifest capabilities.

use async_trait::async_trait;

use super::{CapsuleSecurityGate, IdentityOperation, identity_capability_satisfies};
use crate::manifest::CapsuleManifest;

/// Security gate that enforces capabilities based on the manifest.
/// Assumes capabilities declared in the manifest were approved by the user during installation.
///
/// The `cwd://` scheme prefix is resolved to a physical path at construction
/// time so that runtime path checks use simple `starts_with` matching. The
/// `home://` scheme is resolved dynamically at check time so that shared
/// capsules can route file access to the invoking principal's home directory
/// (see `principal_home` parameter on `check_file_read` / `check_file_write`).
#[derive(Debug, Clone)]
pub(crate) struct ManifestSecurityGate {
    /// The original manifest. `net` and `host_process` fields are queried
    /// at runtime as-is. `fs_read` / `fs_write` are **not** used at runtime —
    /// their scheme-aware split lives in `resolved_static_*` and
    /// `home_suffixes_*`.
    manifest: CapsuleManifest,
    /// Non-`home://` fs_read patterns, fully resolved at construction time.
    /// Includes `cwd://`-resolved paths, wildcard `"*"`, and literal paths.
    resolved_static_read: Vec<String>,
    /// Non-`home://` fs_write patterns, fully resolved at construction time.
    resolved_static_write: Vec<String>,
    /// Suffix strings from `home://<suffix>` fs_read entries. Resolved at
    /// check time against the invocation principal's home root (or the
    /// construction-time `default_home_root` fallback).
    home_suffixes_read: Vec<String>,
    /// Suffix strings from `home://<suffix>` fs_write entries.
    home_suffixes_write: Vec<String>,
    /// Canonical construction-time home root, used as fallback when the
    /// caller does not supply `principal_home`. Typically the capsule's
    /// default-principal home. `None` means no fallback — home patterns are
    /// denied unless the caller provides an explicit `principal_home`.
    default_home_root: Option<std::path::PathBuf>,
    /// Canonical workspace root used to confine wildcard (`"*"`) file access.
    /// Wildcard only matches paths under this root — not the entire filesystem.
    /// Stored as `PathBuf` so that `Path::starts_with` handles component-boundary
    /// matching correctly (e.g. `/workspace-evil` does NOT match `/workspace`).
    workspace_root_path: std::path::PathBuf,
}

impl ManifestSecurityGate {
    pub(crate) fn new(
        manifest: CapsuleManifest,
        workspace_root: std::path::PathBuf,
        home_root: Option<std::path::PathBuf>,
    ) -> Self {
        // Canonicalize roots once up front. Both `partition_schemes` (for prefix
        // strings) and `workspace_root_path` (for wildcard confinement) use
        // the same canonical values, avoiding redundant syscalls.
        let canonical_ws = workspace_root
            .canonicalize()
            .unwrap_or_else(|_| workspace_root.to_path_buf());
        let canonical_home = home_root
            .as_ref()
            .map(|g| g.canonicalize().unwrap_or_else(|_| g.clone()));

        let (resolved_static_read, home_suffixes_read) =
            Self::partition_schemes(&manifest.capabilities.fs_read, &canonical_ws);
        let (resolved_static_write, home_suffixes_write) =
            Self::partition_schemes(&manifest.capabilities.fs_write, &canonical_ws);
        Self {
            manifest,
            resolved_static_read,
            resolved_static_write,
            home_suffixes_read,
            home_suffixes_write,
            default_home_root: canonical_home,
            workspace_root_path: canonical_ws,
        }
    }

    /// Split VFS scheme prefixes into static (resolved at construction) and
    /// `home://` suffix entries (resolved at check time against the invocation
    /// principal's home).
    ///
    /// - `cwd://` → `<cwd>/...` (static)
    /// - `home://suffix` → `"suffix"` added to home suffixes (dynamic)
    /// - `*` → kept as-is (static; confined to workspace at check time)
    /// - literal path → kept as-is (static)
    ///
    /// Expects a pre-canonicalized workspace root.
    fn partition_schemes(
        entries: &[String],
        canonical_ws: &std::path::Path,
    ) -> (Vec<String>, Vec<String>) {
        let mut statics = Vec::with_capacity(entries.len());
        let mut home_suffixes = Vec::new();
        for entry in entries {
            if entry == "*" {
                statics.push("*".to_string());
            } else if let Some(suffix) = entry.strip_prefix("cwd://") {
                let path = canonical_ws.join(suffix);
                statics.push(path.to_string_lossy().to_string());
            } else if let Some(suffix) = entry.strip_prefix("home://") {
                // Defer resolution until check time so we can target the
                // per-invocation principal's home root.
                home_suffixes.push(suffix.to_string());
            } else {
                statics.push(entry.clone());
            }
        }
        (statics, home_suffixes)
    }

    /// Check a filesystem path against a list of resolved static patterns plus
    /// a list of `home://` suffixes resolved against the given principal_home.
    ///
    /// Rejects paths containing `..` (ParentDir) components to prevent traversal
    /// attacks like `/workspace/../../etc/passwd` which would pass a naive
    /// `starts_with` check. Uses `Path::starts_with` for component-boundary
    /// matching, so `/workspace-evil` does NOT match `/workspace`.
    ///
    /// When a wildcard `"*"` is present, it only matches paths under the
    /// canonical workspace root — preventing escape to global paths
    /// (e.g. `~/.astrid/keys/`).
    ///
    /// If `principal_home` is `Some`, it supersedes `default_home_root` for
    /// resolving `home://` suffixes. If both are `None` and the manifest has
    /// `home://` entries, those entries do not match anything.
    fn check_fs_permission(
        &self,
        path: &str,
        statics: &[String],
        home_suffixes: &[String],
        principal_home: Option<&std::path::Path>,
    ) -> bool {
        let path_obj = std::path::Path::new(path);

        // Reject paths with '..' components — these can bypass starts_with checks
        // (e.g. /workspace/../../etc/passwd starts_with /workspace but resolves outside).
        if path_obj
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return false;
        }

        if statics.iter().any(|p| {
            if p == "*" {
                path_obj.starts_with(&self.workspace_root_path)
            } else {
                path_obj.starts_with(p)
            }
        }) {
            return true;
        }

        let effective_home: Option<std::path::PathBuf> = principal_home
            .map(std::path::Path::to_path_buf)
            .or_else(|| self.default_home_root.clone());

        let Some(home) = effective_home else {
            return false;
        };

        home_suffixes
            .iter()
            .any(|suffix| path_obj.starts_with(home.join(suffix)))
    }
}

#[async_trait]
impl CapsuleSecurityGate for ManifestSecurityGate {
    async fn check_http_request(
        &self,
        capsule_id: &str,
        _method: &str,
        url: &str,
    ) -> Result<(), String> {
        let parsed_url = reqwest::Url::parse(url).map_err(|e| format!("Invalid URL: {e}"))?;
        let host_str = parsed_url.host_str().unwrap_or("");

        if self
            .manifest
            .capabilities
            .net
            .iter()
            .any(|d| d == "*" || host_str == d || host_str.ends_with(&format!(".{d}")))
        {
            Ok(())
        } else {
            Err(format!(
                "capsule '{capsule_id}' denied: network access to host '{host_str}' not declared in manifest"
            ))
        }
    }

    async fn check_file_read(
        &self,
        capsule_id: &str,
        path: &str,
        principal_home: Option<&std::path::Path>,
    ) -> Result<(), String> {
        if self.check_fs_permission(
            path,
            &self.resolved_static_read,
            &self.home_suffixes_read,
            principal_home,
        ) {
            Ok(())
        } else {
            Err(format!(
                "capsule '{capsule_id}' denied: read access to '{path}' not declared in manifest"
            ))
        }
    }

    async fn check_file_write(
        &self,
        capsule_id: &str,
        path: &str,
        principal_home: Option<&std::path::Path>,
    ) -> Result<(), String> {
        if self.check_fs_permission(
            path,
            &self.resolved_static_write,
            &self.home_suffixes_write,
            principal_home,
        ) {
            Ok(())
        } else {
            Err(format!(
                "capsule '{capsule_id}' denied: write access to '{path}' not declared in manifest"
            ))
        }
    }

    async fn check_host_process(&self, capsule_id: &str, command: &str) -> Result<(), String> {
        if self
            .manifest
            .capabilities
            .host_process
            .iter()
            .any(|cmd| command == cmd || command.starts_with(&format!("{cmd} ")))
        {
            Ok(())
        } else {
            Err(format!(
                "capsule '{capsule_id}' denied: host process '{command}' not declared in manifest"
            ))
        }
    }

    async fn check_net_bind(&self, capsule_id: &str) -> Result<(), String> {
        // Require at least one non-empty net_bind entry. Empty strings in the
        // manifest are treated as malformed and do not grant capability.
        let has_valid_entry = self
            .manifest
            .capabilities
            .net_bind
            .iter()
            .any(|entry| !entry.is_empty());
        if has_valid_entry {
            Ok(())
        } else {
            Err(format!(
                "capsule '{capsule_id}' denied: net_bind not declared in manifest"
            ))
        }
    }

    async fn check_net_connect(
        &self,
        capsule_id: &str,
        host: &str,
        port: u16,
    ) -> Result<(), String> {
        // Each allowlist entry is "host:port" or "host:*". Match against the
        // literal host the capsule named; DNS resolution and SSRF check run
        // after this gate.
        let allowed = self
            .manifest
            .capabilities
            .net_connect
            .iter()
            .any(|entry| net_connect_pattern_matches(entry, host, port));
        if allowed {
            Ok(())
        } else {
            Err(format!(
                "capsule '{capsule_id}' denied: \"{host}:{port}\" not in net_connect allowlist"
            ))
        }
    }

    async fn check_identity(
        &self,
        capsule_id: &str,
        operation: IdentityOperation,
    ) -> Result<(), String> {
        let required = operation.required_capability();
        if identity_capability_satisfies(&self.manifest.capabilities.identity, required) {
            Ok(())
        } else {
            Err(format!(
                "capsule '{capsule_id}' denied: identity operation '{required}' \
                 not declared in manifest (has: {:?})",
                self.manifest.capabilities.identity
            ))
        }
    }
}

/// Match a `net_connect` allowlist entry against a literal `host:port`.
///
/// Patterns:
///   - `"host:port"` — exact match.
///   - `"host:*"` — any port for the named host.
///
/// Hostnames are compared case-insensitively (DNS names are case-insensitive
/// per RFC 1035). The pattern host segment is taken literally — DNS-style
/// wildcards (`*.example.com`) are intentionally NOT supported in this version
/// (see RFC: rfcs#27 Unresolved questions).
///
/// Shared with the HTTP host's local-egress allowlist
/// (`engine::wasm::host::http`) so manifest `net_connect` and the operator
/// `[security.capsule_local_egress]` allowlist use identical `host:port`
/// matching semantics.
pub(crate) fn net_connect_pattern_matches(pattern: &str, host: &str, port: u16) -> bool {
    let Some((pat_host, pat_port)) = pattern.rsplit_once(':') else {
        return false;
    };
    if !pat_host.eq_ignore_ascii_case(host) {
        return false;
    }
    match pat_port {
        "*" => true,
        p => p.parse::<u16>().is_ok_and(|n| n == port),
    }
}

#[cfg(test)]
#[path = "manifest_gate_tests.rs"]
mod tests;
