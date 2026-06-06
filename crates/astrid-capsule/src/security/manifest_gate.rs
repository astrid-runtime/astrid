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
                "capsule '{capsule_id}' denied: network access to '{url}' not declared in manifest"
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
fn net_connect_pattern_matches(pattern: &str, host: &str, port: u16) -> bool {
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
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::manifest::{CapabilitiesDef, CapsuleManifest, PackageDef};

    fn make_manifest(net: Vec<&str>, fs_read: Vec<&str>, fs_write: Vec<&str>) -> CapsuleManifest {
        CapsuleManifest {
            package: PackageDef {
                name: "test".into(),
                version: "0.1.0".into(),
                description: None,
                authors: vec![],
                repository: None,
                homepage: None,
                documentation: None,
                license: None,
                license_file: None,
                readme: None,
                keywords: vec![],
                categories: vec![],
                astrid_version: None,
                publish: None,
                include: None,
                exclude: None,
                metadata: None,
            },
            components: vec![],
            imports: HashMap::new(),
            exports: HashMap::new(),
            capabilities: CapabilitiesDef {
                net: net.into_iter().map(String::from).collect(),
                net_bind: vec![],
                net_connect: vec![],
                kv: vec![],
                fs_read: fs_read.into_iter().map(String::from).collect(),
                fs_write: fs_write.into_iter().map(String::from).collect(),
                host_process: vec![],
                uplink: false,
                identity: vec![],
                allow_prompt_injection: false,
            },
            env: Default::default(),
            context_files: vec![],
            commands: vec![],
            mcp_servers: vec![],
            skills: vec![],
            uplinks: vec![],
            topics: vec![],
            publishes: ::std::collections::HashMap::new(),
            subscribes: ::std::collections::HashMap::new(),
            tools: ::std::vec::Vec::new(),
        }
    }

    fn workspace_root() -> std::path::PathBuf {
        std::path::PathBuf::from("/workspace")
    }

    fn home_root() -> std::path::PathBuf {
        std::path::PathBuf::from("/home/user/.astrid")
    }

    #[tokio::test]
    async fn test_manifest_security_gate_http() {
        let manifest = make_manifest(vec!["api.github.com"], vec![], vec![]);
        let gate = ManifestSecurityGate::new(manifest, workspace_root(), None);

        assert!(
            gate.check_http_request("test", "GET", "https://api.github.com/v1")
                .await
                .is_ok()
        );
        assert!(
            gate.check_http_request("test", "GET", "https://v1.api.github.com/v1")
                .await
                .is_ok()
        );
        assert!(
            gate.check_http_request("test", "GET", "https://evil.com/v1")
                .await
                .is_err()
        );
        assert!(
            gate.check_http_request("test", "GET", "http://api.github.com@127.0.0.1/admin")
                .await
                .is_err()
        );
        assert!(
            gate.check_http_request("test", "GET", "http://github.com/v1")
                .await
                .is_err()
        );

        let all_manifest = make_manifest(vec!["*"], vec![], vec![]);
        let all_gate = ManifestSecurityGate::new(all_manifest, workspace_root(), None);
        assert!(
            all_gate
                .check_http_request("test", "GET", "https://evil.com/v1")
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn test_manifest_security_gate_fs() {
        let manifest = make_manifest(vec![], vec!["/workspace/src", "/tmp/exact.txt"], vec!["*"]);
        let gate = ManifestSecurityGate::new(manifest, workspace_root(), None);

        // Path matches correctly
        assert!(
            gate.check_file_read("test", "/workspace/src/main.rs", None)
                .await
                .is_ok()
        );
        assert!(
            gate.check_file_read("test", "/tmp/exact.txt", None)
                .await
                .is_ok()
        );

        // Path boundary correctly enforced
        assert!(
            gate.check_file_read("test", "/workspace/src-evil/main.rs", None)
                .await
                .is_err()
        );
        assert!(
            gate.check_file_read("test", "/workspace/src_evil/main.rs", None)
                .await
                .is_err()
        );
        assert!(
            gate.check_file_read("test", "/workspace/src", None)
                .await
                .is_ok()
        ); // Exact match is OK

        // Write wildcard is confined to workspace root — paths outside are denied.
        assert!(
            gate.check_file_write("test", "/workspace/src/main.rs", None)
                .await
                .is_ok()
        );
        assert!(
            gate.check_file_write("test", "/etc/passwd", None)
                .await
                .is_err()
        );
        assert!(
            gate.check_file_write("test", "/random/file.txt", None)
                .await
                .is_err()
        );

        // Path traversal via .. must be rejected even with explicit prefix match
        assert!(
            gate.check_file_read("test", "/workspace/src/../../etc/passwd", None)
                .await
                .is_err(),
            "path traversal via .. must be rejected"
        );
    }

    #[tokio::test]
    async fn test_scheme_resolution_workspace() {
        let manifest = make_manifest(vec![], vec!["cwd://"], vec![]);
        let gate = ManifestSecurityGate::new(manifest, workspace_root(), None);

        assert!(
            gate.check_file_read("test", "/workspace/src/main.rs", None)
                .await
                .is_ok()
        );
        assert!(
            gate.check_file_read("test", "/other/path", None)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_scheme_resolution_home_default_root() {
        let manifest = make_manifest(vec![], vec!["home://"], vec![]);
        let gate = ManifestSecurityGate::new(manifest, workspace_root(), Some(home_root()));

        // With no principal_home override, falls back to default_home_root (capsule owner's).
        assert!(
            gate.check_file_read("test", "/home/user/.astrid/skills/my-skill/SKILL.md", None)
                .await
                .is_ok()
        );
        assert!(
            gate.check_file_read("test", "/workspace/src/main.rs", None)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_scheme_resolution_home_principal_override() {
        // With principal_home supplied, home:// resolves against it, not the default.
        let manifest = make_manifest(vec![], vec!["home://"], vec![]);
        let gate = ManifestSecurityGate::new(manifest, workspace_root(), Some(home_root()));

        let alice = std::path::PathBuf::from("/home/user/.astrid/home/alice");

        // Alice's home paths are allowed when principal_home is alice.
        assert!(
            gate.check_file_read(
                "test",
                "/home/user/.astrid/home/alice/note.txt",
                Some(&alice),
            )
            .await
            .is_ok()
        );
        // The default-principal path is NOT automatically allowed when alice's
        // home is the active principal home.
        assert!(
            gate.check_file_read(
                "test",
                "/home/user/.astrid/skills/my-skill/SKILL.md",
                Some(&alice),
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn test_home_cross_principal_denied() {
        // Alice active, path is Bob's home -> denied (path not under alice's root).
        let manifest = make_manifest(vec![], vec!["home://"], vec![]);
        let gate = ManifestSecurityGate::new(manifest, workspace_root(), None);

        let alice = std::path::PathBuf::from("/home/user/.astrid/home/alice");
        let bob_path = "/home/user/.astrid/home/bob/secret.txt";
        assert!(
            gate.check_file_read("test", bob_path, Some(&alice))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_home_traversal_denied() {
        // Even with principal_home set, traversal components are rejected
        // before any starts_with match is attempted.
        let manifest = make_manifest(vec![], vec!["home://"], vec![]);
        let gate = ManifestSecurityGate::new(manifest, workspace_root(), None);

        let alice = std::path::PathBuf::from("/home/user/.astrid/home/alice");
        let attack = "/home/user/.astrid/home/alice/../bob/secret.txt";
        assert!(
            gate.check_file_read("test", attack, Some(&alice))
                .await
                .is_err(),
            "traversal via .. must be rejected even with principal_home"
        );
    }

    #[tokio::test]
    async fn test_scheme_resolution_home_without_default_root() {
        // When no default root is configured AND no principal_home is passed,
        // home:// entries match nothing.
        let manifest = make_manifest(vec![], vec!["home://"], vec![]);
        let gate = ManifestSecurityGate::new(manifest, workspace_root(), None);

        assert!(
            gate.check_file_read("test", "/home/user/.astrid/skills/my-skill/SKILL.md", None,)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_scheme_resolution_both() {
        let manifest = make_manifest(vec![], vec!["cwd://", "home://"], vec![]);
        let gate = ManifestSecurityGate::new(manifest, workspace_root(), Some(home_root()));

        assert!(
            gate.check_file_read("test", "/workspace/src/main.rs", None)
                .await
                .is_ok()
        );
        assert!(
            gate.check_file_read("test", "/home/user/.astrid/config.toml", None)
                .await
                .is_ok()
        );
        assert!(
            gate.check_file_read("test", "/etc/passwd", None)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_global_path_denied_without_manifest_entry() {
        // Manifest only has cwd://, no home:// — global paths must be denied
        // even when home_root is configured.
        let manifest = make_manifest(vec![], vec!["cwd://"], vec![]);
        let gate = ManifestSecurityGate::new(manifest, workspace_root(), Some(home_root()));

        assert!(
            gate.check_file_read("test", "/home/user/.astrid/skills/foo/SKILL.md", None)
                .await
                .is_err()
        );
        // Workspace paths should still work
        assert!(
            gate.check_file_read("test", "/workspace/src/main.rs", None)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn wildcard_confined_to_workspace_root() {
        // Use a real tempdir so canonicalize() resolves correctly on all platforms
        // (e.g. macOS /tmp -> /private/tmp).
        let tmp = tempfile::tempdir().unwrap();
        let ws = tmp.path().join("project");
        std::fs::create_dir_all(&ws).unwrap();
        let canonical_ws = ws.canonicalize().unwrap();

        let manifest = make_manifest(vec![], vec!["*"], vec!["*"]);
        let gate = ManifestSecurityGate::new(manifest, ws, None);

        // Paths under the canonical workspace root are allowed
        let read_path = canonical_ws.join("src/main.rs");
        assert!(
            gate.check_file_read("test", read_path.to_str().unwrap(), None)
                .await
                .is_ok()
        );
        let write_path = canonical_ws.join("out/file.txt");
        assert!(
            gate.check_file_write("test", write_path.to_str().unwrap(), None)
                .await
                .is_ok()
        );

        // Paths outside the workspace root are denied even with wildcard
        assert!(
            gate.check_file_read("test", "/etc/passwd", None)
                .await
                .is_err()
        );
        assert!(
            gate.check_file_write("test", "/home/user/.astrid/keys/user.key", None)
                .await
                .is_err()
        );

        // Prefix-collision attack: /project-evil should NOT match /project
        let evil_path = canonical_ws.parent().unwrap().join("project-evil/file.txt");
        assert!(
            gate.check_file_write("test", evil_path.to_str().unwrap(), None)
                .await
                .is_err()
        );

        // Path traversal attack: /workspace/../../etc/passwd must be rejected
        // even though it starts_with /workspace at component level.
        let traversal = format!("{}/../../etc/passwd", canonical_ws.display());
        assert!(
            gate.check_file_read("test", &traversal, None)
                .await
                .is_err(),
            "path traversal via .. must be rejected"
        );
        assert!(
            gate.check_file_write("test", &traversal, None)
                .await
                .is_err(),
            "path traversal via .. must be rejected for writes"
        );
    }

    #[tokio::test]
    async fn net_bind_gate_enforced() {
        // No net_bind capability -> denied
        let manifest = make_manifest(vec![], vec![], vec![]);
        let gate = ManifestSecurityGate::new(manifest, workspace_root(), None);
        assert!(gate.check_net_bind("test").await.is_err());

        // With net_bind capability -> allowed
        let mut manifest2 = make_manifest(vec![], vec![], vec![]);
        manifest2.capabilities.net_bind = vec!["unix:///tmp/sock".into()];
        let gate2 = ManifestSecurityGate::new(manifest2, workspace_root(), None);
        assert!(gate2.check_net_bind("test").await.is_ok());

        // Empty string in net_bind is treated as malformed -> denied
        let mut manifest3 = make_manifest(vec![], vec![], vec![]);
        manifest3.capabilities.net_bind = vec!["".into()];
        let gate3 = ManifestSecurityGate::new(manifest3, workspace_root(), None);
        assert!(gate3.check_net_bind("test").await.is_err());
    }

    #[tokio::test]
    async fn identity_gate_deny_by_default() {
        let manifest = make_manifest(vec![], vec![], vec![]);
        let gate = ManifestSecurityGate::new(manifest, workspace_root(), None);

        assert!(
            gate.check_identity("test", IdentityOperation::Resolve)
                .await
                .is_err()
        );
        assert!(
            gate.check_identity("test", IdentityOperation::Link)
                .await
                .is_err()
        );
        assert!(
            gate.check_identity("test", IdentityOperation::CreateUser)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn identity_gate_resolve_only() {
        let mut manifest = make_manifest(vec![], vec![], vec![]);
        manifest.capabilities.identity = vec!["resolve".into()];
        let gate = ManifestSecurityGate::new(manifest, workspace_root(), None);

        assert!(
            gate.check_identity("test", IdentityOperation::Resolve)
                .await
                .is_ok()
        );
        assert!(
            gate.check_identity("test", IdentityOperation::Link)
                .await
                .is_err()
        );
        assert!(
            gate.check_identity("test", IdentityOperation::CreateUser)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn identity_gate_link_implies_resolve() {
        let mut manifest = make_manifest(vec![], vec![], vec![]);
        manifest.capabilities.identity = vec!["link".into()];
        let gate = ManifestSecurityGate::new(manifest, workspace_root(), None);

        assert!(
            gate.check_identity("test", IdentityOperation::Resolve)
                .await
                .is_ok()
        );
        assert!(
            gate.check_identity("test", IdentityOperation::Link)
                .await
                .is_ok()
        );
        assert!(
            gate.check_identity("test", IdentityOperation::Unlink)
                .await
                .is_ok()
        );
        assert!(
            gate.check_identity("test", IdentityOperation::ListLinks)
                .await
                .is_ok()
        );
        assert!(
            gate.check_identity("test", IdentityOperation::CreateUser)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn identity_gate_admin_implies_all() {
        let mut manifest = make_manifest(vec![], vec![], vec![]);
        manifest.capabilities.identity = vec!["admin".into()];
        let gate = ManifestSecurityGate::new(manifest, workspace_root(), None);

        assert!(
            gate.check_identity("test", IdentityOperation::Resolve)
                .await
                .is_ok()
        );
        assert!(
            gate.check_identity("test", IdentityOperation::Link)
                .await
                .is_ok()
        );
        assert!(
            gate.check_identity("test", IdentityOperation::CreateUser)
                .await
                .is_ok()
        );
    }

    #[test]
    fn net_connect_exact_match() {
        assert!(net_connect_pattern_matches(
            "example.com:443",
            "example.com",
            443
        ));
    }

    #[test]
    fn net_connect_port_mismatch_is_denied() {
        assert!(!net_connect_pattern_matches(
            "example.com:443",
            "example.com",
            80
        ));
    }

    #[test]
    fn net_connect_host_mismatch_is_denied() {
        assert!(!net_connect_pattern_matches(
            "example.com:443",
            "evil.com",
            443
        ));
    }

    #[test]
    fn net_connect_port_wildcard_matches_any_port() {
        assert!(net_connect_pattern_matches(
            "example.com:*",
            "example.com",
            1
        ));
        assert!(net_connect_pattern_matches(
            "example.com:*",
            "example.com",
            65535
        ));
    }

    #[test]
    fn net_connect_host_is_case_insensitive() {
        assert!(net_connect_pattern_matches(
            "Example.COM:443",
            "example.com",
            443
        ));
    }

    #[test]
    fn net_connect_missing_colon_is_denied() {
        assert!(!net_connect_pattern_matches(
            "example.com",
            "example.com",
            80
        ));
    }

    #[test]
    fn net_connect_invalid_port_is_denied() {
        assert!(!net_connect_pattern_matches(
            "example.com:abc",
            "example.com",
            80
        ));
    }

    #[tokio::test]
    async fn check_net_connect_default_denies_with_empty_allowlist() {
        let mut manifest = make_manifest(vec![], vec![], vec![]);
        manifest.capabilities.net_connect = vec![];
        let gate = ManifestSecurityGate::new(manifest, workspace_root(), None);
        let err = gate
            .check_net_connect("c", "example.com", 443)
            .await
            .unwrap_err();
        assert!(err.contains("not in net_connect allowlist"), "{err}");
    }

    #[tokio::test]
    async fn check_net_connect_matches_allowlist_entry() {
        let mut manifest = make_manifest(vec![], vec![], vec![]);
        manifest.capabilities.net_connect = vec!["example.com:443".to_string()];
        let gate = ManifestSecurityGate::new(manifest, workspace_root(), None);
        assert!(
            gate.check_net_connect("c", "example.com", 443)
                .await
                .is_ok()
        );
        assert!(
            gate.check_net_connect("c", "example.com", 80)
                .await
                .is_err()
        );
        assert!(gate.check_net_connect("c", "evil.com", 443).await.is_err());
    }
}
