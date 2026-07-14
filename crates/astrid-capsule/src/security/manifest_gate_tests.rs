//! Tests for `manifest_gate.rs`. Split out to keep `manifest_gate.rs` under the
//! 1000-line CI threshold. Included via `#[path]` from its sibling.

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
            bind_workers: None,
            net_connect: vec![],
            kv: vec![],
            fs_read: fs_read.into_iter().map(String::from).collect(),
            fs_write: fs_write.into_iter().map(String::from).collect(),
            host_process: vec![],
            allow_persistent: false,
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
        gate.check_file_read("test", "/home/user/.astrid/documents/project/note.md", None)
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
            "/home/user/.astrid/documents/project/note.md",
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
        gate.check_file_read("test", "/home/user/.astrid/documents/project/note.md", None,)
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
        gate.check_file_read("test", "/home/user/.astrid/documents/project/note.md", None)
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

#[tokio::test]
async fn check_net_tcp_bind_matches_net_bind_host_port() {
    let mut manifest = make_manifest(vec![], vec![], vec![]);
    manifest.capabilities.net_bind = vec!["127.0.0.1:8799".to_string()];
    let gate = ManifestSecurityGate::new(manifest, workspace_root(), None);
    // Exact host:port allowed.
    assert!(gate.check_net_tcp_bind("c", "127.0.0.1", 8799).await.is_ok());
    // Wrong port denied.
    assert!(gate.check_net_tcp_bind("c", "127.0.0.1", 9000).await.is_err());
    // Wrong host denied.
    assert!(gate.check_net_tcp_bind("c", "0.0.0.0", 8799).await.is_err());
}

#[tokio::test]
async fn check_net_tcp_bind_wildcard_port() {
    let mut manifest = make_manifest(vec![], vec![], vec![]);
    manifest.capabilities.net_bind = vec!["127.0.0.1:*".to_string()];
    let gate = ManifestSecurityGate::new(manifest, workspace_root(), None);
    assert!(gate.check_net_tcp_bind("c", "127.0.0.1", 8799).await.is_ok());
    assert!(gate.check_net_tcp_bind("c", "127.0.0.1", 1234).await.is_ok());
}

#[tokio::test]
async fn check_net_tcp_bind_unix_entry_does_not_authorize_tcp() {
    // The CLI proxy declares `net_bind = ["unix:*"]`. That entry must NEVER
    // authorize an inbound TCP bind — the two socket families share the field
    // without cross-authorizing.
    let mut manifest = make_manifest(vec![], vec![], vec![]);
    manifest.capabilities.net_bind = vec!["unix:*".to_string()];
    let gate = ManifestSecurityGate::new(manifest, workspace_root(), None);
    assert!(gate.check_net_tcp_bind("c", "127.0.0.1", 8799).await.is_err());
}

#[tokio::test]
async fn check_net_tcp_bind_empty_net_bind_denies() {
    let manifest = make_manifest(vec![], vec![], vec![]);
    let gate = ManifestSecurityGate::new(manifest, workspace_root(), None);
    assert!(gate.check_net_tcp_bind("c", "127.0.0.1", 8799).await.is_err());
}
