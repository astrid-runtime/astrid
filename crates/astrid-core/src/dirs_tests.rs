//! Tests for `dirs.rs`. Split out to keep `dirs.rs` under the 1000-line CI
//! threshold. Included via `#[path]` from its sibling.

use super::*;

fn migration_target() -> LayoutMigrationTarget {
    LayoutMigrationTarget::new("test-store/3;state-owner-codec/2", "test-binary/1").unwrap()
}

fn test_home_root(dir: &tempfile::TempDir) -> PathBuf {
    #[cfg(windows)]
    {
        dir.path().join("astrid-home")
    }
    #[cfg(not(windows))]
    {
        dir.path().to_path_buf()
    }
}

fn parent_traversal_path() -> String {
    #[cfg(windows)]
    {
        r"C:\tmp\..\etc".to_owned()
    }
    #[cfg(not(windows))]
    {
        "/tmp/../etc".to_owned()
    }
}

fn absolute_test_home() -> String {
    #[cfg(windows)]
    {
        r"C:\Users\astrid-test".to_owned()
    }
    #[cfg(not(windows))]
    {
        std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_owned())
    }
}

// ── AstridHome resolution ────────────────────────────────────────

#[test]
fn test_astrid_home_resolve_with_env() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    let path_str = path.to_string_lossy().to_string();

    let home = AstridHome::resolve_with_env(Some(path_str), None).unwrap();
    assert_eq!(home.root(), path);
}

#[test]
fn test_astrid_home_resolve_default() {
    let home_val = absolute_test_home();
    let home = AstridHome::resolve_with_env(None, Some(home_val.clone())).unwrap();
    let expected = PathBuf::from(home_val).join(".astrid");
    assert_eq!(home.root(), expected);
}

#[test]
fn test_astrid_home_rejects_traversal_in_astrid_home() {
    let result = AstridHome::resolve_with_env(Some(parent_traversal_path()), None);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("'..'"),
        "expected path traversal error, got: {err}"
    );
}

#[test]
fn test_astrid_home_rejects_traversal_in_home() {
    let result = AstridHome::resolve_with_env(None, Some(parent_traversal_path()));
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("'..'"),
        "expected path traversal error, got: {err}"
    );
}

#[test]
fn test_astrid_home_rejects_relative_env() {
    let result = AstridHome::resolve_with_env(Some("relative/path".to_string()), None);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("absolute"));
}

#[test]
fn test_astrid_home_rejects_empty_env() {
    let result = AstridHome::resolve_with_env(Some(String::new()), None);
    assert!(result.is_err());
}

#[test]
fn test_astrid_home_rejects_relative_home() {
    let result = AstridHome::resolve_with_env(None, Some("relative/path".to_string()));
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("absolute"));
}

// ── AstridHome ensure ────────────────────────────────────────────

#[test]
fn test_astrid_home_ensure_creates_dirs() {
    let dir = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(test_home_root(&dir));
    home.ensure().unwrap();

    assert!(home.etc_dir().exists());
    assert!(home.hooks_dir().exists());
    assert!(home.var_dir().exists());
    assert!(home.run_dir().exists());
    assert!(home.log_dir().exists());
    assert!(home.keys_dir().exists());
    assert!(home.secrets_dir().exists());
    assert!(home.bin_dir().exists());
    assert!(home.home_dir().exists());
    assert!(home.content_staging_path().exists());
    assert!(home.migrations_dir().exists());
    assert!(home.cow_dir().exists());
    assert!(home.fleets_dir().exists());
}

#[test]
fn test_astrid_home_ensure_writes_layout_version() {
    let dir = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(test_home_root(&dir));
    home.ensure().unwrap();

    let version_path = home.etc_dir().join("layout-version");
    assert!(version_path.exists());
    let content = std::fs::read_to_string(&version_path).unwrap();
    assert_eq!(content, LAYOUT_VERSION);
}

#[test]
fn test_astrid_home_ensure_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(test_home_root(&dir));
    home.ensure().unwrap();
    home.ensure().unwrap(); // second call should not fail
}

#[test]
fn test_nonempty_home_without_layout_sentinel_is_refused_without_mutation() {
    let dir = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(test_home_root(&dir));
    let legacy = home.var_dir().join("state.db");
    crate::platform_fs::ensure_private_directory(&legacy).unwrap();
    std::fs::write(legacy.join("legacy"), b"preserve-me").unwrap();

    let error = home.ensure().unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(!home.layout_version_path().exists());
    assert_eq!(
        std::fs::read(legacy.join("legacy")).unwrap(),
        b"preserve-me"
    );
    assert!(!home.srv_dir().exists());
}

#[test]
fn test_layout_version_requires_canonical_exact_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(test_home_root(&dir));
    crate::platform_fs::ensure_private_directory(&home.etc_dir()).unwrap();
    std::fs::write(home.layout_version_path(), b"1\n").unwrap();

    let error = home.ensure().unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(!home.var_dir().exists());
}

#[test]
fn test_astrid_home_rejects_unknown_layout_before_mutation() {
    let dir = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(test_home_root(&dir));
    crate::platform_fs::ensure_private_directory(&home.etc_dir()).unwrap();
    std::fs::write(home.layout_version_path(), "999").unwrap();

    let error = home.ensure().unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(!home.var_dir().exists());
    assert_eq!(
        std::fs::read_to_string(home.layout_version_path()).unwrap(),
        "999"
    );
}

#[test]
fn test_layout_v1_is_not_committed_until_store_and_ownership_finish() {
    let dir = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(test_home_root(&dir));
    crate::platform_fs::ensure_private_directory(&home.etc_dir()).unwrap();
    std::fs::write(home.layout_version_path(), LEGACY_LAYOUT_VERSION).unwrap();

    home.ensure().unwrap();

    assert_eq!(
        std::fs::read_to_string(home.layout_version_path()).unwrap(),
        LEGACY_LAYOUT_VERSION
    );
    assert!(!home.srv_dir().exists());
    assert!(!home.migrations_dir().exists());
}

#[cfg(not(windows))]
#[test]
fn test_layout_v1_completion_preserves_existing_tree_and_creates_fleet_roots() {
    let dir = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(test_home_root(&dir));
    crate::platform_fs::ensure_private_directory(&home.etc_dir()).unwrap();
    std::fs::write(home.layout_version_path(), LEGACY_LAYOUT_VERSION).unwrap();
    home.ensure().unwrap();
    let preserved = home
        .principal_home(&PrincipalId::default())
        .root()
        .join("note");
    std::fs::create_dir_all(preserved.parent().unwrap()).unwrap();
    std::fs::write(&preserved, b"released-home-bytes").unwrap();
    let fleet = crate::FleetUid::from_bytes([7; 32]);

    home.begin_layout_v2_migration(&migration_target()).unwrap();
    home.complete_layout_v2([fleet], &migration_target())
        .unwrap();

    assert_eq!(std::fs::read(&preserved).unwrap(), b"released-home-bytes");
    assert!(home.fleet_shared_dir(fleet).is_dir());
    assert!(home.fleet_workspaces_dir(fleet).is_dir());
    assert!(
        home.migrations_dir()
            .join("layout-v1-to-v2.intent")
            .is_file()
    );
    assert!(
        home.migrations_dir()
            .join("layout-v1-to-v2.complete")
            .is_file()
    );
    assert_eq!(
        std::fs::read_to_string(home.layout_version_path()).unwrap(),
        LAYOUT_VERSION
    );
    home.complete_layout_v2([fleet], &migration_target())
        .unwrap();
}

#[cfg(not(windows))]
#[test]
fn test_layout_migration_records_are_canonical_and_content_bound() {
    let dir = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(test_home_root(&dir));
    crate::platform_fs::ensure_private_directory(&home.etc_dir()).unwrap();
    std::fs::write(home.layout_version_path(), LEGACY_LAYOUT_VERSION).unwrap();
    home.ensure().unwrap();
    std::fs::create_dir_all(home.state_db_path()).unwrap();
    std::fs::write(home.state_db_path().join("legacy"), b"legacy-bytes").unwrap();
    std::fs::create_dir_all(home.principal_store_path()).unwrap();
    let fleet = crate::FleetUid::from_bytes([11; 32]);

    home.begin_layout_v2_migration(&migration_target()).unwrap();
    home.complete_layout_v2([fleet], &migration_target())
        .unwrap();

    let intent_path = home.migrations_dir().join("layout-v1-to-v2.intent");
    let receipt_path = home.migrations_dir().join("layout-v1-to-v2.complete");
    let intent = std::fs::read(&intent_path).unwrap();
    let receipt = std::fs::read(&receipt_path).unwrap();
    assert_eq!(intent.last(), Some(&b'\n'));
    let value: serde_json::Value = serde_json::from_slice(&intent).unwrap();
    let receipt_value: serde_json::Value = serde_json::from_slice(&receipt).unwrap();
    assert_eq!(value["schema"], 1);
    assert_eq!(value["material"]["source"]["entries"], 1);
    assert_eq!(value["material"]["source"]["bytes"], 12);
    assert_eq!(
        value["material"]["target_store_format"],
        "test-store/3;state-owner-codec/2"
    );
    assert_eq!(value["transaction_id"].as_str().unwrap().len(), 64);
    assert_eq!(receipt_value["intent"], value);
    assert_eq!(receipt_value["transaction_id"], value["transaction_id"]);
    assert_eq!(
        receipt_value["fleet_uids"],
        serde_json::json!([fleet.to_string()])
    );

    std::fs::write(home.layout_version_path(), LEGACY_LAYOUT_VERSION).unwrap();
    let other_fleet = crate::FleetUid::from_bytes([12; 32]);
    let error = home
        .complete_layout_v2([other_fleet], &migration_target())
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(std::fs::read(intent_path).unwrap(), intent);
}

#[cfg(unix)]
#[test]
fn test_layout_migration_rejects_redirected_destination_before_intent() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(test_home_root(&dir));
    crate::platform_fs::ensure_private_directory(&home.etc_dir()).unwrap();
    std::fs::write(home.layout_version_path(), LEGACY_LAYOUT_VERSION).unwrap();
    home.ensure().unwrap();
    symlink(outside.path(), home.srv_dir()).unwrap();

    let error = home
        .begin_layout_v2_migration(&migration_target())
        .unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(!home.migrations_dir().exists());
    assert_eq!(
        std::fs::read_to_string(home.layout_version_path()).unwrap(),
        LEGACY_LAYOUT_VERSION
    );
    assert!(std::fs::read_dir(outside.path()).unwrap().next().is_none());
}

#[cfg(windows)]
#[test]
fn test_windows_layout_one_requires_explicit_developer_import() {
    let dir = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(test_home_root(&dir));
    crate::platform_fs::ensure_private_directory(&home.etc_dir()).unwrap();
    std::fs::write(home.layout_version_path(), LEGACY_LAYOUT_VERSION).unwrap();
    home.ensure().unwrap();

    let error = home
        .begin_layout_v2_migration(&migration_target())
        .unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    assert!(!home.migrations_dir().exists());
    assert_eq!(
        std::fs::read_to_string(home.layout_version_path()).unwrap(),
        LEGACY_LAYOUT_VERSION
    );
}

#[cfg(unix)]
#[test]
fn test_layout_v1_completion_makes_legacy_store_read_only() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(test_home_root(&dir));
    crate::platform_fs::ensure_private_directory(&home.etc_dir()).unwrap();
    std::fs::write(home.layout_version_path(), LEGACY_LAYOUT_VERSION).unwrap();
    home.ensure().unwrap();
    std::fs::create_dir_all(home.state_db_path()).unwrap();
    let legacy_file = home.state_db_path().join("legacy.data");
    std::fs::write(&legacy_file, b"legacy").unwrap();

    home.begin_layout_v2_migration(&migration_target()).unwrap();
    home.complete_layout_v2([], &migration_target()).unwrap();

    assert_eq!(
        std::fs::metadata(&legacy_file)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o400
    );
    assert_eq!(
        std::fs::metadata(home.state_db_path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o500
    );
}

#[cfg(unix)]
#[test]
fn test_astrid_home_ensure_sets_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(test_home_root(&dir));
    home.ensure().unwrap();

    let root_perms = std::fs::metadata(home.root()).unwrap().permissions();
    assert_eq!(root_perms.mode() & 0o777, 0o700);

    let keys_perms = std::fs::metadata(home.keys_dir()).unwrap().permissions();
    assert_eq!(keys_perms.mode() & 0o777, 0o700);
}

#[cfg(unix)]
#[test]
fn test_astrid_home_ensure_repairs_secrets_permissions_without_touching_contents() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(test_home_root(&dir));
    std::fs::create_dir_all(home.secrets_dir()).unwrap();
    crate::platform_fs::ensure_private_directory(&home.etc_dir()).unwrap();
    std::fs::write(home.layout_version_path(), LAYOUT_VERSION).unwrap();
    let secret = home.secrets_dir().join("existing-secret");
    let bytes = b"preserve-these-secret-bytes";
    std::fs::write(&secret, bytes).unwrap();
    std::fs::set_permissions(home.secrets_dir(), std::fs::Permissions::from_mode(0o755)).unwrap();

    home.ensure().unwrap();

    let permissions = std::fs::metadata(home.secrets_dir()).unwrap().permissions();
    assert_eq!(permissions.mode() & 0o777, 0o700);
    assert_eq!(std::fs::read(secret).unwrap(), bytes);
}

// ── AstridHome path accessors ────────────────────────────────────

#[test]
fn test_astrid_home_fhs_paths() {
    let home = AstridHome::from_path("/tmp/test-astrid");
    let r = "/tmp/test-astrid";

    assert_eq!(home.root(), Path::new(r));
    assert_eq!(home.etc_dir(), PathBuf::from(format!("{r}/etc")));
    assert_eq!(
        home.config_path(),
        PathBuf::from(format!("{r}/etc/config.toml"))
    );
    assert_eq!(
        home.servers_config_path(),
        PathBuf::from(format!("{r}/etc/servers.toml"))
    );
    assert_eq!(
        home.gateway_config_path(),
        PathBuf::from(format!("{r}/etc/gateway.toml"))
    );
    assert_eq!(home.hooks_dir(), PathBuf::from(format!("{r}/etc/hooks")));
    assert_eq!(home.var_dir(), PathBuf::from(format!("{r}/var")));
    assert_eq!(
        home.layout_version_path(),
        PathBuf::from(format!("{r}/etc/layout-version"))
    );
    assert_eq!(
        home.state_db_path(),
        PathBuf::from(format!("{r}/var/state.db"))
    );
    assert_eq!(
        home.principal_store_path(),
        PathBuf::from(format!("{r}/var/principal-store"))
    );
    assert_eq!(
        home.content_staging_path(),
        PathBuf::from(format!("{r}/var/content-staging"))
    );
    assert_eq!(
        home.migrations_dir(),
        PathBuf::from(format!("{r}/var/migrations"))
    );
    assert_eq!(home.run_dir(), PathBuf::from(format!("{r}/run")));
    assert_eq!(
        home.socket_path(),
        PathBuf::from(format!("{r}/run/system.sock"))
    );
    assert_eq!(
        home.token_path(),
        PathBuf::from(format!("{r}/run/system.token"))
    );
    assert_eq!(
        home.ready_path(),
        PathBuf::from(format!("{r}/run/system.ready"))
    );
    assert_eq!(
        home.deferred_db_path(),
        PathBuf::from(format!("{r}/run/deferred.db"))
    );
    assert_eq!(home.log_dir(), PathBuf::from(format!("{r}/log")));
    assert_eq!(home.keys_dir(), PathBuf::from(format!("{r}/keys")));
    assert_eq!(
        home.runtime_key_path(),
        PathBuf::from(format!("{r}/keys/runtime.key"))
    );
    assert_eq!(home.bin_dir(), PathBuf::from(format!("{r}/bin")));
    assert_eq!(home.home_dir(), PathBuf::from(format!("{r}/home")));
    let fleet = crate::FleetUid::from_bytes([9; 32]);
    assert_eq!(
        home.fleet_shared_dir(fleet),
        PathBuf::from(format!("{r}/srv/fleets/{fleet}/shared"))
    );
    assert_eq!(
        home.fleet_workspaces_dir(fleet),
        PathBuf::from(format!("{r}/srv/fleets/{fleet}/workspaces"))
    );
}

// ── PrincipalHome ────────────────────────────────────────────────

#[test]
fn test_principal_home_from_astrid_home() {
    let home = AstridHome::from_path("/tmp/test-astrid");
    let principal = PrincipalId::default();
    let ph = home.principal_home(&principal);
    assert_eq!(ph.root(), Path::new("/tmp/test-astrid/home/default"));
}

#[test]
fn test_principal_home_paths() {
    let ph = PrincipalHome::from_path("/tmp/test-astrid/home/alice");
    let r = "/tmp/test-astrid/home/alice";

    assert_eq!(ph.root(), Path::new(r));
    assert_eq!(
        ph.capsules_dir(),
        PathBuf::from(format!("{r}/.local/capsules"))
    );
    assert_eq!(ph.kv_dir(), PathBuf::from(format!("{r}/.local/kv")));
    assert_eq!(ph.log_dir(), PathBuf::from(format!("{r}/.local/log")));
    assert_eq!(ph.audit_dir(), PathBuf::from(format!("{r}/.local/audit")));
    assert_eq!(ph.tokens_dir(), PathBuf::from(format!("{r}/.local/tokens")));
    assert_eq!(ph.tmp_dir(), PathBuf::from(format!("{r}/.local/tmp")));
    assert_eq!(ph.config_dir(), PathBuf::from(format!("{r}/.config")));
    assert_eq!(ph.env_dir(), PathBuf::from(format!("{r}/.config/env")));
}

#[test]
fn test_principal_home_ensure_creates_dirs() {
    let dir = tempfile::tempdir().unwrap();
    let ph = PrincipalHome::from_path(dir.path().join("alice"));
    ph.ensure().unwrap();

    assert!(ph.capsules_dir().exists());
    assert!(ph.kv_dir().exists());
    assert!(ph.log_dir().exists());
    assert!(ph.audit_dir().exists());
    assert!(ph.tokens_dir().exists());
    assert!(ph.tmp_dir().exists());
    assert!(ph.env_dir().exists());
}

#[cfg(unix)]
#[test]
fn test_principal_home_ensure_sets_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let ph = PrincipalHome::from_path(dir.path().join("bob"));
    ph.ensure().unwrap();

    let root_perms = std::fs::metadata(ph.root()).unwrap().permissions();
    assert_eq!(root_perms.mode() & 0o777, 0o700);

    let local_perms = std::fs::metadata(ph.root().join(".local"))
        .unwrap()
        .permissions();
    assert_eq!(local_perms.mode() & 0o777, 0o700);

    let config_perms = std::fs::metadata(ph.root().join(".config"))
        .unwrap()
        .permissions();
    assert_eq!(config_perms.mode() & 0o777, 0o700);
}

#[test]
fn test_principal_home_ensure_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let ph = PrincipalHome::from_path(dir.path().join("charlie"));
    ph.ensure().unwrap();
    ph.ensure().unwrap(); // second call should not fail
}

// ── WorkspaceDir ─────────────────────────────────────────────────

#[test]
fn workspace_layout_defaults_to_dot_astrid() {
    let layout = WorkspaceLayout::default();
    assert_eq!(layout.state_dir_name(), ".astrid");
    assert_eq!(
        layout.capsules_dir(Path::new("/project")),
        PathBuf::from("/project/.astrid/capsules")
    );
}

#[test]
fn workspace_layout_accepts_one_portable_directory_name() {
    let layout = WorkspaceLayout::new(".alternate-runtime").unwrap();
    assert_eq!(
        layout.config_path(Path::new("/project")),
        PathBuf::from("/project/.alternate-runtime/config.toml")
    );
}

#[test]
fn workspace_layout_rejects_ambiguous_or_unsafe_names() {
    for value in [
        "",
        ".",
        "..",
        "/absolute",
        "nested/path",
        "nested\\path",
        "../escape",
        "name with spaces",
        "drive:name",
        ".trailing.",
        "CON",
        "nul.txt",
        "COM1",
        ".LPT9",
    ] {
        assert!(
            WorkspaceLayout::new(value).is_err(),
            "{value:?} must be rejected"
        );
    }
}

#[test]
fn workspace_selection_identity_covers_root_and_layout() {
    let root_a = tempfile::tempdir().unwrap();
    let root_b = tempfile::tempdir().unwrap();
    let default = WorkspaceLayout::default();
    let alternate = WorkspaceLayout::new(".alternate-runtime").unwrap();

    let selected = workspace_selection_fingerprint(root_a.path(), &default);
    assert_eq!(
        selected,
        workspace_selection_fingerprint(root_a.path(), &default)
    );
    assert_ne!(
        selected,
        workspace_selection_fingerprint(root_a.path(), &alternate)
    );
    assert_ne!(
        selected,
        workspace_selection_fingerprint(root_b.path(), &default)
    );
}

#[test]
fn workspace_selection_accepts_missing_then_real_state_directory() {
    let root = tempfile::tempdir().unwrap();
    let layout = WorkspaceLayout::new(".alternate-runtime").unwrap();
    let selection = layout.resolve(root.path()).unwrap();

    assert!(!selection.state_dir().exists());
    selection.ensure_state_dir().unwrap();
    selection.verify().unwrap();
    assert!(selection.state_dir().is_dir());
    assert_eq!(
        selection.project_root(),
        root.path().canonicalize().unwrap()
    );
}

#[cfg(unix)]
#[test]
fn workspace_selection_rejects_state_directory_symlink_escape() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    symlink(outside.path(), root.path().join(".alternate-runtime")).unwrap();

    let error = WorkspaceLayout::new(".alternate-runtime")
        .unwrap()
        .resolve(root.path())
        .unwrap_err();
    assert!(error.to_string().contains("redirect"));
}

#[cfg(unix)]
#[test]
fn workspace_selection_detects_post_selection_symlink_swap() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let layout = WorkspaceLayout::new(".alternate-runtime").unwrap();
    let selection = layout.resolve(root.path()).unwrap();
    selection.ensure_state_dir().unwrap();

    std::fs::remove_dir(selection.state_dir()).unwrap();
    symlink(outside.path(), selection.state_dir()).unwrap();

    assert!(selection.verify().is_err());
    assert!(checked_workspace_selection_fingerprint(root.path(), &layout).is_err());
}

#[cfg(unix)]
#[test]
fn workspace_selection_rejects_redirected_capsule_directory() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let selection = WorkspaceLayout::default().resolve(root.path()).unwrap();
    selection.ensure_state_dir().unwrap();
    symlink(outside.path(), selection.state_dir().join("capsules")).unwrap();

    assert!(selection.capsules_dir().is_err());
    assert!(selection.resolve_directory("capsules/example").is_err());
}

#[cfg(unix)]
#[test]
fn workspace_selection_rejects_persistent_redirects_anywhere_in_checked_trees() {
    use std::os::unix::fs::symlink;

    for relative in [
        "capsules/child",
        "capsules/child/Capsule.toml",
        "capsules/child/meta.json",
        "capsules/child/.env.json",
        "capsules/child/component.wasm",
        "hooks/direct.toml",
    ] {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let selection = WorkspaceLayout::default().resolve(root.path()).unwrap();
        selection.ensure_state_dir().unwrap();
        let redirected = selection.state_dir().join(relative);
        std::fs::create_dir_all(redirected.parent().unwrap()).unwrap();
        if relative == "capsules/child" {
            symlink(outside.path(), &redirected).unwrap();
        } else {
            let outside_file = outside.path().join("outside");
            std::fs::write(&outside_file, b"outside bytes").unwrap();
            symlink(outside_file, &redirected).unwrap();
        }
        let tree = if relative.starts_with("hooks/") {
            "hooks"
        } else {
            "capsules"
        };
        assert!(selection.verify_tree(tree).is_err(), "accepted {relative}");
    }
}

#[cfg(unix)]
#[test]
fn workspace_selection_rejects_redirected_config_file() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::NamedTempFile::new().unwrap();
    let selection = WorkspaceLayout::default().resolve(root.path()).unwrap();
    selection.ensure_state_dir().unwrap();
    symlink(outside.path(), selection.state_dir().join("config.toml")).unwrap();

    assert!(selection.config_path().is_err());
}

#[test]
fn checked_workspace_fingerprint_binds_state_directory_target() {
    let root = tempfile::tempdir().unwrap();
    let default = WorkspaceLayout::default();
    let alternate = WorkspaceLayout::new(".alternate-runtime").unwrap();

    let default_fingerprint =
        checked_workspace_selection_fingerprint(root.path(), &default).unwrap();
    let alternate_fingerprint =
        checked_workspace_selection_fingerprint(root.path(), &alternate).unwrap();

    assert_ne!(default_fingerprint, alternate_fingerprint);
    assert_eq!(default_fingerprint.len(), 64);
}

#[test]
fn workspace_detect_uses_only_the_selected_state_directory() {
    let dir = tempfile::tempdir().unwrap();
    let default_root = dir.path().join("default");
    let alternate_root = default_root.join("nested");
    std::fs::create_dir_all(default_root.join(".astrid")).unwrap();
    std::fs::create_dir_all(alternate_root.join(".alternate-runtime")).unwrap();
    let start = alternate_root.join("src");
    std::fs::create_dir_all(&start).unwrap();

    let alternate = WorkspaceLayout::new(".alternate-runtime").unwrap();
    assert_eq!(
        WorkspaceDir::detect_with_layout(&start, alternate).root(),
        alternate_root
    );
    assert_eq!(WorkspaceDir::detect(&start).root(), default_root);
}

#[test]
fn test_workspace_detect_with_dot_astrid() {
    let dir = tempfile::tempdir().unwrap();
    let astrid_dir = dir.path().join(".astrid");
    std::fs::create_dir(&astrid_dir).unwrap();

    let sub = dir.path().join("src").join("deep");
    std::fs::create_dir_all(&sub).unwrap();

    let ws = WorkspaceDir::detect(&sub);
    assert_eq!(ws.root(), dir.path());
}

#[test]
fn test_workspace_detect_with_git() {
    let dir = tempfile::tempdir().unwrap();
    let git_dir = dir.path().join(".git");
    std::fs::create_dir(&git_dir).unwrap();

    let sub = dir.path().join("src");
    std::fs::create_dir_all(&sub).unwrap();

    let ws = WorkspaceDir::detect(&sub);
    assert_eq!(ws.root(), dir.path());
}

#[test]
fn test_workspace_detect_with_astrid_md() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("ASTRID.md"), "# Project").unwrap();

    let sub = dir.path().join("src");
    std::fs::create_dir_all(&sub).unwrap();

    let ws = WorkspaceDir::detect(&sub);
    assert_eq!(ws.root(), dir.path());
}

#[test]
fn test_workspace_detect_fallback() {
    let dir = tempfile::tempdir().unwrap();
    let isolated = dir.path().join("isolated");
    std::fs::create_dir_all(&isolated).unwrap();

    let ws = WorkspaceDir::from_path(&isolated);
    assert_eq!(ws.root(), isolated);
}

#[test]
fn test_workspace_detect_prefers_dot_astrid_over_git() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join(".astrid")).unwrap();
    std::fs::create_dir(dir.path().join(".git")).unwrap();

    let sub = dir.path().join("src");
    std::fs::create_dir_all(&sub).unwrap();

    let ws = WorkspaceDir::detect(&sub);
    assert_eq!(ws.root(), dir.path());
}

#[test]
fn test_workspace_ensure_creates_dirs_and_id() {
    let dir = tempfile::tempdir().unwrap();
    let ws = WorkspaceDir::from_path(dir.path());
    ws.ensure().unwrap();

    assert!(ws.dot_astrid().exists());
    assert!(ws.workspace_id_path().exists());

    let content = std::fs::read_to_string(ws.workspace_id_path()).unwrap();
    uuid::Uuid::parse_str(content.trim()).expect("workspace-id should be a valid UUID");
}

#[test]
fn test_workspace_id_adopts_existing() {
    let dir = tempfile::tempdir().unwrap();
    let ws = WorkspaceDir::from_path(dir.path());

    crate::platform_fs::ensure_private_directory(&ws.dot_astrid()).unwrap();
    let pre_id = uuid::Uuid::new_v4();
    #[cfg(windows)]
    crate::platform_fs::atomic_write_private_file(
        &ws.workspace_id_path(),
        pre_id.to_string().as_bytes(),
    )
    .unwrap();
    #[cfg(not(windows))]
    std::fs::write(ws.workspace_id_path(), pre_id.to_string()).unwrap();

    let id = ws.workspace_id().unwrap();
    assert_eq!(id, pre_id);
}

#[test]
fn test_workspace_id_stable_across_calls() {
    let dir = tempfile::tempdir().unwrap();
    let ws = WorkspaceDir::from_path(dir.path());
    let id1 = ws.workspace_id().unwrap();
    let id2 = ws.workspace_id().unwrap();
    assert_eq!(id1, id2);
}

#[test]
fn test_workspace_path_accessors() {
    let ws = WorkspaceDir::from_path("/home/user/project");
    assert_eq!(ws.root(), Path::new("/home/user/project"));
    assert_eq!(ws.dot_astrid(), PathBuf::from("/home/user/project/.astrid"));
    assert_eq!(
        ws.capsules_dir(),
        PathBuf::from("/home/user/project/.astrid/capsules")
    );
    assert_eq!(
        ws.workspace_id_path(),
        PathBuf::from("/home/user/project/.astrid/workspace-id")
    );
    assert_eq!(
        ws.instructions_path(),
        PathBuf::from("/home/user/project/.astrid/ASTRID.md")
    );
}

#[test]
fn workspace_path_accessors_use_injected_layout() {
    let layout = WorkspaceLayout::new(".alternate-runtime").unwrap();
    let ws = WorkspaceDir::from_path_with_layout("/home/user/project", layout);
    assert_eq!(
        ws.state_dir(),
        PathBuf::from("/home/user/project/.alternate-runtime")
    );
    assert_eq!(
        ws.capsules_dir(),
        PathBuf::from("/home/user/project/.alternate-runtime/capsules")
    );
    assert_eq!(
        ws.workspace_id_path(),
        PathBuf::from("/home/user/project/.alternate-runtime/workspace-id")
    );
}
