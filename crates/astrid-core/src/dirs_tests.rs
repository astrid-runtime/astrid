//! Tests for `dirs.rs`. Split out to keep `dirs.rs` under the 1000-line CI
//! threshold. Included via `#[path]` from its sibling.

use super::*;

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
    let home_val = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let home = AstridHome::resolve_with_env(None, Some(home_val.clone())).unwrap();
    let expected = PathBuf::from(home_val).join(".astrid");
    assert_eq!(home.root(), expected);
}

#[test]
fn test_astrid_home_rejects_traversal_in_astrid_home() {
    let result = AstridHome::resolve_with_env(Some("/tmp/../etc".to_string()), None);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("'..'"),
        "expected path traversal error, got: {err}"
    );
}

#[test]
fn test_astrid_home_rejects_traversal_in_home() {
    let result = AstridHome::resolve_with_env(None, Some("/tmp/../etc".to_string()));
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
    let home = AstridHome::from_path(dir.path());
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
}

#[test]
fn test_astrid_home_ensure_writes_layout_version() {
    let dir = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(dir.path());
    home.ensure().unwrap();

    let version_path = home.etc_dir().join("layout-version");
    assert!(version_path.exists());
    let content = std::fs::read_to_string(&version_path).unwrap();
    assert_eq!(content, LAYOUT_VERSION);
}

#[test]
fn test_astrid_home_ensure_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(dir.path());
    home.ensure().unwrap();
    home.ensure().unwrap(); // second call should not fail
}

#[cfg(unix)]
#[test]
fn test_astrid_home_ensure_sets_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(dir.path());
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
    let home = AstridHome::from_path(dir.path());
    std::fs::create_dir_all(home.secrets_dir()).unwrap();
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
        home.state_db_path(),
        PathBuf::from(format!("{r}/var/state.db"))
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

    std::fs::create_dir_all(ws.dot_astrid()).unwrap();
    let pre_id = uuid::Uuid::new_v4();
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
