//! Exercise global configuration through the same explicit-home loader as boot.

use super::*;

fn write_config(home: &Path, relative: &str, text: &str) {
    let path = home.join(relative);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

#[test]
fn canonical_home_configuration_is_loaded() {
    let home = tempfile::tempdir().unwrap();
    write_config(
        home.path(),
        "etc/config.toml",
        "[filesystem]\nvolume_name = 'Canonical test volume'\n",
    );
    let resolved = Config::load_with_home(None, home.path()).unwrap();
    assert_eq!(
        resolved.config.filesystem.volume_name,
        "Canonical test volume"
    );
    assert!(
        resolved
            .loaded_files
            .iter()
            .any(|path| path.ends_with("etc/config.toml"))
    );
}

#[test]
fn canonical_overlay_preserves_legacy_fields_and_wins_conflicts() {
    let home = tempfile::tempdir().unwrap();
    write_config(
        home.path(),
        "config.toml",
        "[runtime]\nsystem_prompt = 'legacy prompt'\n[filesystem]\nvolume_name = 'Legacy test volume'\n[audit.retention]\nrequire_anchor = true\n",
    );
    write_config(
        home.path(),
        "etc/config.toml",
        "[filesystem]\nvolume_name = 'Canonical test volume'\n",
    );
    let resolved = Config::load_with_home(None, home.path()).unwrap();
    assert_eq!(resolved.config.runtime.system_prompt, "legacy prompt");
    assert!(resolved.config.audit.retention.require_anchor);
    assert_eq!(
        resolved.config.filesystem.volume_name,
        "Canonical test volume"
    );
    let user_paths: Vec<_> = resolved
        .loaded_files
        .iter()
        .filter(|path| path.starts_with(home.path().to_str().unwrap()))
        .collect();
    assert_eq!(
        user_paths,
        vec![
            &home.path().join("config.toml").display().to_string(),
            &home.path().join("etc/config.toml").display().to_string()
        ]
    );
}

#[test]
fn malformed_home_overlay_never_falls_back_to_other_file() {
    for malformed in ["config.toml", "etc/config.toml"] {
        let home = tempfile::tempdir().unwrap();
        write_config(
            home.path(),
            "config.toml",
            "[runtime]\nsystem_prompt = 'legacy prompt'\n",
        );
        write_config(
            home.path(),
            "etc/config.toml",
            "[filesystem]\nvolume_name = 'Canonical test volume'\n",
        );
        write_config(home.path(), malformed, "[invalid TOML");
        let error = Config::load_with_home(None, home.path()).unwrap_err();
        assert!(
            matches!(error, ConfigError::ParseError { path, .. } if Path::new(&path) == home.path().join(malformed))
        );
    }
}

#[test]
fn canonical_operator_uplinks_remain_protected_from_workspace() {
    let home = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    write_config(
        home.path(),
        "etc/config.toml",
        "[[uplinks]]\nplugin = 'canonical-operator'\nprofile = 'chat'\n",
    );
    write_config(
        workspace.path(),
        ".astrid/config.toml",
        "[[uplinks]]\nplugin = 'workspace-replacement'\nprofile = 'bridge'\n",
    );
    let resolved = Config::load_with_home(Some(workspace.path()), home.path()).unwrap();
    assert_eq!(resolved.config.uplinks.len(), 1);
    assert_eq!(resolved.config.uplinks[0].plugin, "canonical-operator");
}
