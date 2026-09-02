use std::path::Path;

use tempfile::tempdir;

use super::*;

#[cfg(unix)]
use std::fs::Permissions;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[cfg(unix)]
fn write_private_client_config(path: &Path, contents: &str) {
    std::fs::write(path, contents).expect("write test client config");
    std::fs::set_permissions(path, Permissions::from_mode(0o600))
        .expect("restrict test client config");
}

#[test]
fn empty_client_config_uses_historical_default() {
    let config: ClientConfig = toml::from_str("").unwrap();
    assert_eq!(config.run_idle_secs, 120);
    assert_eq!(DEFAULT_RUN_IDLE_TIMEOUT_SECS, 120);
}

#[test]
fn client_config_rejects_runtime_policy_and_bad_bounds() {
    let result: Result<ClientConfig, _> = toml::from_str("[security]\nrequire_signatures = true\n");
    assert!(result.is_err());

    for invalid in ["run_idle_secs = 0", "run_idle_secs = 86_401"] {
        let value = toml::from_str::<ClientConfig>(invalid).unwrap();
        assert!(validate_run_idle_secs(value.run_idle_secs).is_err());
    }
}

#[cfg(unix)]
#[test]
fn explicit_client_path_requires_absolute_private_file() {
    let root = tempdir().unwrap();
    let relative = Path::new("client.toml");
    assert!(client_config_path(Some(relative.as_os_str()), None).is_err());
    assert!(
        load_run_idle_timeout(relative)
            .unwrap_err()
            .to_string()
            .contains("absolute")
    );

    let absolute = root.path().join("private/client.toml");
    std::fs::create_dir_all(absolute.parent().unwrap()).unwrap();
    write_private_client_config(&absolute, "run_idle_secs = 600\n");
    assert_eq!(load_run_idle_timeout(&absolute).unwrap(), 600);
}

#[cfg(unix)]
#[test]
fn explicit_client_path_rejects_symlink_and_permissive_file() {
    let root = tempdir().unwrap();
    let target = root.path().join("target.toml");
    let link = root.path().join("link.toml");
    write_private_client_config(&target, "run_idle_secs = 300\n");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert!(load_run_idle_timeout(&link).is_err());

    let permissive = root.path().join("permissive.toml");
    write_private_client_config(&permissive, "run_idle_secs = 300\n");
    std::fs::set_permissions(&permissive, Permissions::from_mode(0o646)).unwrap();
    assert!(load_run_idle_timeout(&permissive).is_err());
}

#[test]
fn explicit_missing_path_fails_instead_of_falling_back() {
    let root = tempdir().unwrap();
    let missing = root.path().join("missing.toml");
    assert!(load_run_idle_timeout(&missing).is_err());
}

#[cfg(unix)]
#[test]
fn canonical_default_is_selected_only_when_it_is_a_regular_file() {
    let root = tempdir().unwrap();
    let canonical = root.path().join(".aos/etc/astrid/client.toml");
    assert_eq!(
        client_config_path(None, Some(root.path()))
            .unwrap()
            .as_deref(),
        None
    );

    std::fs::create_dir_all(canonical.parent().unwrap()).unwrap();
    write_private_client_config(&canonical, "run_idle_secs = 45\n");
    assert_eq!(
        client_config_path(None, Some(root.path()))
            .unwrap()
            .as_deref(),
        Some(canonical.as_path())
    );
}

#[test]
fn resolution_preserves_cli_precedence_and_absent_file_default() {
    assert_eq!(resolve_run_idle_timeout(Some(30), None).unwrap(), 30);
    assert_eq!(
        resolve_run_idle_timeout(Some(30), Some(Path::new("/missing/client.toml"))).unwrap(),
        30
    );
    assert_eq!(resolve_run_idle_timeout(None, None).unwrap(), 120);
}
