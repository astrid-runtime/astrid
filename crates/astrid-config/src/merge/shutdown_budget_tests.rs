use super::{deep_merge, enforce_restrictions};

#[test]
fn workspace_cannot_change_daemon_shutdown_budget() {
    for requested in [1, 30, 60, 600] {
        let baseline: toml::Value =
            toml::from_str("[timeouts]\ndaemon_shutdown_secs = 45").unwrap();
        let workspace: toml::Value =
            toml::from_str(&format!("[timeouts]\ndaemon_shutdown_secs = {requested}")).unwrap();
        let mut merged = baseline.clone();
        deep_merge(&mut merged, &workspace);
        enforce_restrictions(&mut merged, &baseline, &workspace);
        assert_eq!(
            merged["timeouts"]["daemon_shutdown_secs"].as_integer(),
            Some(45)
        );
    }
}
