use super::*;
use astrid_core::dirs::{AstridHome, WorkspaceLayout};

#[test]
fn budget_policy_uses_the_captured_runtime_home() {
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    std::fs::write(
        first.path().join("config.toml"),
        "[resources]\ndefault_user_cpu_fuel_per_sec = 123",
    )
    .unwrap();
    std::fs::write(
        second.path().join("config.toml"),
        "[resources]\ndefault_user_cpu_fuel_per_sec = 456",
    )
    .unwrap();
    for (root, expected) in [(first.path(), 123), (second.path(), 456)] {
        let policy = load_policy(
            &AstridHome::from_path(root),
            workspace.path(),
            &WorkspaceLayout::default(),
        )
        .unwrap();
        assert_eq!(
            policy.default_user_cpu_fuel_per_sec.unwrap().get(),
            expected
        );
    }
}

#[test]
fn invalid_captured_policy_cannot_fall_back_to_unlimited() {
    let home = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    std::fs::write(
        home.path().join("config.toml"),
        "[resources]\ndefault_user_cpu_fuel_per_sec = 0",
    )
    .unwrap();
    assert!(
        load_policy(
            &AstridHome::from_path(home.path()),
            workspace.path(),
            &WorkspaceLayout::default()
        )
        .is_err()
    );
}
