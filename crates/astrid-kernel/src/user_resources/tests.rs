use super::*;
use astrid_core::dirs::{AstridHome, WorkspaceLayout};
use std::collections::BTreeMap;

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

#[tokio::test]
async fn lifecycle_resolution_preserves_personal_defaults_and_refuses_unassigned_budgets() {
    let home = tempfile::tempdir().unwrap();
    let kernel = crate::test_kernel_with_home(AstridHome::from_path(home.path())).await;
    let principal = astrid_core::PrincipalId::default();
    assert!(
        execution_throttle(
            &kernel.user_cpu,
            &kernel.profile_cache,
            &kernel.groups,
            &principal
        )
        .await
        .unwrap()
        .is_none()
    );
    let cpu = Arc::new(UserCpuAccounting::new(
        kernel.ownership_store.clone(),
        kernel.principal_directory.clone(),
        std::num::NonZeroU64::new(100),
        BTreeMap::default(),
    ));
    // The enrolled default now has an explicit payer from the ceremony. A
    // separate admitted identity with no ownership models unresolved legacy
    // attribution without erasing that production invariant in the fixture.
    let unassigned = astrid_core::PrincipalId::new("unassigned").unwrap();
    kernel
        .identity_store
        .create_principal(unassigned.clone(), [3; 32])
        .await
        .unwrap();
    let error = execution_throttle(&cpu, &kernel.profile_cache, &kernel.groups, &unassigned)
        .await
        .err()
        .unwrap();
    assert!(
        error.contains("explicit resource-user assignment"),
        "{error}"
    );
}

#[tokio::test]
async fn lifecycle_resolution_shares_the_supplied_runtime_ledger_even_for_admin_principal() {
    let home = tempfile::tempdir().unwrap();
    let kernel = crate::test_kernel_with_home(AstridHome::from_path(home.path())).await;
    let principal = astrid_core::PrincipalId::default();
    // The signed first-owner commit supplies this principal's real payer.
    // Both lifecycle paths below must charge that same runtime ledger.
    let cpu = Arc::new(UserCpuAccounting::new(
        kernel.ownership_store.clone(),
        kernel.principal_directory.clone(),
        std::num::NonZeroU64::new(100),
        BTreeMap::default(),
    ));
    let active = cpu
        .configured_throttle(&principal, 0)
        .await
        .unwrap()
        .unwrap();
    active.charge(500);
    let lifecycle = execution_throttle(&cpu, &kernel.profile_cache, &kernel.groups, &principal)
        .await
        .unwrap()
        .unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(20), lifecycle.wait())
            .await
            .is_err()
    );
}
