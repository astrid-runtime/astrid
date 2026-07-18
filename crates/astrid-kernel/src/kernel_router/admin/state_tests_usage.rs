//! `admin.usage.get` read-path tests (PR3 feat/resource-usage-readpath).
//!
//! Carved out of `state_tests.rs` to keep that file under the per-file CI
//! line cap. The split is purely mechanical — the shared fixture and the
//! `pid` helper are re-defined locally so this file is self-contained,
//! matching the convention in `state_tests_caps.rs` /
//! `state_tests_agent_modify.rs`.
//!
//! These tests pin the contract that the read path replaced the PR-staged
//! stub with live data:
//!   (a) the cumulative cross-capsule fuel total is read from the shared
//!       [`FuelLedger`](astrid_capsule::FuelLedger), not hard-coded `0`;
//!   (b) `exempt` is computed from the SAME capability predicate the
//!       enforcement side uses (`resolve_exemption`), so displayed-exempt
//!       equals enforced-exempt — admin / `system:resources:unbounded`
//!       holders are exempt, a plain agent is not;
//!   (c) the cpu/memory ceilings echo the principal's configured quotas.

use std::sync::Arc;

use astrid_core::dirs::AstridHome;
use astrid_core::groups::BUILTIN_ADMIN;
use astrid_core::principal::PrincipalId;
use astrid_core::profile::Quotas;
use astrid_events::kernel_api::{AdminRequestKind, AdminResponseBody, ResourceUsage};
use tempfile::TempDir;

use super::handlers;
use crate::Kernel;

async fn fixture() -> (TempDir, Arc<Kernel>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let home = AstridHome::from_path(dir.path());
    let kernel = crate::test_kernel_with_home(home).await;
    (dir, kernel)
}

fn pid(name: &str) -> PrincipalId {
    PrincipalId::new(name).unwrap()
}

/// Create an agent principal with the given groups (no extra grants).
async fn create_agent(kernel: &Arc<Kernel>, name: &str, groups: Vec<String>) {
    handlers::dispatch(
        kernel,
        &PrincipalId::default(),
        AdminRequestKind::AgentCreate {
            name: name.into(),
            groups,
            grants: Vec::new(),
            inherit_from: None,
            clone_from: None,
            allow_admin_clone: false,
        },
    )
    .await;
}

/// Drive `usage.get` for `principal` and unwrap the [`ResourceUsage`],
/// failing the test with the error body if the handler rejected it.
async fn usage_get(kernel: &Arc<Kernel>, principal: &PrincipalId) -> ResourceUsage {
    let res = handlers::dispatch(
        kernel,
        &PrincipalId::default(),
        AdminRequestKind::UsageGet {
            principal: principal.clone(),
        },
    )
    .await;
    match res {
        AdminResponseBody::Usage(u) => u,
        other => panic!("expected Usage, got: {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn usage_get_on_nonexistent_principal_is_rejected() {
    // Same phantom-principal guard as quota.get: a typo'd name must not
    // silently report Default-shaped ceilings + a zero total.
    let (_dir, kernel) = fixture().await;
    let res = handlers::dispatch(
        &kernel,
        &PrincipalId::default(),
        AdminRequestKind::UsageGet {
            principal: pid("typo_principal"),
        },
    )
    .await;
    match res {
        AdminResponseBody::Error(msg) => assert!(
            msg.contains("does not exist"),
            "expected phantom-principal rejection, got: {msg}"
        ),
        other => panic!("expected Error, got: {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn usage_get_reports_real_fuel_total() {
    // (a) A principal with recorded fuel reports the live cross-capsule
    // cumulative total from the shared ledger — not the staged stub's 0.
    let (_dir, kernel) = fixture().await;
    create_agent(&kernel, "alice", Vec::new()).await;

    // Zero charges yet → the ledger reports 0 for a known principal.
    assert_eq!(
        usage_get(&kernel, &pid("alice"))
            .await
            .cpu_fuel_consumed_total,
        0,
        "an uncharged principal reads 0, distinct from the old hard-coded stub"
    );

    // Charge twice; usage.get must read the SUM (cross-capsule aggregate).
    kernel.fuel_ledger.charge(&pid("alice"), 1_000);
    kernel.fuel_ledger.charge(&pid("alice"), 234);
    assert_eq!(
        usage_get(&kernel, &pid("alice"))
            .await
            .cpu_fuel_consumed_total,
        1_234,
        "usage.get must surface the live ledger total, not the stub 0"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn usage_get_exempt_matches_capability_holders() {
    // (b) Displayed-exempt == enforced-exempt. An admin-group principal and
    // a `system:resources:unbounded` grant holder both report exempt=true;
    // a plain agent reports exempt=false.
    let (_dir, kernel) = fixture().await;

    // admin group holds `*`, so it matches all three exemption caps.
    create_agent(&kernel, "boss", vec![BUILTIN_ADMIN.into()]).await;
    assert!(
        usage_get(&kernel, &pid("boss")).await.exempt,
        "admin (holds `*`) must report exempt=true"
    );

    // A plain agent: no exemption capability.
    create_agent(&kernel, "worker", Vec::new()).await;
    assert!(
        !usage_get(&kernel, &pid("worker")).await.exempt,
        "a plain agent holds no exemption cap → exempt=false"
    );

    // Grant the explicit unbounded capability — exempt now flips true. This
    // is the read-path mirror of the enforcement predicate
    // (`resolve_exemption`): the same grant that exempts enforcement must
    // exempt the displayed report.
    handlers::dispatch(
        &kernel,
        &PrincipalId::default(),
        AdminRequestKind::CapsGrant {
            principal: pid("worker"),
            capabilities: vec![astrid_core::CAP_RESOURCES_UNBOUNDED.into()],
            unsafe_admin: false,
        },
    )
    .await;
    assert!(
        usage_get(&kernel, &pid("worker")).await.exempt,
        "system:resources:unbounded grant must report exempt=true"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn usage_get_ceilings_match_profile_quotas() {
    // (c) The cpu/memory ceilings echo the principal's configured profile
    // quotas — set a non-default quota and confirm usage.get reflects it.
    let (_dir, kernel) = fixture().await;
    create_agent(&kernel, "carol", Vec::new()).await;

    let quotas = Quotas {
        max_cpu_fuel_per_sec: 7_000_000,
        max_memory_bytes: 32 * 1024 * 1024,
        ..Quotas::default()
    };
    handlers::dispatch(
        &kernel,
        &PrincipalId::default(),
        AdminRequestKind::QuotaSet {
            principal: pid("carol"),
            quotas: quotas.clone(),
        },
    )
    .await;

    let usage = usage_get(&kernel, &pid("carol")).await;
    assert_eq!(usage.principal, pid("carol"));
    assert_eq!(usage.cpu_fuel_per_sec_limit, quotas.max_cpu_fuel_per_sec);
    assert_eq!(
        usage.memory_bytes_limit_per_instance,
        quotas.max_memory_bytes
    );
    // No principal-affine Store is resident in this fixture.
    assert_eq!(usage.memory_bytes_current_total, None);
}

#[tokio::test(flavor = "multi_thread")]
async fn usage_get_reports_principal_affine_current_memory() {
    let (_dir, kernel) = fixture().await;
    create_agent(&kernel, "carol", Vec::new()).await;
    let carol = pid("carol");

    assert!(
        kernel
            .memory_ledger
            .try_reserve_current(&carol, 12 * 1024 * 1024, 64 * 1024 * 1024)
    );
    let usage = usage_get(&kernel, &carol).await;
    assert_eq!(usage.memory_bytes_current_total, Some(12 * 1024 * 1024));

    kernel
        .memory_ledger
        .release_current(&carol, 12 * 1024 * 1024);
    assert_eq!(
        usage_get(&kernel, &carol).await.memory_bytes_current_total,
        None
    );
}
