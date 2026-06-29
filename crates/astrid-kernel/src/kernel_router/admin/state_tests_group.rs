//! Group admin state tests that are narrow enough to keep the broad
//! `state_tests.rs` file below the source-size cap.

use std::sync::Arc;

use astrid_core::dirs::AstridHome;
use astrid_core::groups::{BUILTIN_ADMIN, BUILTIN_AGENT};
use astrid_core::principal::PrincipalId;
use astrid_core::profile::PrincipalProfile;
use astrid_events::kernel_api::{AdminRequestKind, AdminResponseBody};
use tempfile::TempDir;

use super::handlers;
use crate::Kernel;

async fn fixture() -> (TempDir, Arc<Kernel>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let home = AstridHome::from_path(dir.path());
    let kernel = crate::test_kernel_with_home(home).await;
    let admin = PrincipalProfile {
        groups: vec![BUILTIN_ADMIN.to_string()],
        ..Default::default()
    };
    admin
        .save_to_path(&PrincipalProfile::path_for(
            &kernel.astrid_home,
            &PrincipalId::default(),
        ))
        .expect("seed default admin profile");
    kernel.profile_cache.invalidate(&PrincipalId::default());
    (dir, kernel)
}

fn pid(name: &str) -> PrincipalId {
    PrincipalId::new(name).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn group_list_filters_to_callers_profile_groups_without_global_cap() {
    let (_dir, kernel) = fixture().await;
    handlers::dispatch(
        &kernel,
        &PrincipalId::default(),
        AdminRequestKind::GroupCreate {
            name: "ops".into(),
            capabilities: vec!["capsule:install".into()],
            description: None,
            unsafe_admin: false,
        },
    )
    .await;
    let alice = pid("alice");
    let profile = PrincipalProfile {
        groups: vec![BUILTIN_AGENT.to_string()],
        ..Default::default()
    };
    profile
        .save_to_path(&PrincipalProfile::path_for(&kernel.astrid_home, &alice))
        .expect("seed alice profile");
    kernel.profile_cache.invalidate(&alice);

    let res = handlers::dispatch(&kernel, &alice, AdminRequestKind::GroupList).await;
    let AdminResponseBody::GroupList(list) = res else {
        panic!("expected GroupList");
    };
    let names: Vec<_> = list.iter().map(|group| group.name.as_str()).collect();
    assert_eq!(names, vec![BUILTIN_AGENT]);
}
