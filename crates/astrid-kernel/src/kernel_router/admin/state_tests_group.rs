//! Group admin state tests that are narrow enough to keep the broad
//! `state_tests.rs` file below the source-size cap.

use std::sync::Arc;

use astrid_core::dirs::AstridHome;
use astrid_core::groups::{BUILTIN_ADMIN, BUILTIN_AGENT};
use astrid_core::principal::PrincipalId;
use astrid_core::profile::{AuthMethod, DeviceKey, DeviceScope, PrincipalProfile};
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

#[tokio::test(flavor = "multi_thread")]
async fn group_list_global_view_is_attenuated_by_device_scope() {
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

    let full = DeviceKey::new("a".repeat(64), DeviceScope::Full, None, 0);
    let self_only = DeviceKey::new(
        "b".repeat(64),
        DeviceScope::Scoped {
            allow: vec!["self:*".to_string()],
            deny: Vec::new(),
        },
        None,
        0,
    );
    let global_list = DeviceKey::new(
        "c".repeat(64),
        DeviceScope::Scoped {
            allow: vec!["self:*".to_string(), "group:list".to_string()],
            deny: Vec::new(),
        },
        None,
        0,
    );
    let full_id = full.key_id.clone();
    let self_only_id = self_only.key_id.clone();
    let global_list_id = global_list.key_id.clone();
    let profile_path = PrincipalProfile::path_for(&kernel.astrid_home, &PrincipalId::default());
    let mut profile =
        PrincipalProfile::load_from_path(&profile_path).expect("load default profile");
    profile.auth.methods = vec![AuthMethod::Keypair];
    profile.auth.public_keys = vec![full, self_only, global_list];
    profile
        .save_to_path(&profile_path)
        .expect("save device-scoped default profile");
    kernel.profile_cache.invalidate(&PrincipalId::default());

    let names_for = |response| match response {
        AdminResponseBody::GroupList(list) => {
            list.into_iter().map(|group| group.name).collect::<Vec<_>>()
        },
        other => panic!("expected GroupList, got {other:?}"),
    };
    let full = names_for(
        handlers::dispatch_with_device(
            &kernel,
            &PrincipalId::default(),
            Some(&full_id),
            AdminRequestKind::GroupList,
        )
        .await,
    );
    assert!(full.iter().any(|name| name == "ops"));

    let global = names_for(
        handlers::dispatch_with_device(
            &kernel,
            &PrincipalId::default(),
            Some(&global_list_id),
            AdminRequestKind::GroupList,
        )
        .await,
    );
    assert!(global.iter().any(|name| name == "ops"));

    for device_key_id in [self_only_id.as_str(), "0000000000000000"] {
        let scoped = names_for(
            handlers::dispatch_with_device(
                &kernel,
                &PrincipalId::default(),
                Some(device_key_id),
                AdminRequestKind::GroupList,
            )
            .await,
        );
        assert_eq!(scoped, vec![BUILTIN_ADMIN]);
    }
}
