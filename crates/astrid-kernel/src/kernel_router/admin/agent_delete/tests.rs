use astrid_core::{
    PrincipalId,
    dirs::AstridHome,
    profile::{DeviceScope, PrincipalProfile},
};
use astrid_events::kernel_api::{AdminRequestKind, AdminResponseBody};

use super::super::{handlers, test_support};

#[tokio::test(flavor = "multi_thread")]
async fn owned_deletion_rejects_missing_revoked_removed_and_attenuated_credentials() {
    for mode in ["missing", "revoked", "removed", "scoped", "capability"] {
        let dir = tempfile::tempdir().unwrap();
        let kernel = crate::test_kernel_with_home(AstridHome::from_path(dir.path())).await;
        let delegation = test_support::seed_operator(&kernel).await;
        let caller = PrincipalId::default();
        let target = PrincipalId::new("child").unwrap();
        let created = test_support::dispatch_as_operator(
            &kernel,
            &caller,
            AdminRequestKind::AgentCreate {
                name: target.to_string(),
                groups: Vec::new(),
                grants: Vec::new(),
                inherit_from: None,
                clone_from: None,
                allow_admin_clone: false,
            },
        )
        .await;
        assert!(
            matches!(created, AdminResponseBody::Success(_)),
            "{created:?}"
        );
        let path = PrincipalProfile::path_for(&kernel.astrid_home, &caller);
        let mut profile = PrincipalProfile::load_from_path(&path).unwrap();
        let device = profile
            .auth
            .device_by_pubkey(&"ab".repeat(32))
            .unwrap()
            .key_id
            .clone();
        match mode {
            "revoked" => {
                let actor = kernel
                    .ownership_store
                    .load()
                    .await
                    .unwrap()
                    .user_for_device(delegation.principal(), delegation.public_key())
                    .unwrap();
                kernel
                    .ownership_store
                    .revoke_user_device(delegation.principal(), *delegation.public_key(), actor)
                    .await
                    .unwrap();
            },
            "removed" => profile.auth.public_keys.clear(),
            "scoped" => {
                profile
                    .auth
                    .public_keys
                    .iter_mut()
                    .find(|key| key.key_id == device)
                    .unwrap()
                    .scope = DeviceScope::Scoped {
                    allow: vec!["*".into()],
                    deny: vec!["agent:delete".into()],
                };
            },
            "capability" => profile.groups = vec![astrid_core::groups::BUILTIN_RESTRICTED.into()],
            "missing" => {},
            _ => unreachable!(),
        }
        profile.save_to_path(&path).unwrap();
        kernel.profile_cache.invalidate(&caller);
        let before = kernel.ownership_store.load().await.unwrap();
        let response = handlers::dispatch_with_device(
            &kernel,
            &caller,
            (mode != "missing").then_some(device.as_str()),
            AdminRequestKind::AgentDelete {
                principal: target.clone(),
            },
        )
        .await;
        assert!(
            matches!(response, AdminResponseBody::Error(_)),
            "{mode}: {response:?}"
        );
        assert_eq!(
            before,
            kernel.ownership_store.load().await.unwrap(),
            "{mode}"
        );
        assert!(
            PrincipalProfile::path_for(&kernel.astrid_home, &target).exists(),
            "{mode}"
        );
        assert!(
            kernel
                .identity_store
                .resolve("cli", target.as_str())
                .await
                .unwrap()
                .is_some(),
            "{mode}"
        );
    }
}
