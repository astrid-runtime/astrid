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

#[tokio::test(flavor = "multi_thread")]
async fn deletion_releases_private_workspace_but_preserves_promotions_and_peer_branches() {
    use astrid_capsule::context::WorkspaceCommitOp;
    use astrid_storage::{FilesystemPath, WorkspaceBindingLifecycle, WorkspaceBranchStore};

    let dir = tempfile::tempdir().unwrap();
    let kernel = crate::test_kernel_with_home(AstridHome::from_path(dir.path())).await;
    test_support::seed_operator(&kernel).await;
    let caller = PrincipalId::default();
    let alice = PrincipalId::new("workspace-alice").unwrap();
    let bob = PrincipalId::new("workspace-bob").unwrap();
    for target in [&alice, &bob] {
        create_workspace_principal(&kernel, target).await;
    }
    let service = kernel.workspace_branches.as_ref().unwrap();
    let published = FilesystemPath::new("published.txt").unwrap();
    let private = FilesystemPath::new("alice-private.txt").unwrap();
    let peer_private = FilesystemPath::new("bob-private.txt").unwrap();
    let promoted = service.bind(&alice).await.unwrap();
    service
        .filesystem(promoted)
        .write(&published, b"published")
        .unwrap();
    service
        .finish(&alice, promoted, WorkspaceCommitOp::Promote)
        .await
        .unwrap();
    let retired = service.bind(&alice).await.unwrap();
    service
        .filesystem(retired)
        .write(&private, b"alice")
        .unwrap();
    let peer = service.bind(&bob).await.unwrap();
    assert_eq!(retired.owner, peer.owner);
    service
        .filesystem(peer)
        .write(&peer_private, b"bob")
        .unwrap();
    let branches = WorkspaceBranchStore::new(kernel.principal_store.as_ref().unwrap().content());
    let deleted = test_support::dispatch_as_operator(
        &kernel,
        &caller,
        AdminRequestKind::AgentDelete {
            principal: alice.clone(),
        },
    )
    .await;
    assert!(
        matches!(deleted, AdminResponseBody::Success(_)),
        "{deleted:?}"
    );
    assert!(
        !branches
            .list_branches(&retired.owner)
            .unwrap()
            .iter()
            .any(|branch| branch.binding_uid() == Some(retired.uid)),
        "authenticated deletion must release the retired UID's live workspace branches",
    );
    assert_eq!(
        branches
            .binding(&promoted.owner, promoted.branch)
            .unwrap()
            .lifecycle(),
        WorkspaceBindingLifecycle::Promoted,
    );
    assert_eq!(service.binding_for(&bob).await.unwrap(), peer);
    assert_eq!(
        service.filesystem(peer).read(&peer_private, 0, 3).unwrap(),
        b"bob"
    );
    assert_eq!(
        service.filesystem(peer).read(&published, 0, 9).unwrap(),
        b"published"
    );
    create_workspace_principal(&kernel, &alice).await;
    let reused = service.bind(&alice).await.unwrap();
    assert_ne!(reused.uid, retired.uid);
    assert_ne!(reused.branch, retired.branch);
    assert!(service.filesystem(reused).read(&private, 0, 5).is_err());
    assert!(
        service
            .filesystem(reused)
            .read(&peer_private, 0, 3)
            .is_err()
    );
    assert_eq!(
        service.filesystem(reused).read(&published, 0, 9).unwrap(),
        b"published"
    );
}

async fn create_workspace_principal(kernel: &std::sync::Arc<crate::Kernel>, target: &PrincipalId) {
    let response = test_support::dispatch_as_operator(
        kernel,
        &PrincipalId::default(),
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
        matches!(response, AdminResponseBody::Success(_)),
        "{response:?}"
    );
}
