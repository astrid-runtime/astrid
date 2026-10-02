use super::*;
use astrid_storage::env::{get_env, set_env};

#[tokio::test]
async fn failed_publication_rolls_back_only_new_environment() {
    let root = tempfile::tempdir().unwrap();
    let kernel =
        crate::test_kernel_with_home(astrid_core::dirs::AstridHome::from_path(root.path())).await;
    let source = kernel
        .principal_directory
        .uid_for(&PrincipalId::default())
        .unwrap();
    let principal = PrincipalId::new("publication-target").unwrap();
    crate::kernel_router::admin::test_support::seed_operator(&kernel).await;
    let created = crate::kernel_router::admin::test_support::dispatch_as_operator(
        &kernel,
        &PrincipalId::default(),
        astrid_core::kernel_api::AdminRequestKind::AgentCreate {
            name: principal.to_string(),
            groups: vec![astrid_core::groups::BUILTIN_AGENT.into()],
            grants: Vec::new(),
            inherit_from: None,
            clone_from: None,
            allow_admin_clone: false,
        },
    )
    .await;
    assert!(
        matches!(
            created,
            astrid_core::kernel_api::AdminResponseBody::Success(_)
        ),
        "{created:?}"
    );
    let target = kernel.principal_directory.uid_for(&principal).unwrap();
    let capsule = "publish-failure";
    let source_env = principal_env_store(Arc::clone(&kernel.kv), source, capsule).unwrap();
    let target_env = principal_env_store(Arc::clone(&kernel.kv), target, capsule).unwrap();
    set_env(&source_env, "tenant", "default-tenant")
        .await
        .unwrap();
    set_env(&source_env, "same", "existing").await.unwrap();
    set_env(&target_env, "same", "existing").await.unwrap();
    set_env(&target_env, "local", "keep").await.unwrap();
    let _admin = kernel.admin_write_lock.lock().await;
    let _fence = Arc::clone(&kernel.env_install_fence)
        .try_write_owned()
        .unwrap();
    for _ in 0..2 {
        let result = inherit_and_publish(&kernel, source, target, capsule, || {
            kernel
                .principal_store
                .as_ref()
                .unwrap()
                .capsules()
                .install(
                    &astrid_storage::StateOwner::Principal(target),
                    capsule,
                    &astrid_storage::CapsulePackage::new(Vec::new(), Vec::new(), Vec::new()),
                    astrid_storage::CapsuleInstallExpectation::Absent,
                )
                .map(|_| ())
                .map_err(|error| error.to_string())
        })
        .await;
        assert!(result.unwrap_err().contains("fixed package file is empty"));
        assert_eq!(get_env(&target_env, "tenant").await.unwrap(), None);
        assert_eq!(
            get_env(&target_env, "same").await.unwrap().as_deref(),
            Some("existing")
        );
        assert_eq!(
            get_env(&target_env, "local").await.unwrap().as_deref(),
            Some("keep")
        );
    }
    inherit_and_publish(&kernel, source, target, capsule, || Ok(()))
        .await
        .unwrap();
    assert_eq!(
        get_env(&target_env, "tenant").await.unwrap().as_deref(),
        Some("default-tenant")
    );
}

#[tokio::test]
async fn revocation_does_not_require_the_install_fence() {
    let root = tempfile::tempdir().unwrap();
    let kernel =
        crate::test_kernel_with_home(astrid_core::dirs::AstridHome::from_path(root.path())).await;
    let _fence = Arc::clone(&kernel.env_install_fence)
        .try_write_owned()
        .unwrap();
    materialize_added_capsule_installs(&kernel, &PrincipalId::default(), &[])
        .await
        .unwrap();
}
