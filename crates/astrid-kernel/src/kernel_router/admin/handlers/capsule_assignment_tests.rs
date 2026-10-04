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

fn inheritance_entries(count: usize, bytes: usize) -> Vec<(KvEntryKey, Vec<u8>)> {
    (0..count)
        .map(|index| {
            (
                KvEntryKey::new("test:control:env", format!("__env:field-{index}")).unwrap(),
                vec![b'x'; bytes],
            )
        })
        .collect()
}

#[tokio::test]
async fn inheritance_exceeds_one_batch_operation_and_payload_limits() {
    for (count, bytes) in [(513, 1), (65, 1024 * 1024)] {
        let entries = inheritance_entries(count, bytes);
        // Demonstrate the original one-batch failure using the storage contract.
        assert!(
            KvMutationBatch::new(
                entries
                    .iter()
                    .map(|(key, _)| KvBatchCondition::ValueEquals {
                        key: key.clone(),
                        expected: None
                    }),
                entries.iter().map(|(key, value)| KvBatchMutation::Set {
                    key: key.clone(),
                    value: value.clone()
                }),
            )
            .is_err()
        );
        let batches = inheritance_batches(entries).unwrap();
        assert_eq!(batches.len(), 2);
        let kv = astrid_storage::MemoryKvStore::new();
        let mut published = false;
        apply_inheritance(&kv, &batches, || {
            published = true;
            Ok(())
        })
        .await
        .unwrap();
        assert!(published);
        for batch in &batches {
            for mutation in batch.mutations() {
                assert_eq!(
                    kv.get(mutation.key().namespace(), mutation.key().key())
                        .await
                        .unwrap()
                        .as_deref(),
                    mutation.value()
                );
            }
        }
    }
}

#[tokio::test]
async fn late_batch_conflict_rolls_back_earlier_batches_without_publication() {
    let kv = astrid_storage::MemoryKvStore::new();
    let batches = inheritance_batches(inheritance_entries(513, 1)).unwrap();
    let conflicting = batches[1].mutations()[0].key();
    kv.set(conflicting.namespace(), conflicting.key(), b"keep".to_vec())
        .await
        .unwrap();
    let result = apply_inheritance(&kv, &batches, || {
        panic!("must not publish partial environment")
    })
    .await;
    assert!(result.unwrap_err().contains("changed during inheritance"));
    for mutation in batches[0].mutations() {
        assert!(
            kv.get(mutation.key().namespace(), mutation.key().key())
                .await
                .unwrap()
                .is_none()
        );
    }
    assert_eq!(
        kv.get(conflicting.namespace(), conflicting.key())
            .await
            .unwrap(),
        Some(b"keep".to_vec())
    );
    kv.delete(conflicting.namespace(), conflicting.key())
        .await
        .unwrap();
    apply_inheritance(&kv, &batches, || Ok(())).await.unwrap();
}

#[tokio::test]
async fn failed_publication_rolls_back_multiple_batches() {
    let kv = astrid_storage::MemoryKvStore::new();
    let batches = inheritance_batches(inheritance_entries(513, 1)).unwrap();
    assert_eq!(
        apply_inheritance(&kv, &batches, || Err("publication failed".into()))
            .await
            .unwrap_err(),
        "publication failed"
    );
    assert!(kv.list_keys("test:control:env").await.unwrap().is_empty());
    apply_inheritance(&kv, &batches, || Ok(())).await.unwrap();
}
