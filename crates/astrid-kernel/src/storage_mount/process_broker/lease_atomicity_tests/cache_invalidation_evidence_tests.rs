//! Cleanup-evidence, retained-stop, and invalidation race regressions.

use super::*;
use super::{owned_finishers, provider_fixture};
use crate::storage_mount::process_broker::lease_atomicity_tests::{
    ExactFenceFixture, exact_fence_fixture,
};
use crate::storage_mount::process_broker::process_stop;
use crate::storage_mount::process_broker::{
    PROCESS_MOUNT_TEST_ID, ProjectionLeaseTarget, retain_failed_launch_projection,
    retry_failed_projection,
};

fn retained_provider(
    mount_id: astrid_core::storage_provider::StorageMountId,
    target: ProcessProjectionTarget,
    control_path: std::path::PathBuf,
    stopped: bool,
) -> ProjectionLeaseProvider {
    ProjectionLeaseProvider {
        running: RunningProvider {
            child: None,
            control_path,
            token: "old-generation-token".to_owned(),
            stopped,
        },
        lease: ProjectionLeaseTarget { mount_id, target },
    }
}

struct RetainedRetryBlocker {
    key: ProcessProjectionKey,
    projection: Arc<CachedProcessProjection>,
    projections: std::collections::BTreeMap<ProcessProjectionKey, Arc<CachedProcessProjection>>,
}

fn retained_retry_blocker(
    fixture: &ExactFenceFixture,
    branch: ProjectionLeaseProvider,
    owner: ProjectionLeaseProvider,
    mount_root: std::path::PathBuf,
    workspace_mountpoint: std::path::PathBuf,
    home_mountpoint: std::path::PathBuf,
) -> RetainedRetryBlocker {
    let key = ProcessProjectionKey {
        binding: fixture.binding.clone(),
        read_write: true,
    };
    let state = ProjectionCleanupState {
        kernel: Arc::downgrade(&fixture.kernel),
        stop_policy: crate::storage_mount::process_broker::ProcessStopPolicy::default(),
        binding: fixture.binding.clone(),
        branch,
        owner,
        shared: None,
        mount_root,
        cleaned: false,
    };
    let mut projections = std::collections::BTreeMap::new();
    retain_failed_launch_projection(
        &mut projections,
        &key,
        workspace_mountpoint,
        home_mountpoint,
        None,
        state,
    );
    RetainedRetryBlocker {
        projection: Arc::clone(projections.get(&key).expect("retained retry blocker")),
        key,
        projections,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoked_component_invalidates_cached_exact_set() {
    let (_temporary, kernel, caller, broker) =
        provider_fixture!("revoked_component_invalidates_cached_exact_set");
    let stale = successful_fleet_mount_for_fresh_execution(&kernel, &caller, &broker).await;
    let revoked_mount_id = stale.projection.component_mount_ids[1];

    revoke_lease(
        &kernel,
        &caller,
        MountOwnerScope::CallerOnly,
        revoked_mount_id,
    )
    .await
    .expect("ordinary authorized revocation of one component");
    assert!(!kernel.storage_mounts.contains_key(&revoked_mount_id));

    assert_replacement_after_unhealthy_hit_for_fresh_execution(&kernel, &caller, &broker, stale)
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expired_component_invalidates_cached_exact_set() {
    let (_temporary, kernel, caller, broker) =
        provider_fixture!("expired_component_invalidates_cached_exact_set");
    let stale = successful_fleet_mount_for_fresh_execution(&kernel, &caller, &broker).await;
    for mount_id in &stale.projection.component_mount_ids {
        kernel
            .storage_mounts
            .get(mount_id)
            .expect("recorded exact component")
            .expires_at_epoch_secs
            .store(0, Ordering::Release);
    }

    assert_replacement_after_unhealthy_hit_for_fresh_execution(&kernel, &caller, &broker, stale)
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revocation_cannot_interleave_validation_and_cached_reference() {
    let (_temporary, kernel, caller, broker) =
        provider_fixture!("revocation_cannot_interleave_validation_and_cached_reference");
    let stale = successful_fleet_mount_for_fresh_execution(&kernel, &caller, &broker).await;
    let owner_mount_id = stale.projection.component_mount_ids[1];
    let owner_state = kernel
        .storage_mounts
        .get(&owner_mount_id)
        .map(|entry| Arc::clone(entry.value()))
        .expect("owner component");

    let gate = arm_retain_validation_gate();
    let mount_broker = broker.clone();
    let mount_caller = caller.clone();
    let mount_task = Arc::new(OwnedTask::spawn(async move {
        process_stop::cleanup_evidence::scoped_with_label(
            "stale-invalidation-exact-scope",
            async move {
                let replacement_mount = PROCESS_MOUNT_TEST_ID
                    .scope(
                        process_stop::cache_test_support::fresh_process_mount_test_id(),
                        mount_broker.mount(&mount_caller),
                    )
                    .await
                    .expect("validated unhealthy mount replacement");
                let evidence_scope = process_stop::cleanup_evidence::current_scope_for_test()
                    .expect("stale invalidation evidence scope");
                (evidence_scope, replacement_mount)
            },
        )
        .await
    }));
    bounded_phase("validation gate entry", gate.entered().notified()).await;

    let revoke_kernel = Arc::clone(&kernel);
    let revoke_caller = caller.clone();
    let revocation = Arc::new(OwnedTask::spawn(async move {
        revoke_lease(
            &revoke_kernel,
            &revoke_caller,
            MountOwnerScope::CallerOnly,
            owner_mount_id,
        )
        .await
    }));
    bounded_until("revocation publishes its fence", || {
        owner_state.revoked.load(Ordering::Acquire)
    })
    .await;
    assert!(
        bounded_phase(
            "revocation listener drain",
            owner_state.wait_listener_closed(),
        )
        .await,
        "revocation must drain the component listener while reference admission is paused"
    );
    gate.release().notify_one();

    let body_kernel = Arc::clone(&kernel);
    let body_broker = broker.clone();
    let stale_component_mount_ids = stale.projection.component_mount_ids.clone();
    let finishers = owned_finishers![mount_task, revocation];
    run_owned_test_body(&finishers, move || async move {
        let (stale_evidence_scope, replacement_mount) =
            bounded_phase("validated unhealthy mount replacement", mount_task.join()).await;
        join_revocation(&revocation, "authorized component revocation").await;
        assert_ne!(replacement_mount.workspace_root, stale.mount.workspace_root);
        assert_eq!(
            stale.projection.refs.load(Ordering::Acquire),
            1,
            "the stale projection must not gain a reference after revocation"
        );
        assert_eq!(
            process_stop::cleanup_evidence::take_for_test(stale_evidence_scope),
            expected_successful_projection_evidence(&stale_component_mount_ids),
            "stale invalidation evidence must be consumed before replacement cleanup"
        );

        close_mount("replacement provider close", replacement_mount).await;
        close_mount("stale provider close", stale.mount).await;
        assert!(body_kernel.storage_mounts.is_empty());
        assert!(body_broker.projections.lock().await.is_empty());
    })
    .await;
}

#[tokio::test]
async fn stopped_retry_evidence_never_synthesizes_an_acknowledgement() {
    let fixture = exact_fence_fixture().await;
    let branch_mount_id = fixture.branch.mount_id;
    let owner_mount_id = fixture.owner.mount_id;
    let targets = &fixture.binding.targets;
    let absent_control = fixture.kernel.astrid_home.run_dir().join("absent.sock");
    let running = |mount_id: StorageMountId| ProjectionLeaseProvider {
        running: RunningProvider {
            child: None,
            control_path: absent_control.clone(),
            token: "retry-token".to_owned(),
            stopped: true,
        },
        lease: ProjectionLeaseTarget {
            mount_id,
            target: targets.workspace.clone(),
        },
    };
    let key = ProcessProjectionKey {
        binding: fixture.binding.clone(),
        read_write: true,
    };
    let state = ProjectionCleanupState {
        kernel: Arc::downgrade(&fixture.kernel),
        stop_policy: crate::storage_mount::process_broker::ProcessStopPolicy::default(),
        binding: fixture.binding.clone(),
        branch: running(branch_mount_id),
        owner: running(owner_mount_id),
        shared: None,
        mount_root: fixture.kernel.astrid_home.run_dir(),
        cleaned: false,
    };
    let mut projections = std::collections::BTreeMap::new();
    retain_failed_launch_projection(
        &mut projections,
        &key,
        fixture.kernel.astrid_home.run_dir().join("workspace"),
        fixture.kernel.astrid_home.run_dir().join("owner"),
        None,
        state,
    );
    let projection = Arc::clone(projections.get(&key).expect("retained retry blocker"));

    let scope =
        process_stop::cleanup_evidence::scoped_with_label("stopped-retry-evidence", async {
            assert!(
                !retry_failed_projection(&projection, &mut projections, &key).await,
                "absent production lease state must keep the retry blocked"
            );
            process_stop::cleanup_evidence::current_scope_for_test().expect("retry evidence scope")
        })
        .await;
    let events = process_stop::cleanup_evidence::take_for_test(scope);
    assert_eq!(
        events,
        vec![
            cleanup_event(ProjectionCleanupStage::Binding, false),
            provider_stop_outcome_event(
                ProviderComponent::Branch,
                branch_mount_id,
                ProcessStopOutcome::Stopped {
                    acknowledged: false
                },
            ),
            provider_stop_outcome_event(
                ProviderComponent::OwnerHome,
                owner_mount_id,
                ProcessStopOutcome::Stopped {
                    acknowledged: false
                },
            ),
        ]
    );
}

#[tokio::test]
async fn replacement_listener_cannot_override_retained_stop() {
    let fixture = exact_fence_fixture().await;
    let temporary = tempfile::tempdir().expect("replacement scratch root");
    let mount_root = temporary.path().join("process-mount");
    std::fs::create_dir_all(&mount_root).expect("create retained mount root");
    let branch_mount_id = fixture.branch.mount_id;
    let targets = &fixture.binding.targets;
    let replacement_path = mount_root.join("replacement.sock");
    let replacement_listener =
        astrid_core::local_transport::bind(&replacement_path).expect("bind replacement listener");
    let mut blocker = retained_retry_blocker(
        &fixture,
        retained_provider(
            branch_mount_id,
            targets.workspace.clone(),
            replacement_path,
            true,
        ),
        retained_provider(
            fixture.owner.mount_id,
            targets.owner_home.clone(),
            mount_root.join("owner.sock"),
            true,
        ),
        mount_root.clone(),
        temporary.path().join("workspace"),
        temporary.path().join("owner"),
    );
    crate::storage_mount::process_broker::fail_next_root_removal_for_test(mount_root.clone());

    let scope = process_stop::cleanup_evidence::scoped_with_label("replacement-listener", async {
        assert!(
            !retry_failed_projection(&blocker.projection, &mut blocker.projections, &blocker.key)
                .await,
            "the retained root blocker must remain authoritative"
        );
        process_stop::cleanup_evidence::current_scope_for_test()
            .expect("retained stop evidence scope")
    })
    .await;
    let events = process_stop::cleanup_evidence::take_for_test(scope);
    assert_eq!(
        events,
        vec![
            cleanup_event(ProjectionCleanupStage::Binding, false),
            provider_stop_outcome_event(
                ProviderComponent::Branch,
                branch_mount_id,
                ProcessStopOutcome::Stopped {
                    acknowledged: false
                },
            ),
            provider_stop_outcome_event(
                ProviderComponent::OwnerHome,
                fixture.owner.mount_id,
                ProcessStopOutcome::Stopped {
                    acknowledged: false
                },
            ),
            cleanup_event(ProjectionCleanupStage::ListenerSettlement, false),
            resource_event(fixture.branch.mount_id, false),
            resource_event(fixture.owner.mount_id, false),
            cleanup_event(
                ProjectionCleanupStage::CleanupLedger {
                    mount_id: fixture.branch.mount_id,
                },
                false,
            ),
            cleanup_event(
                ProjectionCleanupStage::CleanupLedger {
                    mount_id: fixture.owner.mount_id,
                },
                false,
            ),
            cleanup_event(ProjectionCleanupStage::ProjectionRoot, true),
        ]
    );
    drop(replacement_listener);
    assert!(mount_root.exists());
}

#[tokio::test]
async fn transient_probe_cannot_override_retained_stop() {
    let fixture = exact_fence_fixture().await;
    let temporary = tempfile::tempdir().expect("transient scratch root");
    let mount_root = temporary.path().join("process-mount");
    std::fs::create_dir_all(&mount_root).expect("create retained mount root");
    let probe_path = mount_root.join("transient.sock");
    let probe_listener = astrid_core::local_transport::bind(&probe_path).expect("bind probe");
    drop(probe_listener);

    let mut blocker = retained_retry_blocker(
        &fixture,
        retained_provider(
            fixture.branch.mount_id,
            fixture.binding.targets.workspace.clone(),
            probe_path,
            false,
        ),
        retained_provider(
            fixture.owner.mount_id,
            fixture.binding.targets.owner_home.clone(),
            mount_root.join("transient-owner.sock"),
            true,
        ),
        mount_root.clone(),
        temporary.path().join("workspace"),
        temporary.path().join("owner"),
    );
    crate::storage_mount::process_broker::fail_next_root_removal_for_test(mount_root.clone());

    let scope = process_stop::cleanup_evidence::scoped_with_label("transient-probe", async {
        assert!(
            !retry_failed_projection(&blocker.projection, &mut blocker.projections, &blocker.key)
                .await,
            "a stale transient endpoint must not synthesize lease cleanup success"
        );
        process_stop::cleanup_evidence::current_scope_for_test()
            .expect("transient probe evidence scope")
    })
    .await;
    assert_eq!(
        process_stop::cleanup_evidence::take_for_test(scope),
        vec![
            cleanup_event(ProjectionCleanupStage::Binding, false),
            provider_stop_outcome_event(
                ProviderComponent::Branch,
                fixture.branch.mount_id,
                ProcessStopOutcome::ControlEndpoint,
            )
        ],
        "an unmanaged stale endpoint must terminate cleanup at its first failure"
    );
    assert!(mount_root.exists());
}

#[tokio::test]
async fn provider_stop_evidence_terminates_at_first_canonical_failure() {
    let fixture = exact_fence_fixture().await;
    let targets = &fixture.binding.targets;
    let failed_branch = ProjectionLeaseProvider {
        running: RunningProvider {
            child: None,
            control_path: fixture.kernel.astrid_home.run_dir().join("unowned.sock"),
            token: "unowned-generation".to_owned(),
            stopped: false,
        },
        lease: ProjectionLeaseTarget {
            mount_id: fixture.branch.mount_id,
            target: targets.workspace.clone(),
        },
    };
    let settled_owner = ProjectionLeaseProvider {
        running: RunningProvider {
            child: None,
            control_path: fixture.kernel.astrid_home.run_dir().join("owner.sock"),
            token: "old-generation-token".to_owned(),
            stopped: true,
        },
        lease: ProjectionLeaseTarget {
            mount_id: fixture.owner.mount_id,
            target: targets.owner_home.clone(),
        },
    };
    let key = ProcessProjectionKey {
        binding: fixture.binding.clone(),
        read_write: true,
    };
    let state = ProjectionCleanupState {
        kernel: Arc::downgrade(&fixture.kernel),
        stop_policy: crate::storage_mount::process_broker::ProcessStopPolicy::default(),
        binding: fixture.binding.clone(),
        branch: failed_branch,
        owner: settled_owner,
        shared: None,
        mount_root: fixture.kernel.astrid_home.run_dir(),
        cleaned: false,
    };
    let mut projections = std::collections::BTreeMap::new();
    retain_failed_launch_projection(
        &mut projections,
        &key,
        fixture.kernel.astrid_home.run_dir().join("workspace"),
        fixture.kernel.astrid_home.run_dir().join("owner"),
        None,
        state,
    );
    let projection = Arc::clone(projections.get(&key).expect("retained retry blocker"));
    let scope =
        process_stop::cleanup_evidence::scoped_with_label("first-provider-failure", async {
            assert!(!retry_failed_projection(&projection, &mut projections, &key).await);
            process_stop::cleanup_evidence::current_scope_for_test()
                .expect("provider failure evidence scope")
        })
        .await;

    assert_eq!(
        process_stop::cleanup_evidence::take_for_test(scope),
        vec![
            cleanup_event(ProjectionCleanupStage::Binding, false),
            provider_stop_outcome_event(
                ProviderComponent::Branch,
                fixture.branch.mount_id,
                ProcessStopOutcome::ControlEndpoint,
            ),
        ],
        "a later already-stopped result must not follow the first canonical failure"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ordinary_last_close_keeps_cache_evidence_in_cleanup_scope() {
    let (_temporary, kernel, caller, broker) =
        provider_fixture!("ordinary_last_close_keeps_cache_evidence_in_cleanup_scope");
    let stale = successful_fleet_mount_for_fresh_execution(&kernel, &caller, &broker).await;
    let component_mount_ids = stale.projection.component_mount_ids.clone();

    let scope = process_stop::cleanup_evidence::scoped_with_label("ordinary-last-close", async {
        bounded_phase("ordinary last-close cleanup", stale.mount.close_async()).await;
        process_stop::cleanup_evidence::current_scope_for_test().expect("last-close evidence scope")
    })
    .await;

    assert_eq!(
        process_stop::cleanup_evidence::take_for_test(scope),
        expected_successful_projection_evidence(&component_mount_ids),
        "CacheRemoval and Complete must remain in the same task-local cleanup scope"
    );
    assert!(broker.projections.lock().await.is_empty());
    assert!(kernel.storage_mounts.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn expiry_cannot_interleave_validation_and_cached_reference() {
    let (_temporary, kernel, caller, broker) =
        provider_fixture!("expiry_cannot_interleave_validation_and_cached_reference");
    let stale = successful_fleet_mount_for_fresh_execution(&kernel, &caller, &broker).await;

    let gate = arm_retain_validation_gate();
    let mount_broker = broker.clone();
    let mount_caller = caller.clone();
    let mount_task = Arc::new(OwnedTask::spawn(async move {
        PROCESS_MOUNT_TEST_ID
            .scope(
                process_stop::cache_test_support::fresh_process_mount_test_id(),
                mount_broker.mount(&mount_caller),
            )
            .await
    }));
    bounded_phase("expiry validation gate entry", gate.entered().notified()).await;
    for mount_id in &stale.projection.component_mount_ids {
        kernel
            .storage_mounts
            .get(mount_id)
            .expect("recorded exact component")
            .expires_at_epoch_secs
            .store(0, Ordering::Release);
    }
    gate.release().notify_one();

    let body_kernel = Arc::clone(&kernel);
    let body_broker = broker.clone();
    let body_caller = caller.clone();
    let finishers = owned_finishers![mount_task];
    run_owned_test_body(&finishers, move || async move {
        let replacement_mount = join_mount(&mount_task, "validated expiry mount replacement").await;
        assert_replacement_after_unhealthy_hit_for_fresh_execution(
            &body_kernel,
            &body_caller,
            &body_broker,
            stale,
        )
        .await;
        close_mount("validated expiry provider close", replacement_mount).await;
        assert!(body_kernel.storage_mounts.is_empty());
        assert!(body_broker.projections.lock().await.is_empty());
    })
    .await;
}

#[tokio::test]
async fn externally_removed_member_fences_remaining_exact_authority() {
    let fixture = exact_fence_fixture().await;
    let removed_mount_id = fixture.shared.mount_id;
    assert!(
        fixture
            .kernel
            .storage_mounts
            .remove(&removed_mount_id)
            .is_some()
    );

    let cleanup: ProjectionCleanup = Arc::new(|| Box::pin(async { true }));
    let (projection, key, mut projections) = exact_cached_projection(
        &fixture,
        vec![
            fixture.branch.mount_id,
            fixture.owner.mount_id,
            removed_mount_id,
        ],
        cleanup,
    );

    assert!(
        invalidate_unhealthy_projection(&fixture.kernel, &projection, &mut projections, &key).await
    );
    assert!(projections.is_empty());
    assert_eq!(
        projection.refs.load(std::sync::atomic::Ordering::Acquire),
        1,
        "invalidation must not add a reference to the degraded set"
    );
    assert!(
        fixture
            .states
            .iter()
            .take(2)
            .all(|state| state.is_revoked_for_test()),
        "remaining authorized members must be fenced before replacement"
    );
}

#[tokio::test]
async fn invalidation_records_cache_removal_and_complete_success() {
    let fixture = exact_fence_fixture().await;
    let stale_cleanup: ProjectionCleanup = Arc::new(|| Box::pin(async { true }));
    let ids = vec![
        fixture.branch.mount_id,
        fixture.owner.mount_id,
        fixture.shared.mount_id,
    ];
    let (projection, key, _) = exact_cached_projection(&fixture, ids.clone(), stale_cleanup);
    let replacement_cleanup: ProjectionCleanup = Arc::new(|| Box::pin(async { true }));
    let (_, _, mut projections) = exact_cached_projection(&fixture, ids, replacement_cleanup);

    let scope =
        process_stop::cleanup_evidence::scoped_with_label("invalidation-cache-removal", async {
            let invalidated = invalidate_unhealthy_projection(
                &fixture.kernel,
                &projection,
                &mut projections,
                &key,
            )
            .await;
            let scope = process_stop::cleanup_evidence::current_scope_for_test()
                .expect("typed evidence execution");
            (scope, invalidated)
        })
        .await;
    assert!(scope.1);
    let events = process_stop::cleanup_evidence::take_for_test(scope.0);
    assert_eq!(events.len(), 2);
    assert!(!events.iter().any(|event| event.failed));
    assert_eq!(events[0].stage, ProjectionCleanupStage::CacheRemoval);
    assert_eq!(events[1].stage, ProjectionCleanupStage::Complete);
}

#[tokio::test]
async fn cleanup_evidence_names_first_lease_resource_failure() {
    let fixture = exact_fence_fixture().await;
    let owner_mount_id = fixture.owner.mount_id;
    let owner_state = Arc::clone(&fixture.states[1]);
    crate::storage_mount::inject_cleanup_fault_for_test(
        &owner_state,
        crate::storage_mount::MountCleanupStage::Callback,
    );
    let targets = &fixture.binding.targets;
    let branch = lease_target(fixture.branch.mount_id, targets.workspace.clone());
    let owner = lease_target(owner_mount_id, targets.owner_home.clone());

    let scope =
        process_stop::cleanup_evidence::scoped_with_label("first-failure-evidence", async {
            assert!(
                !revoke_projection_leases(&fixture.kernel, &fixture.binding, &branch, &owner, None)
                    .await
            );
            process_stop::cleanup_evidence::current_scope_for_test()
                .expect("typed evidence execution")
        })
        .await;
    let events = process_stop::cleanup_evidence::take_for_test(scope);
    assert_eq!(
        events,
        vec![
            cleanup_event(ProjectionCleanupStage::ListenerSettlement, false),
            resource_event(fixture.branch.mount_id, false),
            resource_event(owner_mount_id, true),
        ]
    );
}
