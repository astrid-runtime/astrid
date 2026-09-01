//! A degraded exact component set must invalidate its cached projection.

use std::sync::{Arc, atomic::Ordering};

use crate::storage_mount::process_broker::fail_next_root_removal_for_test;
use crate::storage_mount::process_broker::process_stop::cache_test_support::{
    CachedMount, assert_replacement_after_unhealthy_hit_for_fresh_execution, bounded_phase,
    successful_fleet_mount, successful_fleet_mount_for_fresh_execution, uuid_mount_root,
};
use crate::storage_mount::process_broker::process_stop::cleanup_evidence::{
    CleanupEvidenceScope, ProjectionCleanupEvent as CleanupEvent, ProjectionCleanupStage,
};
use crate::storage_mount::process_broker::process_stop::owned_test_tasks::{
    OwnedTask, OwnedTestTask, run_owned_test_body,
};
use astrid_capsule::context::ProcessStorageMountBroker as _;
use astrid_core::{PrincipalId, storage_provider::StorageMountId};

use super::{KernelProcessStorageMountBroker, ProcessProjectionKey, fleet_shared_kernel};
use crate::storage_mount::process_broker::{
    CachedProcessProjection, ProcessProjectionTarget, ProjectionCleanup, RetainedIssuePaths,
    arm_retain_reference_gate, arm_retain_validation_gate, cleanup_uncommitted_issue_lease_set,
    invalidate_unhealthy_projection, retain_failed_issue_projection, revoke_projection_leases,
};
use crate::storage_mount::{MountOwnerScope, issue_lease, revoke_lease};

#[path = "root_retry_tests.rs"]
mod root_retry_tests;

fn provider_test_executable(
    directory: &std::path::Path,
    name: &str,
    exe_suffix: &str,
) -> std::path::PathBuf {
    directory.join(format!("{name}{exe_suffix}"))
}

fn provider_lane_is_ready(test_name: &str) -> bool {
    let provider = std::env::current_exe().ok().and_then(|test_binary| {
        test_binary.parent().map(|directory| {
            provider_test_executable(
                directory,
                super::super::platform_process_provider_name(),
                std::env::consts::EXE_SUFFIX,
            )
        })
    });
    let ready = provider.is_some_and(|provider| {
        std::fs::symlink_metadata(provider).is_ok_and(|metadata| metadata.is_file())
    }) && std::env::var("ASTRID_PROCESS_PROVIDER_TESTS")
        .is_ok_and(|value| value == "1");
    if !ready {
        println!("skipping {test_name}: coinstalled provider is unavailable");
    }
    ready
}

#[test]
fn provider_lane_executable_suffix_is_appended_exactly_once() {
    let directory = std::path::Path::new("/test-binaries");
    let windows = provider_test_executable(directory, "astrid-storage-provider-winfsp", ".exe");
    assert_eq!(
        windows.file_name(),
        Some(std::ffi::OsStr::new("astrid-storage-provider-winfsp.exe"))
    );
    assert!(
        !windows
            .to_string_lossy()
            .ends_with("astrid-storage-provider-winfsp..exe")
    );

    let current = provider_test_executable(
        directory,
        super::super::platform_process_provider_name(),
        std::env::consts::EXE_SUFFIX,
    );
    let current_file_name = format!(
        "{}{}",
        super::super::platform_process_provider_name(),
        std::env::consts::EXE_SUFFIX
    );
    assert_eq!(
        current.file_name().and_then(std::ffi::OsStr::to_str),
        Some(current_file_name.as_str())
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn identical_legacy_labels_use_distinct_evidence_executions() {
    async fn probe(label: &'static str) -> CleanupEvidenceScope {
        super::super::process_stop::cleanup_evidence::scoped_with_label(label, async {
            super::super::process_stop::cleanup_evidence::record(
                ProjectionCleanupStage::Binding,
                true,
            );
            super::super::process_stop::cleanup_evidence::current_scope_for_test()
                .expect("evidence execution")
        })
        .await
    }

    let left_task = tokio::spawn(probe("legacy-651"));
    let right_task = tokio::spawn(probe("legacy-651"));
    let (left, right) = tokio::join!(left_task, right_task);
    let left = left.expect("left evidence probe");
    let right = right.expect("right evidence probe");

    assert_eq!(left.legacy_label, right.legacy_label);
    assert_ne!(left.execution, right.execution);
    assert_eq!(
        super::super::process_stop::cleanup_evidence::take_for_test(left),
        vec![cleanup_event(ProjectionCleanupStage::Binding, true)]
    );
    assert_eq!(
        super::super::process_stop::cleanup_evidence::take_for_test(right),
        vec![cleanup_event(ProjectionCleanupStage::Binding, true)],
        "the first take must not consume the concurrently labeled execution"
    );
    assert!(
        super::super::process_stop::cleanup_evidence::take_for_test(left).is_empty()
            && super::super::process_stop::cleanup_evidence::take_for_test(right).is_empty()
    );
}

macro_rules! owned_finishers {
    [$($task:expr),+ $(,)?] => {
        [$(Arc::clone(&$task) as std::sync::Arc<dyn OwnedTestTask>),+]
    };
}

async fn bounded_until(phase: &'static str, mut predicate: impl FnMut() -> bool) {
    bounded_phase(phase, async {
        while !predicate() {
            tokio::task::yield_now().await;
        }
    })
    .await;
}

macro_rules! provider_fixture {
    ($test_name:literal) => {{
        if !provider_lane_is_ready($test_name) {
            return;
        }
        let (temporary, kernel) = fleet_shared_kernel().await;
        let caller = PrincipalId::default();
        let broker = KernelProcessStorageMountBroker::new(Arc::downgrade(&kernel));
        (temporary, kernel, caller, broker)
    }};
}

async fn join_mount(
    task: &Arc<OwnedTask<Result<astrid_capsule::context::ProcessStorageMount, String>>>,
    phase: &'static str,
) -> astrid_capsule::context::ProcessStorageMount {
    bounded_phase(phase, task.join())
        .await
        .expect("mount admission task succeeded")
}

async fn join_revocation(task: &Arc<OwnedTask<Result<(), String>>>, phase: &'static str) {
    bounded_phase(phase, task.join())
        .await
        .expect("authorized revocation succeeded");
}

async fn close_mount(phase: &'static str, mount: astrid_capsule::context::ProcessStorageMount) {
    bounded_phase(phase, mount.close_async()).await;
}

async fn assert_fresh_replacement(
    kernel: &Arc<crate::Kernel>,
    broker: &KernelProcessStorageMountBroker,
    stale: &Arc<CachedProcessProjection>,
    replacement: astrid_capsule::context::ProcessStorageMount,
) {
    let stale_root = stale
        .workspace_mountpoint
        .parent()
        .expect("fresh UUID projection root")
        .to_path_buf();
    assert!(!stale_root.exists(), "cleanup must remove the stale root");
    assert_eq!(
        stale.refs.load(Ordering::Acquire),
        0,
        "stale stayed unreferenced"
    );
    assert_component_liveness(
        kernel,
        &stale.component_mount_ids,
        false,
        "revoked set absent",
    );
    let projections = broker.projections.lock().await;
    assert_eq!(projections.len(), 1);
    let fresh = projections.values().next().expect("replacement");
    assert!(!Arc::ptr_eq(fresh, stale));
    assert_eq!(fresh.refs.load(Ordering::Acquire), 1);
    drop(projections);
    close_mount("fresh replacement close", replacement).await;
    assert!(kernel.storage_mounts.is_empty());
    assert!(broker.projections.lock().await.is_empty());
}

fn assert_component_liveness(
    kernel: &Arc<crate::Kernel>,
    mount_ids: &[StorageMountId],
    live: bool,
    message: &'static str,
) {
    assert!(
        mount_ids
            .iter()
            .all(|mount_id| kernel.storage_mounts.contains_key(mount_id) == live),
        "{message}"
    );
}

fn exact_cached_projection(
    fixture: &super::ExactFenceFixture,
    mount_ids: Vec<StorageMountId>,
    cleanup: ProjectionCleanup,
) -> ExactCachedProjection {
    let projection = Arc::new(CachedProcessProjection {
        binding: fixture.binding.clone(),
        component_mount_ids: mount_ids,
        workspace_mountpoint: fixture.kernel.astrid_home.run_dir(),
        home_mountpoint: fixture.kernel.astrid_home.run_dir(),
        fleet_shared_mountpoint: None,
        refs: std::sync::atomic::AtomicU64::new(1),
        closing: std::sync::atomic::AtomicBool::new(false),
        cleanup_failed: std::sync::atomic::AtomicBool::new(false),
        cleanup,
    });
    let key = ProcessProjectionKey {
        binding: fixture.binding.clone(),
        read_write: true,
    };
    let mut projections = std::collections::BTreeMap::new();
    projections.insert(key.clone(), Arc::clone(&projection));
    (projection, key, projections)
}

type CacheMap = std::collections::BTreeMap<ProcessProjectionKey, Arc<CachedProcessProjection>>;
type ExactCachedProjection = (Arc<CachedProcessProjection>, ProcessProjectionKey, CacheMap);

fn cleanup_event(stage: ProjectionCleanupStage, failed: bool) -> CleanupEvent {
    CleanupEvent { failed, stage }
}

fn provider_stop_event(
    component: crate::storage_mount::process_broker::process_stop::cleanup_evidence::ProviderComponent,
) -> CleanupEvent {
    cleanup_event(
        ProjectionCleanupStage::ProviderStop {
            component,
            outcome: super::super::process_stop::ProcessStopOutcome::Stopped { acknowledged: true },
        },
        false,
    )
}

fn resource_event(mount_id: StorageMountId, failed: bool) -> CleanupEvent {
    cleanup_event(ProjectionCleanupStage::LeaseResources { mount_id }, failed)
}

fn lease_target(
    mount_id: StorageMountId,
    target: ProcessProjectionTarget,
) -> super::ProjectionLeaseTarget {
    super::ProjectionLeaseTarget { mount_id, target }
}

fn cleanup_marker(
    fixture: &super::ExactFenceFixture,
    mount_id: StorageMountId,
) -> std::path::PathBuf {
    fixture
        .kernel
        .astrid_home
        .run_dir()
        .join("mount-cleanup")
        .join(format!("{mount_id}.cleaned"))
}

fn expected_successful_projection_evidence(
    component_mount_ids: &[StorageMountId],
) -> Vec<CleanupEvent> {
    use crate::storage_mount::process_broker::process_stop::cleanup_evidence::ProviderComponent;

    let [branch, owner, shared] = component_mount_ids else {
        panic!("fleet projection evidence requires exactly three components");
    };
    [
        cleanup_event(ProjectionCleanupStage::Binding, false),
        provider_stop_event(ProviderComponent::Branch),
        provider_stop_event(ProviderComponent::OwnerHome),
        provider_stop_event(ProviderComponent::FleetShared),
        cleanup_event(ProjectionCleanupStage::ListenerSettlement, false),
        resource_event(*branch, false),
        resource_event(*owner, false),
        resource_event(*shared, false),
        cleanup_event(
            ProjectionCleanupStage::CleanupLedger { mount_id: *branch },
            false,
        ),
        cleanup_event(
            ProjectionCleanupStage::CleanupLedger { mount_id: *owner },
            false,
        ),
        cleanup_event(
            ProjectionCleanupStage::CleanupLedger { mount_id: *shared },
            false,
        ),
        cleanup_event(ProjectionCleanupStage::ProjectionRoot, false),
        cleanup_event(ProjectionCleanupStage::CacheRemoval, false),
        cleanup_event(ProjectionCleanupStage::Complete, false),
    ]
    .into_iter()
    .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fresh_admission_has_exactly_one_guard_reference() {
    let (_temporary, kernel, caller, broker) =
        provider_fixture!("fresh_admission_has_exactly_one_guard_reference");

    let CachedMount {
        mount: first,
        projection,
    } = successful_fleet_mount_for_fresh_execution(&kernel, &caller, &broker).await;
    let mount_root = first
        .workspace_root
        .parent()
        .expect("fresh UUID mount root")
        .to_path_buf();
    assert!(mount_root.exists(), "fresh admission must start its root");
    assert!(
        mount_root.file_name().is_some_and(|name| {
            name.len() == 32
                && name
                    .to_string_lossy()
                    .chars()
                    .all(|char| char.is_ascii_hexdigit())
        }),
        "the projection parent must be one UUID incarnation, not the shared process-storage parent"
    );
    assert_eq!(projection.component_mount_ids.len(), 3);

    let reused = super::PROCESS_MOUNT_TEST_ID
        .scope(
            super::super::process_stop::cache_test_support::fresh_process_mount_test_id(),
            broker.mount(&caller),
        )
        .await
        .expect("cached process projection while the first guard is held");
    assert_eq!(reused.workspace_root, first.workspace_root);
    assert_eq!(reused.home_root, first.home_root);
    assert_eq!(projection.refs.load(Ordering::Acquire), 2);
    assert_eq!(broker.projections.lock().await.len(), 1);

    first.close_async().await;
    assert_eq!(projection.refs.load(Ordering::Acquire), 1);
    assert_eq!(broker.projections.lock().await.len(), 1);
    assert!(mount_root.exists(), "the last close must own cleanup");
    assert_component_liveness(
        &kernel,
        &projection.component_mount_ids,
        true,
        "live guard set",
    );

    reused.close_async().await;
    assert_eq!(
        projection.refs.load(Ordering::Acquire),
        0,
        "the last close must drain exactly one reference"
    );
    assert!(broker.projections.lock().await.is_empty());
    assert_component_liveness(
        &kernel,
        &projection.component_mount_ids,
        false,
        "clean exact set",
    );
    assert!(!mount_root.exists(), "the last close must clean the root");

    let CachedMount {
        mount: remounted,
        projection: remounted_projection,
    } = successful_fleet_mount_for_fresh_execution(&kernel, &caller, &broker).await;
    assert!(!Arc::ptr_eq(&projection, &remounted_projection));
    assert_eq!(remounted_projection.refs.load(Ordering::Acquire), 1);
    remounted.close_async().await;
    assert_eq!(remounted_projection.refs.load(Ordering::Acquire), 0);
    assert!(kernel.storage_mounts.is_empty());
    assert!(broker.projections.lock().await.is_empty());
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
        super::PROCESS_MOUNT_TEST_ID
            .scope(
                super::super::process_stop::cache_test_support::fresh_process_mount_test_id(),
                mount_broker.mount(&mount_caller),
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
        let replacement_mount =
            join_mount(&mount_task, "validated unhealthy mount replacement").await;
        join_revocation(&revocation, "authorized component revocation").await;
        assert_ne!(replacement_mount.workspace_root, stale.mount.workspace_root);
        assert_eq!(
            stale.projection.refs.load(Ordering::Acquire),
            1,
            "the stale projection must not gain a reference after revocation"
        );

        close_mount("replacement provider close", replacement_mount).await;
        close_mount("stale provider close", stale.mount).await;
        assert!(body_kernel.storage_mounts.is_empty());
        assert!(body_broker.projections.lock().await.is_empty());
        assert_eq!(
            super::super::process_stop::cleanup_evidence::take_latest_for_test(),
            expected_successful_projection_evidence(&stale_component_mount_ids)
        );
    })
    .await;
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
        super::PROCESS_MOUNT_TEST_ID
            .scope(
                super::super::process_stop::cache_test_support::fresh_process_mount_test_id(),
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
    let fixture = super::exact_fence_fixture().await;
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
    let fixture = super::exact_fence_fixture().await;
    let stale_cleanup: ProjectionCleanup = Arc::new(|| Box::pin(async { true }));
    let ids = vec![
        fixture.branch.mount_id,
        fixture.owner.mount_id,
        fixture.shared.mount_id,
    ];
    let (projection, key, _) = exact_cached_projection(&fixture, ids.clone(), stale_cleanup);
    let replacement_cleanup: ProjectionCleanup = Arc::new(|| Box::pin(async { true }));
    let (_, _, mut projections) = exact_cached_projection(&fixture, ids, replacement_cleanup);

    let scope = super::super::process_stop::cleanup_evidence::scoped_with_label(
        "invalidation-cache-removal",
        async {
            let invalidated = invalidate_unhealthy_projection(
                &fixture.kernel,
                &projection,
                &mut projections,
                &key,
            )
            .await;
            let scope = super::super::process_stop::cleanup_evidence::current_scope_for_test()
                .expect("typed evidence execution");
            (scope, invalidated)
        },
    )
    .await;
    assert!(scope.1);
    let events = super::super::process_stop::cleanup_evidence::take_for_test(scope.0);
    assert_eq!(events.len(), 3);
    assert!(!events.iter().any(|event| event.failed));
    assert_eq!(events[1].stage, ProjectionCleanupStage::CacheRemoval);
    assert_eq!(events[2].stage, ProjectionCleanupStage::Complete);
}

#[tokio::test]
async fn cleanup_evidence_names_first_lease_resource_failure() {
    let fixture = super::exact_fence_fixture().await;
    let owner_mount_id = fixture.owner.mount_id;
    let owner_state = Arc::clone(&fixture.states[1]);
    crate::storage_mount::inject_cleanup_fault_for_test(
        &owner_state,
        crate::storage_mount::MountCleanupStage::Callback,
    );
    let targets = &fixture.binding.targets;
    let branch = lease_target(fixture.branch.mount_id, targets.workspace.clone());
    let owner = lease_target(owner_mount_id, targets.owner_home.clone());

    let scope = super::super::process_stop::cleanup_evidence::scoped_with_label(
        "first-failure-evidence",
        async {
            assert!(
                !revoke_projection_leases(&fixture.kernel, &fixture.binding, &branch, &owner, None)
                    .await
            );
            super::super::process_stop::cleanup_evidence::current_scope_for_test()
                .expect("typed evidence execution")
        },
    )
    .await;
    let events = super::super::process_stop::cleanup_evidence::take_for_test(scope);
    assert_eq!(
        events,
        vec![
            cleanup_event(ProjectionCleanupStage::ListenerSettlement, false),
            resource_event(fixture.branch.mount_id, false),
            resource_event(owner_mount_id, true),
        ]
    );
}

#[tokio::test]
async fn provider_drift_is_unauthorized_for_cleanup_and_reuse() {
    let fixture = super::exact_fence_fixture().await;
    let drifted_lease = issue_lease(
        &fixture.kernel,
        &crate::storage_mount::test_mount_admission(
            &fixture.kernel,
            &fixture.caller,
            crate::storage_mount::MountOwnerScope::CrossOwnerWrite,
        ),
        astrid_core::storage_provider::StorageProviderViewV1::Principal(fixture.caller.clone()),
        fixture.binding.targets.owner_home.durable_target(),
        astrid_core::storage_provider::StorageProviderAccessV1::ReadWrite,
        "drifted-process-provider".to_owned(),
        fixture.kernel.astrid_home.run_dir().join("drifted-owner"),
    )
    .await
    .expect("issue drifted owner authority");

    let cleanup: ProjectionCleanup = Arc::new(|| Box::pin(async { true }));
    let (projection, key, mut projections) = exact_cached_projection(
        &fixture,
        vec![
            fixture.branch.mount_id,
            drifted_lease.mount_id,
            fixture.shared.mount_id,
        ],
        cleanup,
    );

    assert!(
        !invalidate_unhealthy_projection(&fixture.kernel, &projection, &mut projections, &key)
            .await,
        "provider drift must remain retained for administrative cleanup"
    );
    assert!(
        projection
            .cleanup_failed
            .load(std::sync::atomic::Ordering::Acquire)
    );
    assert_eq!(projections.len(), 1);
    for state in &fixture.states {
        assert!(!state.is_revoked_for_test());
    }
    assert!(
        !fixture
            .kernel
            .storage_mounts
            .get(&drifted_lease.mount_id)
            .expect("drifted authority remains")
            .is_revoked_for_test()
    );
}

#[tokio::test]
async fn externally_removed_partial_issue_member_is_already_clean() {
    let fixture = super::exact_fence_fixture().await;
    let owner_mount_id = fixture.owner.mount_id;
    assert!(
        fixture
            .kernel
            .storage_mounts
            .remove(&owner_mount_id)
            .is_some()
    );
    let targets = &fixture.binding.targets;
    let branch = lease_target(fixture.branch.mount_id, targets.workspace.clone());
    let owner = lease_target(owner_mount_id, targets.owner_home.clone());

    assert!(
        cleanup_uncommitted_issue_lease_set(
            &fixture.kernel,
            &fixture.binding,
            &branch,
            Some(&owner)
        )
        .await
    );
    assert!(!fixture.kernel.storage_mounts.contains_key(&branch.mount_id));
}

#[tokio::test]
async fn mismatched_partial_issue_member_blocks_exact_cleanup() {
    let fixture = super::exact_fence_fixture().await;
    let drifted_lease = issue_lease(
        &fixture.kernel,
        &crate::storage_mount::test_mount_admission(
            &fixture.kernel,
            &fixture.caller,
            crate::storage_mount::MountOwnerScope::CrossOwnerWrite,
        ),
        astrid_core::storage_provider::StorageProviderViewV1::Principal(fixture.caller.clone()),
        fixture.binding.targets.owner_home.durable_target(),
        astrid_core::storage_provider::StorageProviderAccessV1::ReadWrite,
        "drifted-process-provider".to_owned(),
        fixture.kernel.astrid_home.run_dir().join("drifted-owner"),
    )
    .await
    .expect("issue mismatched owner authority");
    let targets = &fixture.binding.targets;
    let branch = lease_target(fixture.branch.mount_id, targets.workspace.clone());
    let owner = lease_target(drifted_lease.mount_id, targets.owner_home.clone());

    assert!(
        !cleanup_uncommitted_issue_lease_set(
            &fixture.kernel,
            &fixture.binding,
            &branch,
            Some(&owner)
        )
        .await
    );
    assert!(fixture.kernel.storage_mounts.contains_key(&branch.mount_id));
    assert!(
        fixture
            .kernel
            .storage_mounts
            .contains_key(&drifted_lease.mount_id)
    );
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn failed_issue_cleanup_retains_root_and_retry_authority() {
    let fixture = super::exact_fence_fixture().await;
    let root = tempfile::tempdir().expect("issue cleanup scratch root");
    let mount_root = root.path().join("process-mount");
    std::fs::create_dir_all(&mount_root).expect("create retained issue root");
    let targets = &fixture.binding.targets;
    let branch = lease_target(fixture.branch.mount_id, targets.workspace.clone());
    let owner = lease_target(fixture.owner.mount_id, targets.owner_home.clone());
    let key = ProcessProjectionKey {
        binding: fixture.binding.clone(),
        read_write: true,
    };
    let mut projections = std::collections::BTreeMap::new();
    retain_failed_issue_projection(
        &mut projections,
        &key,
        &fixture.kernel,
        vec![branch.mount_id, owner.mount_id],
        RetainedIssuePaths {
            workspace: mount_root.join("workspace"),
            home: mount_root.join("owner"),
            fleet_shared: None,
        },
        branch.clone(),
        Some(owner),
    );
    let projection = Arc::clone(projections.get(&key).expect("retained issue blocker"));
    let owner_state = Arc::clone(&fixture.states[1]);
    crate::storage_mount::inject_cleanup_fault_for_test(
        &owner_state,
        crate::storage_mount::MountCleanupStage::Callback,
    );

    assert!(
        !super::retry_failed_projection(&projection, &mut projections, &key).await,
        "an injected cleanup failure must keep the bounded retry blocked"
    );
    assert_eq!(projections.len(), 1);
    assert!(
        projection
            .cleanup_failed
            .load(std::sync::atomic::Ordering::Acquire)
    );
    assert!(fixture.kernel.storage_mounts.contains_key(&branch.mount_id));
    assert!(
        fixture
            .kernel
            .storage_mounts
            .contains_key(&fixture.owner.mount_id)
    );
    assert!(
        mount_root.exists(),
        "failed cleanup must retain the UUID root"
    );
    let branch_marker = cleanup_marker(&fixture, branch.mount_id);
    assert!(
        branch_marker.is_file(),
        "the branch resource completed before the owner fault and must be ledgered"
    );
    assert!(
        !cleanup_marker(&fixture, fixture.owner.mount_id).is_file(),
        "only the component whose resources were removed may be ledgered"
    );

    for state in &fixture.states {
        crate::storage_mount::clear_cleanup_fault_for_test(state);
    }
    fail_next_root_removal_for_test(mount_root.clone());
    assert!(
        !super::retry_failed_projection(&projection, &mut projections, &key).await,
        "faulted root removal must fail the partial-issue retry"
    );
    assert!(
        projection
            .cleanup_failed
            .load(std::sync::atomic::Ordering::Acquire),
    );
    assert!(!fixture.kernel.storage_mounts.contains_key(&branch.mount_id));
    assert!(
        !fixture
            .kernel
            .storage_mounts
            .contains_key(&fixture.owner.mount_id)
    );
    assert!(
        mount_root.exists(),
        "successful lease cleanup plus failed root removal must retain the UUID root"
    );
    assert!(
        super::retry_failed_projection(&projection, &mut projections, &key).await,
        "the exact retry after the root fault must remove the root"
    );
    assert!(!fixture.kernel.storage_mounts.contains_key(&branch.mount_id));
    assert!(
        !fixture
            .kernel
            .storage_mounts
            .contains_key(&fixture.owner.mount_id)
    );
    assert!(
        !mount_root.exists(),
        "successful retry must remove the root"
    );
    assert!(
        !fixture
            .kernel
            .astrid_home
            .run_dir()
            .join("mount-cleanup")
            .exists(),
        "completed unmap must retire the exact cleanup ledger"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revocation_after_validation_before_reference_admits_replacement() {
    let (_temporary, kernel, caller, broker) =
        provider_fixture!("revocation_after_validation_before_reference_admits_replacement");
    let stale = successful_fleet_mount_for_fresh_execution(&kernel, &caller, &broker).await;
    let owner_mount_id = stale.projection.component_mount_ids[1];
    let owner_state = kernel
        .storage_mounts
        .get(&owner_mount_id)
        .map(|entry| Arc::clone(entry.value()))
        .expect("owner component");

    let validation_gate = arm_retain_validation_gate();
    let reference_gate = arm_retain_reference_gate();
    let mount_broker = broker.clone();
    let mount_caller = caller.clone();
    let mount_task = Arc::new(OwnedTask::spawn(async move {
        super::PROCESS_MOUNT_TEST_ID
            .scope(
                super::super::process_stop::cache_test_support::fresh_process_mount_test_id(),
                mount_broker.mount(&mount_caller),
            )
            .await
    }));
    bounded_phase(
        "post-validation gate entry",
        validation_gate.entered().notified(),
    )
    .await;
    validation_gate.release().notify_one();
    bounded_phase("reference gate entry", reference_gate.entered().notified()).await;

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
    bounded_until("post-validation revocation fence", || {
        owner_state.revoked.load(Ordering::Acquire)
    })
    .await;
    assert!(
        bounded_phase(
            "post-validation listener drain",
            owner_state.wait_listener_closed(),
        )
        .await,
        "revocation must drain the component listener before reference release"
    );
    reference_gate.release().notify_one();

    let body_kernel = Arc::clone(&kernel);
    let body_broker = broker.clone();
    let body_caller = caller.clone();
    let finishers = owned_finishers![mount_task, revocation];
    run_owned_test_body(&finishers, move || async move {
        let replacement_mount = join_mount(&mount_task, "post-validation mount replacement").await;
        join_revocation(&revocation, "post-validation revocation").await;
        assert_replacement_after_unhealthy_hit_for_fresh_execution(
            &body_kernel,
            &body_caller,
            &body_broker,
            stale,
        )
        .await;
        close_mount("post-validation provider close", replacement_mount).await;
        assert!(body_kernel.storage_mounts.is_empty());
        assert!(body_broker.projections.lock().await.is_empty());
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn first_mount_revocation_between_validation_and_reference_admits_replacement() {
    if !provider_lane_is_ready(
        "first_mount_revocation_between_validation_and_reference_admits_replacement",
    ) {
        return;
    }
    let (_temporary, kernel) = fleet_shared_kernel().await;
    let caller = PrincipalId::default();
    let broker = KernelProcessStorageMountBroker::new(Arc::downgrade(&kernel));
    let validation_gate = arm_retain_validation_gate();
    let reference_gate = arm_retain_reference_gate();
    let mount_broker = broker.clone();
    let mount_caller = caller.clone();
    let mount_task = Arc::new(OwnedTask::spawn(async move {
        super::PROCESS_MOUNT_TEST_ID
            .scope(
                super::super::process_stop::cache_test_support::fresh_process_mount_test_id(),
                mount_broker.mount(&mount_caller),
            )
            .await
    }));

    bounded_phase(
        "fresh revocation validation gate",
        validation_gate.entered().notified(),
    )
    .await;
    validation_gate.release().notify_one();
    bounded_phase(
        "fresh revocation reference gate",
        reference_gate.entered().notified(),
    )
    .await;
    let projections = broker.projections.lock().await;
    let stale = Arc::clone(projections.values().next().expect("fresh publication"));
    drop(projections);
    let owner_mount_id = stale.component_mount_ids[1];
    let owner_state = Arc::clone(
        kernel
            .storage_mounts
            .get(&owner_mount_id)
            .expect("fresh owner")
            .value(),
    );
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
    bounded_until("fresh-mount revocation fence", || {
        owner_state.revoked.load(Ordering::Acquire)
    })
    .await;
    assert!(
        bounded_phase(
            "fresh-mount listener drain",
            owner_state.wait_listener_closed(),
        )
        .await,
        "fresh-mount revocation must STOP and close the listener before retain resumes"
    );
    reference_gate.release().notify_one();

    let body_kernel = Arc::clone(&kernel);
    let body_broker = broker.clone();
    let finishers = owned_finishers![mount_task, revocation];
    run_owned_test_body(&finishers, move || async move {
        let replacement_mount = join_mount(&mount_task, "fresh retain replacement").await;
        join_revocation(&revocation, "fresh-mount revocation join").await;
        assert_fresh_replacement(&body_kernel, &body_broker, &stale, replacement_mount).await;
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn first_mount_expiry_between_validation_and_reference_admits_replacement() {
    if !provider_lane_is_ready(
        "first_mount_expiry_between_validation_and_reference_admits_replacement",
    ) {
        return;
    }
    let (_temporary, kernel) = fleet_shared_kernel().await;
    let caller = PrincipalId::default();
    let broker = KernelProcessStorageMountBroker::new(Arc::downgrade(&kernel));
    let validation_gate = arm_retain_validation_gate();
    let reference_gate = arm_retain_reference_gate();
    let mount_broker = broker.clone();
    let mount_caller = caller.clone();
    let mount_task = Arc::new(OwnedTask::spawn(async move {
        super::PROCESS_MOUNT_TEST_ID
            .scope(
                super::super::process_stop::cache_test_support::fresh_process_mount_test_id(),
                mount_broker.mount(&mount_caller),
            )
            .await
    }));
    bounded_phase(
        "fresh expiry validation gate",
        validation_gate.entered().notified(),
    )
    .await;
    validation_gate.release().notify_one();
    bounded_phase(
        "fresh expiry reference gate",
        reference_gate.entered().notified(),
    )
    .await;
    let stale = {
        let projections = broker.projections.lock().await;
        Arc::clone(projections.values().next().expect("fresh publication"))
    };
    for mount_id in &stale.component_mount_ids {
        kernel
            .storage_mounts
            .get(mount_id)
            .expect("fresh exact component")
            .expires_at_epoch_secs
            .store(0, Ordering::Release);
    }
    reference_gate.release().notify_one();

    let body_kernel = Arc::clone(&kernel);
    let body_broker = broker.clone();
    let finishers = owned_finishers![mount_task];
    run_owned_test_body(&finishers, move || async move {
        let replacement_mount = join_mount(&mount_task, "fresh expiry replacement").await;
        assert_fresh_replacement(&body_kernel, &body_broker, &stale, replacement_mount).await;
    })
    .await;
}
