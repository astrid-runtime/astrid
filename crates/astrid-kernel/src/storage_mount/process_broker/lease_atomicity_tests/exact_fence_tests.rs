//! Exact-set fencing while a mutation is already admitted.

use std::sync::Arc;

use astrid_core::storage_filesystem::StorageFilesystemOperationV1;

use super::{ProjectionLeaseTarget, exact_fence_fixture};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exact_set_fence_denies_reads_and_renewal_while_writer_held() {
    use super::fence_projection_leases_for_test;
    use std::sync::atomic::Ordering as AtomicOrdering;

    let fixture = exact_fence_fixture().await;
    let branch_state = Arc::clone(&fixture.states[0]);
    let gate = Arc::new(crate::storage_mount::MutationTestGate {
        entered: tokio::sync::Semaphore::new(0),
        release: tokio::sync::Semaphore::new(0),
    });
    *branch_state.mutation_test_gate.lock().unwrap() = Some(Arc::clone(&gate));
    let mutation_kernel = Arc::clone(&fixture.kernel);
    let mutation = tokio::spawn(async move {
        crate::storage_mount::execute_operation_for_test(
            &mutation_kernel,
            &branch_state,
            StorageFilesystemOperationV1::Create {
                path: "in-flight.bin".to_owned(),
                kind: astrid_core::storage_filesystem::StorageFilesystemEntryKindV1::File,
            },
        )
        .await
    });
    gate.entered
        .acquire()
        .await
        .expect("writer entered")
        .forget();

    let targets = &fixture.binding.targets;
    let branch_target = ProjectionLeaseTarget {
        mount_id: fixture.branch.mount_id,
        target: targets.workspace.clone(),
    };
    let owner_target = ProjectionLeaseTarget {
        mount_id: fixture.owner.mount_id,
        target: targets.owner_home.clone(),
    };
    let shared_target = ProjectionLeaseTarget {
        mount_id: fixture.shared.mount_id,
        target: targets
            .fleet_shared
            .as_ref()
            .expect("shared target")
            .clone(),
    };
    let fence_kernel = Arc::clone(&fixture.kernel);
    let binding = fixture.binding.clone();
    let fence = tokio::spawn(async move {
        fence_projection_leases_for_test(
            &fence_kernel,
            &binding,
            &branch_target,
            &owner_target,
            Some(&shared_target),
        )
        .await
    });
    while !fixture.states[0].revoked.load(AtomicOrdering::Acquire) {
        tokio::task::yield_now().await;
    }

    super::assert_exact_reads_and_renewals_denied(&fixture).await;
    assert!(
        fixture
            .states
            .iter()
            .all(|state| state.is_revoked_for_test()),
        "the complete exact set must be synchronously revoked"
    );
    gate.release.add_permits(1);
    let mutation_outcome = mutation.await.expect("held writer completes");
    assert!(
        matches!(
            mutation_outcome,
            astrid_core::storage_filesystem::StorageFilesystemOutcomeV1::Success(_)
        ),
        "revocation must drain an already admitted writer: {mutation_outcome:?}"
    );
    assert!(fence.await.expect("exact-set fence"));
}
