//! Hostile identity, namespace, and projection-revocation regressions.

use std::sync::Arc;

use astrid_core::PrincipalId;
use astrid_core::dirs::AstridHome;
use astrid_core::identity::{FleetUid, PrincipalUid, UserUid};
use astrid_core::storage_filesystem::StorageFilesystemTargetV1;
use astrid_core::storage_provider::{StorageProviderAccessV1, StorageProviderViewV1};
use astrid_storage::StateOwner;

use super::{
    ProcessProjectionBinding, ProcessProjectionTarget, ProcessProjectionTargetSet,
    ProjectionGeneration, blocked_projection_lease, force_revoke_projection_lease,
    rollback_uncommitted_lease,
};
use crate::storage_mount::{
    MountOwnerScope, clear_cleanup_fault_for_test, inject_cleanup_fault_for_test, issue_lease,
    test_mount_admission,
};

fn valid_binding(actor: PrincipalUid, workspace_bytes: [u8; 16]) -> ProcessProjectionBinding {
    let owner = StateOwner::Principal(actor);
    ProcessProjectionBinding::new(
        owner,
        actor,
        ProjectionGeneration::capture().expect("test generation"),
        ProcessProjectionTargetSet::branch(
            owner,
            actor,
            astrid_core::WorkspaceUid::from_bytes(workspace_bytes),
            None,
        )
        .expect("valid target set"),
    )
    .expect("valid principal projection")
}

fn key(binding: ProcessProjectionBinding) -> super::ProcessProjectionKey {
    super::ProcessProjectionKey {
        binding,
        read_write: true,
    }
}

#[test]
fn user_owner_and_namespace_drift_fail_closed() {
    let actor = PrincipalUid::from_bytes([0xA1; 32]);
    let user_owner = StateOwner::User(UserUid::from_bytes([0xB1; 32]));
    let targets = ProcessProjectionTargetSet {
        workspace: ProcessProjectionTarget::WorkspaceBranch {
            owner: user_owner,
            workspace: astrid_core::WorkspaceUid::from_bytes([0xC1; 16]),
        },
        owner_home: ProcessProjectionTarget::AgentHome(actor),
        fleet_shared: None,
    };
    let error = ProcessProjectionBinding::new(
        user_owner,
        actor,
        ProjectionGeneration::capture().expect("test generation"),
        targets,
    )
    .expect_err("User state must not become a process projection");
    assert!(error.contains("user"));

    let fleet = FleetUid::from_bytes([0xD1; 32]);
    let fleet_owner = StateOwner::Fleet(fleet);
    assert!(
        ProcessProjectionTargetSet::branch(
            fleet_owner,
            actor,
            astrid_core::WorkspaceUid::from_bytes([0xC2; 16]),
            None,
        )
        .is_err()
    );
    assert!(
        ProcessProjectionTargetSet::branch(
            StateOwner::Principal(actor),
            actor,
            astrid_core::WorkspaceUid::from_bytes([0xCB; 16]),
            Some(fleet),
        )
        .is_err()
    );
    assert!(
        ProcessProjectionTargetSet {
            workspace: ProcessProjectionTarget::WorkspaceBranch {
                owner: StateOwner::Principal(actor),
                workspace: astrid_core::WorkspaceUid::from_bytes([0xC3; 16]),
            },
            owner_home: ProcessProjectionTarget::AgentHome(actor),
            fleet_shared: Some(ProcessProjectionTarget::FleetShared(fleet)),
        }
        .validate()
        .is_err()
    );
    assert!(
        ProcessProjectionTargetSet {
            workspace: ProcessProjectionTarget::WorkspaceBranch {
                owner: StateOwner::Principal(actor),
                workspace: astrid_core::WorkspaceUid::from_bytes([0xC7; 16]),
            },
            owner_home: ProcessProjectionTarget::AgentHome(actor),
            fleet_shared: None,
        }
        .validate()
        .is_ok()
    );
    assert!(
        ProcessProjectionTargetSet {
            workspace: ProcessProjectionTarget::WorkspaceBranch {
                owner: StateOwner::Fleet(fleet),
                workspace: astrid_core::WorkspaceUid::from_bytes([0xC8; 16]),
            },
            owner_home: ProcessProjectionTarget::AgentHome(actor),
            fleet_shared: Some(ProcessProjectionTarget::FleetShared(fleet)),
        }
        .validate()
        .is_ok()
    );
    assert!(
        ProcessProjectionTargetSet {
            workspace: ProcessProjectionTarget::WorkspaceBranch {
                owner: StateOwner::Fleet(fleet),
                workspace: astrid_core::WorkspaceUid::from_bytes([0xC9; 16]),
            },
            owner_home: ProcessProjectionTarget::AgentHome(actor),
            fleet_shared: None,
        }
        .validate()
        .is_err()
    );
    assert!(
        ProcessProjectionTargetSet::branch(
            StateOwner::Principal(actor),
            actor,
            astrid_core::WorkspaceUid::from_bytes([0xCA; 16]),
            Some(fleet),
        )
        .is_err()
    );
}

#[test]
fn projection_key_requires_exact_identity_generation_and_target() {
    let actor = PrincipalUid::from_bytes([0xA2; 32]);
    let other_actor = PrincipalUid::from_bytes([0xA3; 32]);
    let base = valid_binding(actor, [0xC4; 16]);

    assert_ne!(
        key(base.clone()),
        key(valid_binding(other_actor, [0xC4; 16]))
    );
    assert_ne!(key(base.clone()), key(valid_binding(actor, [0xC5; 16])));

    let changed_generation = ProcessProjectionBinding {
        generation: ProjectionGeneration {
            parent_pid: base.generation.parent_pid.wrapping_add(1),
            start_identity: Arc::from("other-parent-start"),
        },
        ..base.clone()
    };
    assert_ne!(key(base), key(changed_generation));
}

async fn issue_home_lease(
    kernel: &Arc<crate::Kernel>,
    caller: &PrincipalId,
    name: &str,
    provider: &str,
) -> astrid_core::storage_filesystem::StorageMountLeaseV1 {
    let temporary = kernel
        .astrid_home
        .root()
        .join("projection-tests")
        .join(name);
    issue_lease(
        kernel,
        &test_mount_admission(kernel, caller, MountOwnerScope::CallerOnly),
        StorageProviderViewV1::Principal(caller.clone()),
        StorageFilesystemTargetV1::OwnerSubtree {
            prefix: "home".to_owned(),
        },
        StorageProviderAccessV1::ReadWrite,
        provider.to_owned(),
        temporary,
    )
    .await
    .expect("issue projection-style lease")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn force_revoke_requires_exact_actor_owner_and_target() {
    let temporary = tempfile::tempdir().expect("test home root");
    let home = AstridHome::from_path(temporary.path().join(".astrid"));
    let kernel = Arc::new(crate::test_kernel_with_home(home).await);
    let caller = PrincipalId::default();
    let actor = kernel
        .principal_directory
        .uid_for(&caller)
        .expect("caller actor UID");
    let lease = issue_home_lease(&kernel, &caller, "exact", "test-provider").await;
    let owner = StateOwner::Principal(actor);
    let target = StorageFilesystemTargetV1::OwnerSubtree {
        prefix: "home".to_owned(),
    };

    assert!(
        !force_revoke_projection_lease(
            &kernel,
            PrincipalUid::from_bytes([0xE1; 32]),
            owner,
            &target,
            lease.mount_id,
        )
        .await
    );
    assert!(
        !force_revoke_projection_lease(
            &kernel,
            actor,
            StateOwner::Fleet(FleetUid::from_bytes([0xE2; 32])),
            &target,
            lease.mount_id,
        )
        .await
    );
    assert!(
        !force_revoke_projection_lease(
            &kernel,
            actor,
            owner,
            &StorageFilesystemTargetV1::OwnerRoot,
            lease.mount_id,
        )
        .await
    );
    assert!(kernel.storage_mounts.contains_key(&lease.mount_id));
    assert!(force_revoke_projection_lease(&kernel, actor, owner, &target, lease.mount_id).await);
    assert!(!kernel.storage_mounts.contains_key(&lease.mount_id));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_force_revoke_retains_revoked_state_until_retry() {
    let temporary = tempfile::tempdir().expect("test home root");
    let home = AstridHome::from_path(temporary.path().join(".astrid"));
    let kernel = Arc::new(crate::test_kernel_with_home(home).await);
    let caller = PrincipalId::default();
    let actor = kernel
        .principal_directory
        .uid_for(&caller)
        .expect("caller actor UID");
    let lease = issue_home_lease(&kernel, &caller, "retry", "test-provider").await;
    let state = Arc::clone(kernel.storage_mounts.get(&lease.mount_id).unwrap().value());
    inject_cleanup_fault_for_test(&state, crate::storage_mount::MountCleanupStage::Directory);
    let owner = StateOwner::Principal(actor);
    let target = StorageFilesystemTargetV1::OwnerSubtree {
        prefix: "home".to_owned(),
    };

    assert!(!force_revoke_projection_lease(&kernel, actor, owner, &target, lease.mount_id).await);
    assert!(kernel.storage_mounts.contains_key(&lease.mount_id));
    assert!(state.is_revoked_for_test());
    clear_cleanup_fault_for_test(&state);
    assert!(force_revoke_projection_lease(&kernel, actor, owner, &target, lease.mount_id).await);
    assert!(!kernel.storage_mounts.contains_key(&lease.mount_id));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn launch_rollback_revokes_the_exact_typed_projection_target() {
    let temporary = tempfile::tempdir().expect("test home root");
    let home = AstridHome::from_path(temporary.path().join(".astrid"));
    let kernel = Arc::new(crate::test_kernel_with_home(home).await);
    let caller = PrincipalId::default();
    let actor = kernel
        .principal_directory
        .uid_for(&caller)
        .expect("caller actor UID");
    let binding = valid_binding(actor, [0xC6; 16]);
    let lease = issue_home_lease(&kernel, &caller, "rollback", "test-provider").await;
    let wrong_target = ProcessProjectionTarget::FleetShared(FleetUid::from_bytes([0xE3; 32]));

    rollback_uncommitted_lease(&kernel, &binding, &wrong_target, lease.mount_id).await;
    assert!(kernel.storage_mounts.contains_key(&lease.mount_id));
    rollback_uncommitted_lease(
        &kernel,
        &binding,
        &binding.targets.owner_home,
        lease.mount_id,
    )
    .await;
    assert!(!kernel.storage_mounts.contains_key(&lease.mount_id));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retained_projection_lease_blocks_duplicate_creation() {
    let temporary = tempfile::tempdir().expect("test home root");
    let home = AstridHome::from_path(temporary.path().join(".astrid"));
    let kernel = Arc::new(crate::test_kernel_with_home(home).await);
    let caller = PrincipalId::default();
    let actor = kernel
        .principal_directory
        .uid_for(&caller)
        .expect("caller actor UID");
    let binding = valid_binding(actor, [0xCC; 16]);
    let lease = issue_home_lease(
        &kernel,
        &caller,
        "blocked",
        super::platform_process_provider_name(),
    )
    .await;
    let state = Arc::clone(kernel.storage_mounts.get(&lease.mount_id).unwrap().value());
    inject_cleanup_fault_for_test(&state, crate::storage_mount::MountCleanupStage::Directory);

    assert!(
        !force_revoke_projection_lease(
            &kernel,
            actor,
            binding.owner,
            &binding.targets.owner_home.durable_target(),
            lease.mount_id,
        )
        .await
    );
    let error = blocked_projection_lease(&kernel, &binding)
        .expect("retained projection lease must block creation");
    assert!(error.contains("requires cleanup"));

    clear_cleanup_fault_for_test(&state);
    assert!(
        force_revoke_projection_lease(
            &kernel,
            actor,
            binding.owner,
            &binding.targets.owner_home.durable_target(),
            lease.mount_id,
        )
        .await
    );
    assert!(blocked_projection_lease(&kernel, &binding).is_none());
}
