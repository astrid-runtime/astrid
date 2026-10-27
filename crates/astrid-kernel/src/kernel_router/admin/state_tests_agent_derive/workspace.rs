//! Capsule readiness must see the same workspace owner as a fresh service.
use super::*;
use astrid_capsule::capsule::ReadyStatus;
use astrid_capsule::context::WorkspaceBranchService;
use astrid_storage::FilesystemPath;

pub(super) struct WorkspaceProbe {
    service: Arc<WorkspaceBranchService>,
    principal: PrincipalId,
    expected_owner: StateOwner,
}

impl WorkspaceProbe {
    pub(super) async fn check(&self) -> ReadyStatus {
        let Ok(binding) = self.service.bind(&self.principal).await else {
            return ReadyStatus::Crashed;
        };
        if binding.owner != self.expected_owner {
            return ReadyStatus::Crashed;
        }
        let path = FilesystemPath::new("initialized-during-readiness").unwrap();
        if self
            .service
            .filesystem(binding)
            .write(&path, b"initial snapshot")
            .is_err()
        {
            return ReadyStatus::Crashed;
        }
        ReadyStatus::Ready
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn derived_readiness_binds_to_assigned_fleet_and_rebinds_identically() {
    let (_dir, kernel) = fixture().await;
    let caller = separate_fleet_caller(&kernel).await;
    let caller_uid = kernel.principal_directory.uid_for(&caller).unwrap();
    let graph = kernel.ownership_store.load().await.unwrap();
    let expected_owner = StateOwner::Fleet(graph.principal_owner(caller_uid).unwrap().fleet_uid);
    let principal = PrincipalId::new("workspace-worker").unwrap();
    seed_capsule(&kernel, &PrincipalId::default(), "harness");
    let service = Arc::clone(kernel.workspace_branches.as_ref().unwrap());
    let mut capsule = ReadyCapsule::new("harness");
    capsule.workspace_probe = Some(WorkspaceProbe {
        service: Arc::clone(&service),
        principal: principal.clone(),
        expected_owner,
    });
    kernel
        .capsules
        .write()
        .await
        .register_for(
            Box::new(capsule),
            WasmHash::synthetic("harness", "1.0.0"),
            &principal,
        )
        .unwrap();
    let response = super::super::agent_derive::agent_derive_from_req(
        &kernel,
        &caller,
        AgentDeriveRequest {
            name: principal.to_string(),
            source: PrincipalId::default(),
            load_capsules: vec!["harness".into()],
            allow_capsules: Vec::new(),
            inherit_capsule_state: Vec::new(),
            network_egress: Vec::new(),
        },
    )
    .await;
    assert!(
        matches!(response, AdminResponseBody::Success(_)),
        "{response:?}"
    );
    let initial = service.binding_for(&principal).await.unwrap();
    assert_eq!(initial.owner, expected_owner);
    let recovered = WorkspaceBranchService::new_with_ownership(
        kernel.principal_store.as_ref().unwrap().clone(),
        kernel.principal_directory.clone(),
        Some(Arc::clone(&kernel.ownership_store)),
    );
    let rebound = recovered.bind(&principal).await.unwrap();
    assert_eq!(initial, rebound);
    let path = FilesystemPath::new("initialized-during-readiness").unwrap();
    assert_eq!(
        recovered.filesystem(rebound).read(&path, 0, 16).unwrap(),
        b"initial snapshot"
    );
    let uid = kernel.principal_directory.uid_for(&principal).unwrap();
    let prefix = ContentName::new(WorkspaceBranchService::ATTACHMENT_PREFIX).unwrap();
    let branches = astrid_storage::WorkspaceBranchStore::new(
        kernel.principal_store.as_ref().unwrap().content(),
    );
    assert!(
        branches
            .binding_for_uid(&StateOwner::Principal(uid), uid, &prefix)
            .unwrap()
            .is_none()
    );
}
