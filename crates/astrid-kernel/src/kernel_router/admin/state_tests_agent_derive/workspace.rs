//! Capsule readiness must see the same workspace owner as a fresh service.
use super::*;
use astrid_capsule::capsule::ReadyStatus;
use astrid_capsule::context::WorkspaceBranchService;
use astrid_storage::FilesystemPath;

const CONCURRENT_PRINCIPAL: &str = "concurrent-workspace-worker";
const CONCURRENT_CREATED: &str = "concurrent-created-worker";

struct ProfilePublicationBarrier {
    published: tokio::sync::Notify,
    release: tokio::sync::Semaphore,
}

static PUBLICATION: std::sync::OnceLock<ProfilePublicationBarrier> = std::sync::OnceLock::new();
static CREATED_PUBLICATION: std::sync::OnceLock<ProfilePublicationBarrier> =
    std::sync::OnceLock::new();

pub(crate) async fn pause_after_profile_publication(principal: &PrincipalId) {
    let barrier = match principal.as_str() {
        CONCURRENT_PRINCIPAL => PUBLICATION.get(),
        CONCURRENT_CREATED => CREATED_PUBLICATION.get(),
        _ => None,
    };
    if let Some(barrier) = barrier {
        barrier.published.notify_one();
        barrier.release.acquire().await.unwrap().forget();
    }
}

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_profile_loader_cannot_bind_a_derived_principal_before_fleet_assignment() {
    concurrent_profile_loader_binds_assigned_owner(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_profile_loader_cannot_bind_a_created_principal_before_fleet_assignment() {
    concurrent_profile_loader_binds_assigned_owner(false).await;
}

async fn concurrent_profile_loader_binds_assigned_owner(derived: bool) {
    let (_dir, kernel) = fixture().await;
    let caller = if derived {
        separate_fleet_caller(&kernel).await
    } else {
        PrincipalId::default()
    };
    let caller_uid = kernel.principal_directory.uid_for(&caller).unwrap();
    let graph = kernel.ownership_store.load().await.unwrap();
    let expected_owner = StateOwner::Fleet(graph.principal_owner(caller_uid).unwrap().fleet_uid);
    let alias = if derived {
        CONCURRENT_PRINCIPAL
    } else {
        CONCURRENT_CREATED
    };
    let principal = PrincipalId::new(alias).unwrap();
    seed_capsule(&kernel, &PrincipalId::default(), "harness");
    if !derived {
        let path = PrincipalProfile::path_for(&kernel.astrid_home, &PrincipalId::default());
        let mut profile = PrincipalProfile::load_from_path(&path).unwrap();
        profile.capsules = vec!["harness".into()];
        profile.save_to_path(&path).unwrap();
        kernel.profile_cache.invalidate(&PrincipalId::default());
    }
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
    let publication = if derived {
        &PUBLICATION
    } else {
        &CREATED_PUBLICATION
    };
    assert!(
        publication
            .set(ProfilePublicationBarrier {
                published: tokio::sync::Notify::new(),
                release: tokio::sync::Semaphore::new(0),
            })
            .is_ok()
    );
    let barrier = publication.get().unwrap();
    let derive = spawn_concurrent_provision(Arc::clone(&kernel), caller, derived, alias);
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        barrier.published.notified(),
    )
    .await
    .unwrap();
    // This is the same principal load used by reload and background warm.
    // Bind through the same resolver the engine constructor uses, before any
    // later install/inheritance work can conceal an unassigned published UID.
    let load = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        kernel.ensure_principal_loaded(&principal),
    )
    .await;
    let initial = service.bind(&principal).await;
    barrier.release.add_permits(1);
    let response = tokio::time::timeout(std::time::Duration::from_secs(10), derive)
        .await
        .unwrap()
        .unwrap();
    load.unwrap();
    assert!(
        matches!(response, AdminResponseBody::Success(_)),
        "{response:?}"
    );
    let initial = initial.expect("published principal must resolve its workspace owner");
    kernel.ensure_principal_loaded(&principal).await;
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
}

fn spawn_concurrent_provision(
    kernel: Arc<crate::Kernel>,
    caller: PrincipalId,
    derived: bool,
    alias: &'static str,
) -> tokio::task::JoinHandle<AdminResponseBody> {
    tokio::spawn(async move {
        if derived {
            super::super::agent_derive::agent_derive_from_req(
                &kernel,
                &caller,
                AgentDeriveRequest {
                    name: alias.into(),
                    source: PrincipalId::default(),
                    load_capsules: vec!["harness".into()],
                    allow_capsules: Vec::new(),
                    inherit_capsule_state: Vec::new(),
                    network_egress: Vec::new(),
                },
            )
            .await
        } else {
            super::super::test_support::dispatch_as_operator(
                &kernel,
                &caller,
                astrid_events::kernel_api::AdminRequestKind::AgentCreate {
                    name: alias.into(),
                    groups: Vec::new(),
                    grants: Vec::new(),
                    inherit_from: None,
                    clone_from: Some(PrincipalId::default()),
                    allow_admin_clone: true,
                },
            )
            .await
        }
    })
}
