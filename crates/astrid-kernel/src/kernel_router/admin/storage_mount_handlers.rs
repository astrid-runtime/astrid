//! Authenticated management handlers for native storage mount leases.

use std::sync::Arc;

use astrid_core::PrincipalId;
use astrid_events::kernel_api::{AdminRequestKind, AdminResponseBody};

use crate::kernel_router::AuthorizedRequest;
use crate::storage_mount::{
    MountAdmission, MountOwnerScope, PrincipalBinding, mount_owner_scope_from_check,
};

use super::{resolve_admin_scope, storage_mount_required_capability};

pub(super) async fn dispatch(
    kernel: &Arc<crate::Kernel>,
    caller: &PrincipalId,
    authorization: Option<&AuthorizedRequest>,
    request: AdminRequestKind,
) -> AdminResponseBody {
    let admission = match mount_admission_for(kernel, caller, authorization, &request) {
        Ok(admission) => admission,
        Err(error) => return AdminResponseBody::Error(error),
    };
    match request {
        AdminRequestKind::StorageMountIssue {
            view,
            access,
            provider,
            mountpoint,
        } => match crate::storage_mount::issue_lease(
            kernel,
            &admission,
            view,
            astrid_core::storage_filesystem::StorageFilesystemTargetV1::OwnerRoot,
            access,
            provider,
            mountpoint,
        )
        .await
        {
            Ok(lease) => AdminResponseBody::StorageMountLease(Box::new(lease)),
            Err(error) => AdminResponseBody::Error(error),
        },
        AdminRequestKind::StorageMountStatus { mount_id } => {
            match crate::storage_mount::lease_status(
                kernel,
                admission.alias(),
                admission.owner_scope(),
                mount_id,
            ) {
                Ok(status) => AdminResponseBody::Success(status),
                Err(error) => AdminResponseBody::Error(error),
            }
        },
        AdminRequestKind::StorageMountSync { mount_id } => {
            match crate::storage_mount::sync_lease(
                kernel,
                admission.alias(),
                admission.owner_scope(),
                mount_id,
            )
            .await
            {
                Ok(()) => AdminResponseBody::Success(serde_json::json!({ "mount_id": mount_id })),
                Err(error) => AdminResponseBody::Error(error),
            }
        },
        AdminRequestKind::StorageMountRevoke { mount_id } => {
            match crate::storage_mount::revoke_lease(
                kernel,
                admission.alias(),
                admission.owner_scope(),
                mount_id,
            )
            .await
            {
                Ok(()) => AdminResponseBody::Success(serde_json::json!({ "mount_id": mount_id })),
                Err(error) => AdminResponseBody::Error(error),
            }
        },
        _ => AdminResponseBody::Error("not a storage mount request".to_owned()),
    }
}

fn mount_admission_for(
    kernel: &crate::Kernel,
    caller: &PrincipalId,
    authorization: Option<&AuthorizedRequest>,
    request: &AdminRequestKind,
) -> Result<MountAdmission, String> {
    match authorization {
        Some(authorization) => {
            let uid = authorization.principal_uid.ok_or_else(|| {
                "authorized mount request is missing an immutable caller identity".to_owned()
            })?;
            Ok(MountAdmission::bound(
                PrincipalBinding::bound(authorization.principal.clone(), uid),
                mount_owner_scope_from_check(&authorization.capability_check()),
                Some(storage_mount_required_capability(
                    request,
                    resolve_admin_scope(request, &authorization.principal),
                )),
                authorization.device_scope.clone(),
            ))
        },
        None => MountAdmission::capture(kernel, caller, MountOwnerScope::CallerOnly),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::kernel_router::admin::handlers;
    use crate::kernel_router::authorize_request;
    use crate::storage_mount::{MountOwnerScope, last_authorized_caller_uid, test_mount_admission};
    use astrid_core::groups::BUILTIN_ADMIN;
    use astrid_core::profile::PrincipalProfile;
    use astrid_core::{GroupConfig, PrincipalUid};

    fn denied(response: &AdminResponseBody) -> bool {
        matches!(
            response,
            AdminResponseBody::Error(message)
                if message == "storage mount lease belongs to another principal"
        )
    }

    #[tokio::test]
    async fn read_authority_inspects_but_cannot_manage_another_lease() {
        let temporary = tempfile::tempdir().unwrap();
        let home = astrid_core::dirs::AstridHome::from_path(temporary.path().join(".astrid"));
        let kernel = std::sync::Arc::new(crate::test_kernel_with_home(home).await);
        let owner = PrincipalId::default();
        let lease = crate::storage_mount::issue_lease(
            &kernel,
            &test_mount_admission(&kernel, &owner, MountOwnerScope::CrossOwnerWrite),
            astrid_core::storage_provider::StorageProviderViewV1::Admin,
            astrid_core::storage_filesystem::StorageFilesystemTargetV1::OwnerRoot,
            astrid_core::storage_provider::StorageProviderAccessV1::ReadOnly,
            "read-capability-test".to_owned(),
            temporary.path().join("mount"),
        )
        .await
        .unwrap();

        let reader = PrincipalId::new("reader").unwrap();
        let authorization = AuthorizedRequest {
            principal: reader.clone(),
            principal_uid: Some(PrincipalUid::from_bytes([0x51; 32])),
            profile: std::sync::Arc::new(PrincipalProfile {
                grants: vec!["storage:mount:read".to_owned()],
                ..PrincipalProfile::default()
            }),
            groups: std::sync::Arc::new(GroupConfig::builtin_only()),
            device_scope: None,
        };
        let status = dispatch(
            &kernel,
            &reader,
            Some(&authorization),
            AdminRequestKind::StorageMountStatus {
                mount_id: lease.mount_id,
            },
        )
        .await;
        assert!(matches!(
            status,
            AdminResponseBody::Success(value)
                if value["mount_id"] == serde_json::json!(lease.mount_id)
        ));

        let sync = dispatch(
            &kernel,
            &reader,
            Some(&authorization),
            AdminRequestKind::StorageMountSync {
                mount_id: lease.mount_id,
            },
        )
        .await;
        assert!(denied(&sync));

        let revoke = dispatch(
            &kernel,
            &reader,
            Some(&authorization),
            AdminRequestKind::StorageMountRevoke {
                mount_id: lease.mount_id,
            },
        )
        .await;
        assert!(denied(&revoke));

        let self_revoke = dispatch(
            &kernel,
            &owner,
            None,
            AdminRequestKind::StorageMountRevoke {
                mount_id: lease.mount_id,
            },
        )
        .await;
        assert!(matches!(
            self_revoke,
            AdminResponseBody::Success(value)
                if value["mount_id"] == serde_json::json!(lease.mount_id)
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn authorized_mount_issue_fails_closed_on_identity_replacement() {
        let temporary = tempfile::tempdir().unwrap();
        let home = astrid_core::dirs::AstridHome::from_path(temporary.path().join(".astrid"));
        let kernel = std::sync::Arc::new(crate::test_kernel_with_home(home).await);
        let caller = PrincipalId::new("grant-admin").unwrap();
        let created = handlers::dispatch(
            &kernel,
            &PrincipalId::default(),
            AdminRequestKind::AgentCreate {
                name: caller.to_string(),
                groups: vec![BUILTIN_ADMIN.to_string()],
                grants: Vec::new(),
                inherit_from: None,
                clone_from: None,
                allow_admin_clone: false,
            },
        )
        .await;
        assert!(
            matches!(created, AdminResponseBody::Success(_)),
            "create admin-grouped caller: {created:?}"
        );
        let uid_x = kernel.principal_directory.uid_for(&caller).unwrap();
        let authorization = authorize_request(&kernel, &caller, None, "storage:mount:system:write")
            .expect("authorize mount grant");
        assert_eq!(authorization.principal_uid, Some(uid_x));

        let deleted = handlers::dispatch(
            &kernel,
            &PrincipalId::default(),
            AdminRequestKind::AgentDelete {
                principal: caller.clone(),
            },
        )
        .await;
        assert!(
            matches!(deleted, AdminResponseBody::Success(_)),
            "delete authorized caller: {deleted:?}"
        );
        let recreated = handlers::dispatch(
            &kernel,
            &PrincipalId::default(),
            AdminRequestKind::AgentCreate {
                name: caller.to_string(),
                groups: vec![BUILTIN_ADMIN.to_string()],
                grants: Vec::new(),
                inherit_from: None,
                clone_from: None,
                allow_admin_clone: false,
            },
        )
        .await;
        assert!(
            matches!(recreated, AdminResponseBody::Success(_)),
            "recreate alias as Y: {recreated:?}"
        );
        let uid_y = kernel.principal_directory.uid_for(&caller).unwrap();
        assert_ne!(uid_x, uid_y);

        let mountpoint = temporary.path().join("identity-replacement-mount");
        let issued = handlers::dispatch_authorized(
            &kernel,
            &authorization,
            AdminRequestKind::StorageMountIssue {
                view: astrid_core::storage_provider::StorageProviderViewV1::Admin,
                access: astrid_core::storage_provider::StorageProviderAccessV1::ReadWrite,
                provider: "identity-replacement".to_owned(),
                mountpoint: mountpoint.clone(),
            },
        )
        .await;
        assert!(
            matches!(issued, AdminResponseBody::Error(_)),
            "stale authorized identity must not publish: {issued:?}"
        );
        assert_eq!(last_authorized_caller_uid(&kernel), Some(uid_x));
        assert!(
            kernel.storage_mounts.is_empty(),
            "identity replacement must not leave a map entry"
        );
        assert!(
            !mountpoint.exists()
                || std::fs::read_dir(&mountpoint).is_ok_and(|entries| entries.count() == 0),
            "identity replacement must not leave a callback or mount resource"
        );
    }
}
