//! Authenticated management handlers for native storage mount leases.

use std::sync::Arc;

use astrid_core::PrincipalId;
use astrid_events::kernel_api::{AdminRequestKind, AdminResponseBody};

use crate::kernel_router::AuthorizedRequest;

pub(super) async fn dispatch(
    kernel: &Arc<crate::Kernel>,
    caller: &PrincipalId,
    authorization: Option<&AuthorizedRequest>,
    request: AdminRequestKind,
) -> AdminResponseBody {
    let has_mount_authority = authorization.is_some_and(|authorization| {
        let check = authorization.capability_check();
        check.has("storage:mount")
    });
    let has_read_authority = authorization.is_some_and(|authorization| {
        let check = authorization.capability_check();
        check.has("storage:mount:read")
            || check.has("storage:mount:system:read")
            || check.has("storage:mount:write")
            || check.has("storage:mount:system:write")
    });
    let has_write_authority = authorization.is_some_and(|authorization| {
        let check = authorization.capability_check();
        check.has("storage:mount:write") || check.has("storage:mount:system:write")
    });
    let allow_cross_owner_read = has_mount_authority || has_read_authority;
    let allow_cross_owner_write = has_mount_authority || has_write_authority;
    match request {
        AdminRequestKind::StorageMountIssue {
            view,
            access,
            provider,
            mountpoint,
        } => match crate::storage_mount::issue_lease(
            kernel,
            caller.clone(),
            if access == astrid_core::storage_provider::StorageProviderAccessV1::ReadWrite {
                allow_cross_owner_write
            } else {
                allow_cross_owner_read
            },
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
                caller,
                allow_cross_owner_read,
                mount_id,
            ) {
                Ok(status) => AdminResponseBody::Success(status),
                Err(error) => AdminResponseBody::Error(error),
            }
        },
        AdminRequestKind::StorageMountSync { mount_id } => {
            match crate::storage_mount::sync_lease(
                kernel,
                caller,
                allow_cross_owner_write,
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
                caller,
                allow_cross_owner_write,
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::kernel_router::AuthorizedRequest;
    use astrid_core::{GroupConfig, PrincipalProfile};

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
            owner.clone(),
            true,
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
}
