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
    let allow_cross_owner = authorization.is_some_and(|authorization| {
        let check = authorization.capability_check();
        check.has("storage:mount")
            || check.has("storage:mount:read")
            || check.has("storage:mount:write")
            || check.has("storage:mount:system:read")
            || check.has("storage:mount:system:write")
    });
    match request {
        AdminRequestKind::StorageMountIssue {
            view,
            access,
            provider,
            mountpoint,
        } => match crate::storage_mount::issue_lease(
            kernel,
            caller.clone(),
            allow_cross_owner,
            view,
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
            match crate::storage_mount::lease_status(kernel, caller, allow_cross_owner, mount_id) {
                Ok(status) => AdminResponseBody::Success(status),
                Err(error) => AdminResponseBody::Error(error),
            }
        },
        AdminRequestKind::StorageMountSync { mount_id } => {
            match crate::storage_mount::sync_lease(kernel, caller, allow_cross_owner, mount_id)
                .await
            {
                Ok(()) => AdminResponseBody::Success(serde_json::json!({ "mount_id": mount_id })),
                Err(error) => AdminResponseBody::Error(error),
            }
        },
        AdminRequestKind::StorageMountRevoke { mount_id } => {
            match crate::storage_mount::revoke_lease(kernel, caller, allow_cross_owner, mount_id) {
                Ok(()) => AdminResponseBody::Success(serde_json::json!({ "mount_id": mount_id })),
                Err(error) => AdminResponseBody::Error(error),
            }
        },
        _ => AdminResponseBody::Error("not a storage mount request".to_owned()),
    }
}
