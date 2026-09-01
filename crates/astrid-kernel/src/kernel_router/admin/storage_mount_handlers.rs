//! Authenticated management handlers for native storage mount leases.

use std::sync::Arc;

use astrid_events::kernel_api::{AdminRequestKind, AdminResponseBody};

use crate::kernel_router::AuthorizedRequest;
use crate::storage_mount::{MountGrant, PrincipalBinding, mount_owner_scope_from_check};

use super::{resolve_admin_scope, storage_mount_required_capability};

pub(super) async fn dispatch(
    kernel: &Arc<crate::Kernel>,
    authorization: Option<&AuthorizedRequest>,
    request: AdminRequestKind,
) -> AdminResponseBody {
    let Some(authorization) = authorization else {
        return AdminResponseBody::Error(
            "storage mount request requires an authorized principal identity".to_owned(),
        );
    };
    let grant = match mount_grant_for(authorization, &request) {
        Ok(grant) => grant,
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
            &grant,
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
            match crate::storage_mount::lease_status_from_grant(kernel, &grant, mount_id).await {
                Ok(status) => AdminResponseBody::Success(status),
                Err(error) => AdminResponseBody::Error(error),
            }
        },
        AdminRequestKind::StorageMountSync { mount_id } => {
            match crate::storage_mount::sync_lease_from_grant(kernel, &grant, mount_id).await {
                Ok(()) => AdminResponseBody::Success(serde_json::json!({ "mount_id": mount_id })),
                Err(error) => AdminResponseBody::Error(error),
            }
        },
        AdminRequestKind::StorageMountRevoke { mount_id } => {
            match crate::storage_mount::revoke_from_grant(kernel, &grant, mount_id).await {
                Ok(()) => AdminResponseBody::Success(serde_json::json!({ "mount_id": mount_id })),
                Err(error) => AdminResponseBody::Error(error),
            }
        },
        _ => AdminResponseBody::Error("not a storage mount request".to_owned()),
    }
}

fn mount_grant_for(
    authorization: &AuthorizedRequest,
    request: &AdminRequestKind,
) -> Result<MountGrant, String> {
    let identity = authorization.identity.as_ref().ok_or_else(|| {
        "authorized mount request is missing an immutable caller identity".to_owned()
    })?;
    Ok(MountGrant::bound(
        PrincipalBinding::bound(identity.alias.clone(), identity.uid),
        mount_owner_scope_from_check(&authorization.capability_check()),
        Some(storage_mount_required_capability(
            request,
            resolve_admin_scope(request, &authorization.principal),
        )),
        authorization.device_scope.clone(),
    ))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::kernel_router::admin::handlers;
    use crate::kernel_router::{
        AuthorizedPrincipal, arm_authorize_identity_gate, arm_confirm_policy_identity_gate,
        authorize_request_with_identity,
    };
    use crate::storage_mount::{
        MountOwnerScope, clear_last_authorized_caller_for_test, last_authorized_caller_uid,
        test_mount_admission,
    };
    use astrid_core::groups::BUILTIN_ADMIN;
    use astrid_core::principal::PrincipalId;
    use astrid_events::ipc::{IpcMessage, IpcPayload, Topic};
    use astrid_events::kernel_api::{AdminKernelRequest, AdminRequestKind, AdminResponseBody};

    fn denied(response: &AdminResponseBody) -> bool {
        matches!(
            response,
            AdminResponseBody::Error(message)
                if message == "storage mount lease belongs to another principal"
        )
    }

    async fn create_admin_grouped(kernel: &Arc<crate::Kernel>, name: &str) -> PrincipalId {
        let caller = PrincipalId::new(name).unwrap();
        let created = handlers::dispatch(
            kernel,
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
            "create {name}: {created:?}"
        );
        caller
    }

    async fn delete_principal(kernel: &Arc<crate::Kernel>, principal: &PrincipalId) {
        let deleted = handlers::dispatch(
            kernel,
            &PrincipalId::default(),
            AdminRequestKind::AgentDelete {
                principal: principal.clone(),
            },
        )
        .await;
        assert!(
            matches!(deleted, AdminResponseBody::Success(_)),
            "delete {principal}: {deleted:?}"
        );
    }

    fn authorize_mount(
        kernel: &crate::Kernel,
        caller: &PrincipalId,
        required_cap: &str,
    ) -> crate::kernel_router::AuthorizedRequest {
        let identity = AuthorizedPrincipal::bind(kernel, caller).expect("bind mount identity");
        authorize_request_with_identity(kernel, caller, None, required_cap, Some(identity))
            .expect("authorize mount grant")
    }

    async fn send_admin(
        kernel: &Arc<crate::Kernel>,
        caller: &PrincipalId,
        suffix: &str,
        req: AdminKernelRequest,
    ) -> serde_json::Value {
        let topic = Topic::admin_request(suffix);
        let response_topic = Topic::admin_response(suffix);
        let mut rx = kernel.event_bus.subscribe_topic(response_topic.as_str());
        let payload = serde_json::to_value(&req).expect("serialize admin request");
        let mut msg = IpcMessage::new(topic, IpcPayload::RawJson(payload), kernel.session_id.0);
        msg.principal = Some(caller.to_string());
        let _ = kernel.event_bus.publish(astrid_events::AstridEvent::Ipc {
            metadata: astrid_events::EventMetadata::new("test"),
            message: msg,
        });
        astrid_runtime::time::timeout(std::time::Duration::from_secs(8), async {
            loop {
                let event = rx.recv().await.expect("response event");
                if let astrid_events::AstridEvent::Ipc { message, .. } = &*event
                    && let IpcPayload::RawJson(val) = &message.payload
                {
                    return val.clone();
                }
            }
        })
        .await
        .expect("admin response")
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
        let created = handlers::dispatch(
            &kernel,
            &PrincipalId::default(),
            AdminRequestKind::AgentCreate {
                name: reader.to_string(),
                groups: vec!["agent".to_owned()],
                grants: vec!["storage:mount:read".to_owned()],
                inherit_from: None,
                clone_from: None,
                allow_admin_clone: false,
            },
        )
        .await;
        assert!(
            matches!(created, AdminResponseBody::Success(_)),
            "create reader: {created:?}"
        );
        let authorization = authorize_mount(&kernel, &reader, "storage:mount:read");
        let status = dispatch(
            &kernel,
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
            Some(&authorization),
            AdminRequestKind::StorageMountSync {
                mount_id: lease.mount_id,
            },
        )
        .await;
        assert!(denied(&sync));

        let revoke = dispatch(
            &kernel,
            Some(&authorization),
            AdminRequestKind::StorageMountRevoke {
                mount_id: lease.mount_id,
            },
        )
        .await;
        assert!(denied(&revoke));

        let owner_auth = authorize_mount(&kernel, &owner, "storage:mount:system:write");
        let self_revoke = dispatch(
            &kernel,
            Some(&owner_auth),
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
        let caller = create_admin_grouped(&kernel, "grant-admin").await;
        let uid_x = kernel.principal_directory.uid_for(&caller).unwrap();
        let authorization = authorize_mount(&kernel, &caller, "storage:mount:system:write");
        assert_eq!(authorization.principal_uid(), Some(uid_x));

        delete_principal(&kernel, &caller).await;
        let recreated = create_admin_grouped(&kernel, "grant-admin").await;
        let uid_y = kernel.principal_directory.uid_for(&recreated).unwrap();
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stale_grant_cannot_status_sync_or_revoke_after_identity_replacement() {
        let temporary = tempfile::tempdir().unwrap();
        let home = astrid_core::dirs::AstridHome::from_path(temporary.path().join(".astrid"));
        let kernel = std::sync::Arc::new(crate::test_kernel_with_home(home).await);
        let owner = PrincipalId::default();
        let lease = crate::storage_mount::issue_lease(
            &kernel,
            &test_mount_admission(&kernel, &owner, MountOwnerScope::CrossOwnerWrite),
            astrid_core::storage_provider::StorageProviderViewV1::Admin,
            astrid_core::storage_filesystem::StorageFilesystemTargetV1::OwnerRoot,
            astrid_core::storage_provider::StorageProviderAccessV1::ReadWrite,
            "stale-grant-manage".to_owned(),
            temporary.path().join("stale-grant-mount"),
        )
        .await
        .unwrap();
        let manager = create_admin_grouped(&kernel, "grant-manager").await;
        let uid_x = kernel.principal_directory.uid_for(&manager).unwrap();
        let authorization = authorize_mount(&kernel, &manager, "storage:mount:system:write");
        let live_status = handlers::dispatch_authorized(
            &kernel,
            &authorization,
            AdminRequestKind::StorageMountStatus {
                mount_id: lease.mount_id,
            },
        )
        .await;
        assert!(
            matches!(
                live_status,
                AdminResponseBody::Success(ref value)
                    if value["mount_id"] == serde_json::json!(lease.mount_id)
            ),
            "live cross-owner grant must inspect: {live_status:?}"
        );

        delete_principal(&kernel, &manager).await;
        let recycled = create_admin_grouped(&kernel, "grant-manager").await;
        let uid_y = kernel.principal_directory.uid_for(&recycled).unwrap();
        assert_ne!(uid_x, uid_y);

        for request in [
            AdminRequestKind::StorageMountStatus {
                mount_id: lease.mount_id,
            },
            AdminRequestKind::StorageMountSync {
                mount_id: lease.mount_id,
            },
            AdminRequestKind::StorageMountRevoke {
                mount_id: lease.mount_id,
            },
        ] {
            let response = handlers::dispatch_authorized(&kernel, &authorization, request).await;
            assert!(
                matches!(response, AdminResponseBody::Error(_)),
                "stale grant must fail closed: {response:?}"
            );
        }
        assert!(
            kernel.storage_mounts.get(&lease.mount_id).is_some(),
            "stale revoke must not remove the mapped lease"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unauthenticated_dispatch_cannot_bypass_mount_identity() {
        let temporary = tempfile::tempdir().unwrap();
        let home = astrid_core::dirs::AstridHome::from_path(temporary.path().join(".astrid"));
        let kernel = std::sync::Arc::new(crate::test_kernel_with_home(home).await);
        let issued = handlers::dispatch(
            &kernel,
            &PrincipalId::default(),
            AdminRequestKind::StorageMountIssue {
                view: astrid_core::storage_provider::StorageProviderViewV1::Admin,
                access: astrid_core::storage_provider::StorageProviderAccessV1::ReadWrite,
                provider: "bypass".to_owned(),
                mountpoint: temporary.path().join("bypass-mount"),
            },
        )
        .await;
        assert!(
            matches!(issued, AdminResponseBody::Error(ref message) if message.contains("authorized principal identity")),
            "CallerOnly dispatch must not issue: {issued:?}"
        );
        assert!(kernel.storage_mounts.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn production_route_fails_closed_if_identity_changes_during_snapshot() {
        let temporary = tempfile::tempdir().unwrap();
        let home = astrid_core::dirs::AstridHome::from_path(temporary.path().join(".astrid"));
        let kernel = std::sync::Arc::new(crate::test_kernel_with_home(home).await);
        let caller = create_admin_grouped(&kernel, "snapshot-admin").await;
        let uid_x = kernel.principal_directory.uid_for(&caller).unwrap();
        let guard = arm_authorize_identity_gate(&kernel);
        let mountpoint = temporary.path().join("snapshot-mount");
        let request = AdminKernelRequest::with_request_id(
            "snapshot-identity",
            AdminRequestKind::StorageMountIssue {
                view: astrid_core::storage_provider::StorageProviderViewV1::Admin,
                access: astrid_core::storage_provider::StorageProviderAccessV1::ReadWrite,
                provider: "snapshot-identity".to_owned(),
                mountpoint: mountpoint.clone(),
            },
        );
        let send = tokio::spawn({
            let kernel = Arc::clone(&kernel);
            let caller = caller.clone();
            async move { send_admin(&kernel, &caller, "storage.mount.issue", request).await }
        });
        guard.gate().wait_until_entered().await;
        delete_principal(&kernel, &caller).await;
        let recycled = create_admin_grouped(&kernel, "snapshot-admin").await;
        let uid_y = kernel.principal_directory.uid_for(&recycled).unwrap();
        assert_ne!(uid_x, uid_y);
        guard.gate().release();
        let response = send.await.expect("join admin send");
        assert_eq!(response["status"], "Error");
        assert!(
            response["data"]
                .as_str()
                .is_some_and(|error| !error.is_empty()),
            "identity drift during snapshot must fail: {response}"
        );
        assert!(
            kernel.storage_mounts.is_empty(),
            "snapshot drift must not publish a lease"
        );
        assert!(
            !mountpoint.exists()
                || std::fs::read_dir(&mountpoint).is_ok_and(|entries| entries.count() == 0)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn production_route_fails_closed_if_identity_changes_during_policy_confirm() {
        let temporary = tempfile::tempdir().unwrap();
        let home = astrid_core::dirs::AstridHome::from_path(temporary.path().join(".astrid"));
        let kernel = std::sync::Arc::new(crate::test_kernel_with_home(home).await);
        clear_last_authorized_caller_for_test(&kernel);
        let caller = create_admin_grouped(&kernel, "policy-confirm-admin").await;
        let uid_x = kernel.principal_directory.uid_for(&caller).unwrap();
        let guard = arm_confirm_policy_identity_gate(&kernel);
        let mountpoint = temporary.path().join("policy-confirm-mount");
        let request = AdminKernelRequest::with_request_id(
            "policy-confirm-identity",
            AdminRequestKind::StorageMountIssue {
                view: astrid_core::storage_provider::StorageProviderViewV1::Admin,
                access: astrid_core::storage_provider::StorageProviderAccessV1::ReadWrite,
                provider: "policy-confirm-identity".to_owned(),
                mountpoint: mountpoint.clone(),
            },
        );
        let send = tokio::spawn({
            let kernel = Arc::clone(&kernel);
            let caller = caller.clone();
            async move { send_admin(&kernel, &caller, "storage.mount.issue", request).await }
        });
        guard.gate().wait_until_entered().await;
        delete_principal(&kernel, &caller).await;
        let recycled = create_admin_grouped(&kernel, "policy-confirm-admin").await;
        let uid_y = kernel.principal_directory.uid_for(&recycled).unwrap();
        assert_ne!(uid_x, uid_y);
        guard.gate().release();
        let response = send.await.expect("join admin send");
        assert_eq!(response["status"], "Error");
        assert!(
            response["data"]
                .as_str()
                .is_some_and(|error| !error.is_empty()),
            "identity drift during policy confirmation must fail: {response}"
        );
        assert!(
            kernel.storage_mounts.is_empty(),
            "policy-confirm drift must not publish a lease"
        );
        assert_eq!(
            last_authorized_caller_uid(&kernel),
            None,
            "policy denial must occur before issue_lease admission"
        );
        assert!(
            !mountpoint.exists()
                || std::fs::read_dir(&mountpoint).is_ok_and(|entries| entries.count() == 0),
            "policy-confirm drift must not leave a callback or mount resource"
        );
    }

    #[test]
    fn mount_variants_require_principal_identity() {
        let issue = AdminRequestKind::StorageMountIssue {
            view: astrid_core::storage_provider::StorageProviderViewV1::Admin,
            access: astrid_core::storage_provider::StorageProviderAccessV1::ReadOnly,
            provider: "x".to_owned(),
            mountpoint: std::env::temp_dir().join("astrid-mount-variant"),
        };
        assert!(issue.requires_principal_identity());
        assert!(
            AdminRequestKind::StorageMountStatus {
                mount_id: astrid_core::storage_provider::StorageMountId::new(),
            }
            .requires_principal_identity()
        );
        assert!(
            AdminRequestKind::StorageMountSync {
                mount_id: astrid_core::storage_provider::StorageMountId::new(),
            }
            .requires_principal_identity()
        );
        assert!(
            AdminRequestKind::StorageMountRevoke {
                mount_id: astrid_core::storage_provider::StorageMountId::new(),
            }
            .requires_principal_identity()
        );
        assert!(!AdminRequestKind::AgentList.requires_principal_identity());
    }
}
