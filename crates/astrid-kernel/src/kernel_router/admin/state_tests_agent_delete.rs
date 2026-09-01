//! Principal deletion state-reclamation regression tests (#1217).

use std::path::PathBuf;
use std::sync::Arc;

use astrid_core::dirs::AstridHome;
use astrid_core::groups::{BUILTIN_ADMIN, BUILTIN_AGENT};
use astrid_core::principal::PrincipalId;
use astrid_core::profile::PrincipalProfile;
use astrid_core::storage_filesystem::{
    STORAGE_FILESYSTEM_PROTOCOL_V1, StorageFilesystemEntryKindV1, StorageFilesystemOperationV1,
    StorageFilesystemOutcomeV1, StorageFilesystemRequestV1, StorageFilesystemResponseV1,
    StorageFilesystemSuccessV1, StorageFilesystemTargetV1, StorageMountLeaseV1,
};
use astrid_core::storage_provider::{StorageProviderAccessV1, StorageProviderViewV1};
use astrid_core::{
    FleetGenesis, FleetIdentity, Permission, PrincipalOwnership, PrincipalUid, UserGenesis,
    UserIdentity, UserUid, types::Timestamp,
};
use astrid_crypto::KeyPair;
use astrid_events::kernel_api::{AdminRequestKind, AdminResponseBody};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

#[cfg(any(unix, windows))]
mod latched_panic;

#[cfg(any(unix, windows))]
use crate::storage_mount::{
    MountAdmission, MountCleanupStage, MountOwnerScope, arm_issue_admission_gate,
    clear_cleanup_fault_for_test, expire_lease_for_test, inject_cleanup_fault_for_test,
    issue_lease, last_authorized_caller_uid, test_mount_admission,
};

use super::handlers;
use crate::Kernel;

async fn fixture() -> (tempfile::TempDir, Arc<Kernel>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let kernel = crate::test_kernel_with_home(AstridHome::from_path(dir.path())).await;
    let admin = PrincipalProfile {
        groups: vec![BUILTIN_ADMIN.to_string()],
        ..Default::default()
    };
    admin
        .save_to_path(&PrincipalProfile::path_for(
            &kernel.astrid_home,
            &PrincipalId::default(),
        ))
        .expect("seed default admin profile");
    kernel.profile_cache.invalidate(&PrincipalId::default());
    (dir, kernel)
}

fn seed_footprint(kernel: &Kernel, principal: &PrincipalId) -> (PathBuf, PathBuf, PathBuf) {
    let home = kernel
        .astrid_home
        .principal_home(principal)
        .root()
        .to_path_buf();
    let key = kernel
        .astrid_home
        .keys_dir()
        .join(format!("{principal}.key"));
    let secrets = kernel.astrid_home.secrets_dir().join(principal.as_str());
    std::fs::create_dir_all(key.parent().unwrap()).unwrap();
    std::fs::write(&key, b"signing-key").unwrap();
    std::fs::create_dir_all(&secrets).unwrap();
    std::fs::write(secrets.join("api_key"), b"secret").unwrap();
    (home, key, secrets)
}

async fn create(kernel: &Arc<Kernel>, principal: &PrincipalId) {
    let response = handlers::dispatch(
        kernel,
        &PrincipalId::default(),
        AdminRequestKind::AgentCreate {
            name: principal.to_string(),
            groups: vec![BUILTIN_AGENT.to_string()],
            grants: Vec::new(),
            inherit_from: None,
            clone_from: None,
            allow_admin_clone: false,
        },
    )
    .await;
    assert!(matches!(response, AdminResponseBody::Success(_)));
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_delete_reclaims_home_key_and_secrets_and_reports_them() {
    let (_dir, kernel) = fixture().await;
    assert!(
        kernel.principal_store.is_some(),
        "deletion regressions must exercise the native production store"
    );
    let principal = PrincipalId::new("ghost").unwrap();
    create(&kernel, &principal).await;
    let (home, key, secrets) = seed_footprint(&kernel, &principal);
    kernel
        .kv
        .set("ghost:capsule:session", "history", b"private".to_vec())
        .await
        .unwrap();

    let response = handlers::dispatch(
        &kernel,
        &PrincipalId::default(),
        AdminRequestKind::AgentDelete {
            principal: principal.clone(),
        },
    )
    .await;

    assert!(!home.exists() && !key.exists() && !secrets.exists());
    assert!(
        kernel
            .kv
            .get("ghost:capsule:session", "history")
            .await
            .is_err(),
        "the deleted durable identity must no longer resolve a KV namespace"
    );
    let AdminResponseBody::Success(value) = response else {
        panic!("expected Success response");
    };
    assert_eq!(
        value["reclaimed"],
        serde_json::json!(["kv", "home", "keys", "secrets"])
    );
    assert_eq!(value["unloaded_capsules"], serde_json::json!([]));
    assert_eq!(value["cleanup_errors"], serde_json::json!([]));
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_delete_closes_authz_before_reclaiming() {
    let (_dir, kernel) = fixture().await;
    let principal = PrincipalId::new("active").unwrap();
    create(&kernel, &principal).await;
    let (home, key, secrets) = seed_footprint(&kernel, &principal);
    assert_eq!(
        kernel.profile_cache.resolve(&principal).unwrap().groups,
        vec![BUILTIN_AGENT.to_string()]
    );

    let response = handlers::dispatch(
        &kernel,
        &PrincipalId::default(),
        AdminRequestKind::AgentDelete {
            principal: principal.clone(),
        },
    )
    .await;
    assert!(matches!(response, AdminResponseBody::Success(_)));

    assert!(kernel.profile_cache.resolve(&principal).is_err());
    assert!(!home.exists() && !key.exists() && !secrets.exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_delete_rejects_reappeared_legacy_secret_after_completed_ledger() {
    let (_dir, kernel) = fixture().await;
    let principal = PrincipalId::new("reappeared-secret").unwrap();
    create(&kernel, &principal).await;
    let principal_uid = kernel
        .principal_directory
        .uid_for(&principal)
        .expect("principal UID");
    crate::legacy_migration_barrier::record_absent_legacy_secret_for_test(
        &kernel.astrid_home,
        principal_uid,
    )
    .expect("absent legacy-secret ledger component");

    // The completion ledger records that this participating alias had no
    // legacy secret source. Recreating one after cut-over models a stale
    // operator copy before deletion, not ordinary post-cutover state.
    let secret_root = kernel.astrid_home.secrets_dir();
    astrid_core::platform_fs::ensure_private_directory(&secret_root).expect("legacy secrets root");
    let reappeared = secret_root.join(principal.as_str());
    astrid_core::platform_fs::ensure_private_directory(&reappeared)
        .expect("reappeared legacy secret scope");
    let secret = reappeared.join("api_key");
    std::fs::write(&secret, b"must-survive").expect("reappeared secret");

    let retried = handlers::dispatch(
        &kernel,
        &PrincipalId::default(),
        AdminRequestKind::AgentDelete {
            principal: principal.clone(),
        },
    )
    .await;

    assert!(
        matches!(retried, AdminResponseBody::Error(_)),
        "agent.delete must fail closed when a completed-ledger secret source reappears"
    );
    assert!(
        kernel
            .identity_store
            .resolve("cli", principal.as_str())
            .await
            .expect("identity lookup")
            .is_some(),
        "a blocked deletion must not unlink the principal identity"
    );
    assert!(
        PrincipalProfile::path_for(&kernel.astrid_home, &principal).exists(),
        "a blocked deletion must preserve the principal profile"
    );
    assert!(
        secret.exists(),
        "reappeared legacy secret must be preserved"
    );
    assert!(
        reappeared.is_dir(),
        "reappeared legacy scope must be preserved"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_delete_purges_every_token_and_allowance_scope() {
    use astrid_approval::{Allowance, AllowanceId, AllowancePattern};
    use astrid_capabilities::{AuditEntryId, CapabilityToken, ResourcePattern, TokenScope};

    let (_dir, kernel) = fixture().await;
    let principal = PrincipalId::new("authority").unwrap();
    create(&kernel, &principal).await;
    let keypair = KeyPair::generate();
    let make_token = |scope| {
        CapabilityToken::create(
            ResourcePattern::exact("mcp://danger:run").unwrap(),
            vec![Permission::Invoke],
            scope,
            keypair.key_id(),
            AuditEntryId::new(),
            &keypair,
            None,
            principal.clone(),
        )
    };
    let session = make_token(TokenScope::Session);
    let persistent = make_token(TokenScope::Persistent);
    let persistent_id = persistent.id.clone();
    kernel.capabilities.add(session).await.unwrap();
    kernel.capabilities.add(persistent).await.unwrap();
    for session_only in [true, false] {
        kernel
            .allowance_store
            .add_allowance(Allowance {
                id: AllowanceId::new(),
                principal: principal.clone(),
                action_pattern: AllowancePattern::ServerTools {
                    server: format!("danger-{session_only}"),
                },
                created_at: Timestamp::now(),
                expires_at: None,
                max_uses: None,
                uses_remaining: None,
                session_only,
                workspace_root: None,
                signature: keypair.sign(b"allowance"),
            })
            .unwrap();
    }

    let response = handlers::dispatch(
        &kernel,
        &PrincipalId::default(),
        AdminRequestKind::AgentDelete {
            principal: principal.clone(),
        },
    )
    .await;

    assert!(matches!(response, AdminResponseBody::Success(_)));
    assert_eq!(kernel.allowance_store.count_for(&principal), 0);
    assert!(
        kernel
            .capabilities
            .get(&persistent_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        !kernel
            .capabilities
            .has_capability(&principal, "mcp://danger:run", Permission::Invoke)
            .await
    );
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn failed_reclamation_keeps_alias_reserved_until_retry_succeeds() {
    use std::os::unix::fs::PermissionsExt as _;

    let (_dir, kernel) = fixture().await;
    let principal = PrincipalId::new("retry-delete").unwrap();
    create(&kernel, &principal).await;
    // Exercise a failed native-control cleanup without creating a legacy
    // principal home. The key directory is system-owned and is still
    // retired by deletion; denying its parent keeps the alias reserved until
    // the retry, while the migration barrier remains satisfied.
    let homes = kernel.astrid_home.keys_dir().clone();
    let original_mode = std::fs::metadata(&homes).unwrap().permissions().mode();
    std::fs::set_permissions(&homes, std::fs::Permissions::from_mode(0o500)).unwrap();

    let failed = handlers::dispatch(
        &kernel,
        &PrincipalId::default(),
        AdminRequestKind::AgentDelete {
            principal: principal.clone(),
        },
    )
    .await;
    assert!(matches!(failed, AdminResponseBody::Error(_)));
    let recreate = handlers::dispatch(
        &kernel,
        &PrincipalId::default(),
        AdminRequestKind::AgentCreate {
            name: principal.to_string(),
            groups: vec![BUILTIN_AGENT.to_string()],
            grants: Vec::new(),
            inherit_from: None,
            clone_from: None,
            allow_admin_clone: false,
        },
    )
    .await;
    assert!(matches!(recreate, AdminResponseBody::Error(_)));

    std::fs::set_permissions(&homes, std::fs::Permissions::from_mode(original_mode)).unwrap();
    let retried = handlers::dispatch(
        &kernel,
        &PrincipalId::default(),
        AdminRequestKind::AgentDelete {
            principal: principal.clone(),
        },
    )
    .await;
    assert!(matches!(retried, AdminResponseBody::Success(_)));
}

#[cfg(any(unix, windows))]
async fn mount_callback(
    lease: &StorageMountLeaseV1,
    operation: StorageFilesystemOperationV1,
) -> StorageFilesystemOutcomeV1 {
    let mut stream = astrid_core::local_transport::connect(&lease.callback_path)
        .await
        .expect("mount callback connect");
    let request = StorageFilesystemRequestV1 {
        protocol_version: STORAGE_FILESYSTEM_PROTOCOL_V1,
        request_id: "agent-delete-mount".to_owned(),
        lease_token: lease.lease_token.clone(),
        operation,
    };
    let bytes = serde_json::to_vec(&request).unwrap();
    stream
        .write_all(&u32::try_from(bytes.len()).unwrap().to_be_bytes())
        .await
        .unwrap();
    stream.write_all(&bytes).await.unwrap();
    let mut response_length = [0_u8; 4];
    stream.read_exact(&mut response_length).await.unwrap();
    let mut response = vec![0_u8; u32::from_be_bytes(response_length) as usize];
    stream.read_exact(&mut response).await.unwrap();
    let response: StorageFilesystemResponseV1 = serde_json::from_slice(&response).unwrap();
    response.outcome
}

#[cfg(any(unix, windows))]
fn create_file(path: &str) -> StorageFilesystemOperationV1 {
    StorageFilesystemOperationV1::Create {
        path: path.to_owned(),
        kind: StorageFilesystemEntryKindV1::File,
    }
}

#[cfg(any(unix, windows))]
async fn issue_principal_mount(
    kernel: &std::sync::Arc<Kernel>,
    principal: &PrincipalId,
    mountpoint: std::path::PathBuf,
) -> Result<StorageMountLeaseV1, String> {
    let admission = MountAdmission::capture(kernel, principal, MountOwnerScope::CallerOnly)?;
    issue_lease(
        kernel,
        &admission,
        StorageProviderViewV1::Principal(principal.clone()),
        StorageFilesystemTargetV1::OwnerRoot,
        StorageProviderAccessV1::ReadWrite,
        "test-provider".to_owned(),
        mountpoint,
    )
    .await
}

#[cfg(any(unix, windows))]
async fn delete_principal(kernel: &std::sync::Arc<Kernel>, principal: &PrincipalId) {
    let response = handlers::dispatch(
        kernel,
        &PrincipalId::default(),
        AdminRequestKind::AgentDelete {
            principal: principal.clone(),
        },
    )
    .await;
    assert!(
        matches!(response, AdminResponseBody::Success(_)),
        "agent delete failed: {response:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg(any(unix, windows))]
async fn issue_lease_fails_closed_once_principal_retirement_begins() {
    let (dir, kernel) = fixture().await;
    let principal = PrincipalId::new("retiring-mount").unwrap();
    create(&kernel, &principal).await;
    kernel
        .capabilities
        .begin_principal_retirement(principal.clone())
        .await;

    let viewed = issue_principal_mount(&kernel, &principal, dir.path().join("retiring-self-mount"))
        .await
        .expect_err("self-issued lease must fail after retirement begins");
    assert!(
        viewed.contains("retiring"),
        "expected retirement fail-closed, got {viewed}"
    );

    let cross = issue_lease(
        &kernel,
        &test_mount_admission(
            &kernel,
            &PrincipalId::default(),
            MountOwnerScope::CrossOwnerWrite,
        ),
        StorageProviderViewV1::Principal(principal.clone()),
        StorageFilesystemTargetV1::OwnerRoot,
        StorageProviderAccessV1::ReadWrite,
        "test-provider".to_owned(),
        dir.path().join("retiring-view-mount"),
    )
    .await
    .expect_err("viewed-principal lease must fail after retirement begins");
    assert!(
        cross.contains("retiring"),
        "expected viewed-principal retirement fail-closed, got {cross}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg(any(unix, windows))]
async fn agent_delete_drains_live_mount_and_refuses_resurrection() {
    let (dir, kernel) = fixture().await;
    let principal = PrincipalId::new("mount-live").unwrap();
    create(&kernel, &principal).await;
    let lease = issue_principal_mount(&kernel, &principal, dir.path().join("live-mount"))
        .await
        .expect("issue live mount");
    assert_eq!(
        mount_callback(&lease, create_file("keep.txt")).await,
        StorageFilesystemOutcomeV1::Success(StorageFilesystemSuccessV1::Done)
    );

    delete_principal(&kernel, &principal).await;

    assert!(
        kernel.storage_mounts.get(&lease.mount_id).is_none(),
        "live mount must not survive agent_delete"
    );
    assert!(!astrid_core::local_transport::endpoint_is_present(&lease.callback_path).unwrap());
    assert!(!lease.resource_path.exists());
    assert!(
        astrid_core::local_transport::connect(&lease.callback_path)
            .await
            .is_err()
    );
    assert!(
        issue_principal_mount(&kernel, &principal, dir.path().join("resurrect-mount"))
            .await
            .is_err(),
        "deleted principal must not resurrect a mount lease"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg(any(unix, windows))]
async fn agent_delete_drains_expired_mount_still_mapped() {
    let (dir, kernel) = fixture().await;
    let principal = PrincipalId::new("mount-stale").unwrap();
    create(&kernel, &principal).await;
    let lease = issue_principal_mount(&kernel, &principal, dir.path().join("stale-mount"))
        .await
        .expect("issue stale mount");
    let state = std::sync::Arc::clone(
        kernel
            .storage_mounts
            .get(&lease.mount_id)
            .expect("mapped lease")
            .value(),
    );
    expire_lease_for_test(&state);
    assert!(kernel.storage_mounts.contains_key(&lease.mount_id));

    delete_principal(&kernel, &principal).await;

    assert!(
        kernel.storage_mounts.get(&lease.mount_id).is_none(),
        "expired mapped mount must not survive agent_delete"
    );
    assert!(!astrid_core::local_transport::endpoint_is_present(&lease.callback_path).unwrap());
    assert!(
        astrid_core::local_transport::connect(&lease.callback_path)
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg(any(unix, windows))]
async fn paused_issue_after_owner_resolve_cannot_publish_after_caller_drain() {
    let (dir, kernel) = fixture().await;
    let principal = PrincipalId::new("paused-self").unwrap();
    create(&kernel, &principal).await;
    let gate = arm_issue_admission_gate(&kernel);
    let issue_kernel = Arc::clone(&kernel);
    let issue_principal = principal.clone();
    let mountpoint = dir.path().join("paused-self-mount");
    let issue = tokio::spawn(async move {
        issue_principal_mount(&issue_kernel, &issue_principal, mountpoint).await
    });
    gate.gate().wait_until_entered().await;
    let deleted = handlers::dispatch(
        &kernel,
        &PrincipalId::default(),
        AdminRequestKind::AgentDelete {
            principal: principal.clone(),
        },
    )
    .await;
    gate.gate().release();
    let issued = issue.await.expect("paused issue task");
    assert!(
        matches!(deleted, AdminResponseBody::Success(_)),
        "caller drain must complete while admission is paused: {deleted:?}"
    );
    let error = issued.expect_err("paused issue must not publish after caller drain");
    assert!(
        error.contains("retiring"),
        "expected retirement fail-closed, got {error}"
    );
    assert!(
        kernel.storage_mounts.is_empty(),
        "paused admission must not leave a map entry after drain"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg(any(unix, windows))]
async fn paused_issue_after_owner_resolve_cannot_publish_after_viewed_principal_drain() {
    let (dir, kernel) = fixture().await;
    let principal = PrincipalId::new("paused-view").unwrap();
    create(&kernel, &principal).await;
    let gate = arm_issue_admission_gate(&kernel);
    let issue_kernel = Arc::clone(&kernel);
    let viewed = principal.clone();
    let mountpoint = dir.path().join("paused-view-mount");
    let issue = tokio::spawn(async move {
        issue_lease(
            &issue_kernel,
            &test_mount_admission(
                &issue_kernel,
                &PrincipalId::default(),
                MountOwnerScope::CrossOwnerWrite,
            ),
            StorageProviderViewV1::Principal(viewed),
            StorageFilesystemTargetV1::OwnerRoot,
            StorageProviderAccessV1::ReadWrite,
            "test-provider".to_owned(),
            mountpoint,
        )
        .await
    });
    gate.gate().wait_until_entered().await;
    let deleted = handlers::dispatch(
        &kernel,
        &PrincipalId::default(),
        AdminRequestKind::AgentDelete {
            principal: principal.clone(),
        },
    )
    .await;
    gate.gate().release();
    let issued = issue.await.expect("paused cross-owner issue task");
    assert!(
        matches!(deleted, AdminResponseBody::Success(_)),
        "viewed-principal drain must complete while admission is paused: {deleted:?}"
    );
    let error = issued.expect_err("paused issue must not publish after viewed drain");
    assert!(
        error.contains("retiring"),
        "expected viewed-principal retirement fail-closed, got {error}"
    );
    assert!(
        kernel.storage_mounts.is_empty(),
        "paused cross-owner admission must not leave a map entry after drain"
    );
}

#[cfg(any(unix, windows))]
fn assert_cleanup_fault_retained(
    lease: &StorageMountLeaseV1,
    label: &str,
    fault: MountCleanupStage,
) {
    match fault {
        MountCleanupStage::Callback => {
            assert!(
                astrid_core::local_transport::endpoint_is_present(&lease.callback_path)
                    .expect("callback endpoint state")
                    == cfg!(unix),
                "{label}: callback cleanup fault must leave the endpoint where the backend supports a retained endpoint"
            );
        },
        // Principal deletion retries drain timeouts only after the retained
        // lifecycle worker acknowledges completion; it is not a resource fault.
        MountCleanupStage::Drain => unreachable!("delete fixtures never inject drain"),
        MountCleanupStage::Manifest => {
            assert!(
                lease.resource_path.join("lease.json").exists(),
                "{label}: manifest cleanup fault must leave the manifest"
            );
        },
        MountCleanupStage::Directory => {
            assert!(
                !astrid_core::local_transport::endpoint_is_present(&lease.callback_path)
                    .expect("callback endpoint state"),
                "{label}: directory cleanup fault must follow callback removal"
            );
            assert!(
                lease.resource_path.exists(),
                "{label}: directory cleanup fault must leave the resource directory"
            );
        },
    }
}

async fn delete_fails_closed_on_cleanup_fault_then_retries(
    kernel: &Arc<Kernel>,
    mountpoint: PathBuf,
    label: &str,
    fault: MountCleanupStage,
) {
    let principal = PrincipalId::new(label).unwrap();
    create(kernel, &principal).await;
    let lease = issue_principal_mount(kernel, &principal, mountpoint)
        .await
        .expect("issue mount for cleanup fault");
    let state = Arc::clone(
        kernel
            .storage_mounts
            .get(&lease.mount_id)
            .expect("mapped lease")
            .value(),
    );
    inject_cleanup_fault_for_test(&state, fault);
    let failed = handlers::dispatch(
        kernel,
        &PrincipalId::default(),
        AdminRequestKind::AgentDelete {
            principal: principal.clone(),
        },
    )
    .await;
    assert!(
        matches!(failed, AdminResponseBody::Error(_)),
        "{label}: agent.delete must fail closed on mount cleanup: {failed:?}"
    );
    assert!(
        kernel
            .identity_store
            .resolve("cli", principal.as_str())
            .await
            .expect("identity lookup")
            .is_some(),
        "{label}: failed drain must not unlink identity"
    );
    assert!(
        PrincipalProfile::path_for(&kernel.astrid_home, &principal).exists(),
        "{label}: failed drain must preserve the principal profile"
    );
    {
        let mapped = kernel
            .storage_mounts
            .get(&lease.mount_id)
            .unwrap_or_else(|| {
                panic!("{label}: failed cleanup must keep the revoked lease mapped")
            });
        assert!(
            mapped.value().is_revoked_for_test(),
            "{label}: leftover map entry must be revoked"
        );
    }
    assert_cleanup_fault_retained(&lease, label, fault);
    clear_cleanup_fault_for_test(&state);
    let retried = handlers::dispatch(
        kernel,
        &PrincipalId::default(),
        AdminRequestKind::AgentDelete {
            principal: principal.clone(),
        },
    )
    .await;
    assert!(
        matches!(retried, AdminResponseBody::Success(_)),
        "{label}: retry after clearing cleanup fault must succeed: {retried:?}"
    );
    assert!(
        kernel
            .identity_store
            .resolve("cli", principal.as_str())
            .await
            .expect("identity lookup")
            .is_none(),
        "{label}: successful retry must unlink identity"
    );
    assert!(
        kernel.storage_mounts.get(&lease.mount_id).is_none(),
        "{label}: successful retry must remove the map entry"
    );
    assert!(!astrid_core::local_transport::endpoint_is_present(&lease.callback_path).unwrap());
    assert!(!lease.resource_path.exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg(any(unix, windows))]
async fn agent_delete_preserves_identity_when_mount_cleanup_fails_then_retries() {
    let (dir, kernel) = fixture().await;
    for (label, fault) in [
        ("cleanup-callback", MountCleanupStage::Callback),
        ("cleanup-manifest", MountCleanupStage::Manifest),
        ("cleanup-directory", MountCleanupStage::Directory),
    ] {
        delete_fails_closed_on_cleanup_fault_then_retries(
            &kernel,
            dir.path().join(format!("{label}-mount")),
            label,
            fault,
        )
        .await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg(any(unix, windows))]
async fn paused_issue_after_owner_resolve_cannot_publish_after_admin_caller_drain() {
    let (dir, kernel) = fixture().await;
    let principal = PrincipalId::new("paused-admin").unwrap();
    create_with_groups(&kernel, &principal, vec![BUILTIN_ADMIN.to_string()]).await;
    let gate = arm_issue_admission_gate(&kernel);
    let issue_kernel = Arc::clone(&kernel);
    let issue_principal = principal.clone();
    let mountpoint = dir.path().join("paused-admin-mount");
    let issue = tokio::spawn(async move {
        issue_lease(
            &issue_kernel,
            &test_mount_admission(
                &issue_kernel,
                &issue_principal,
                MountOwnerScope::CrossOwnerWrite,
            ),
            StorageProviderViewV1::Admin,
            StorageFilesystemTargetV1::OwnerRoot,
            StorageProviderAccessV1::ReadWrite,
            "test-provider".to_owned(),
            mountpoint,
        )
        .await
    });
    gate.gate().wait_until_entered().await;
    let deleted = handlers::dispatch(
        &kernel,
        &PrincipalId::default(),
        AdminRequestKind::AgentDelete {
            principal: principal.clone(),
        },
    )
    .await;
    gate.gate().release();
    let issued = issue.await.expect("paused admin issue task");
    assert!(
        matches!(deleted, AdminResponseBody::Success(_)),
        "admin drain must complete while admission is paused: {deleted:?}"
    );
    let error = issued.expect_err("paused admin issue must not publish after drain");
    assert!(
        error.contains("retiring"),
        "expected retirement fail-closed, got {error}"
    );
    assert!(
        kernel.storage_mounts.is_empty(),
        "paused admin admission must not leave a map entry after drain"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg(any(unix, windows))]
async fn paused_issue_after_owner_resolve_cannot_publish_after_self_fleet_alias_recycle() {
    let (dir, kernel) = fixture().await;
    let manager = PrincipalId::new("fleet-manager").unwrap();
    create(&kernel, &manager).await;
    let (fleet, assigned_by) = assign_current_uid_to_new_fleet(&kernel, &manager).await;
    let caller = PrincipalId::new("fleet-self").unwrap();
    create(&kernel, &caller).await;
    let uid_x = kernel.principal_directory.uid_for(&caller).unwrap();
    assign_uid_to_fleet(&kernel, uid_x, fleet, assigned_by).await;
    let gate = arm_issue_admission_gate(&kernel);
    let issue_kernel = Arc::clone(&kernel);
    let issue_caller = caller.clone();
    let mountpoint = dir.path().join("paused-fleet-mount");
    let issue = tokio::spawn(async move {
        issue_lease(
            &issue_kernel,
            &test_mount_admission(&issue_kernel, &issue_caller, MountOwnerScope::CallerOnly),
            StorageProviderViewV1::Fleet(fleet),
            StorageFilesystemTargetV1::OwnerRoot,
            StorageProviderAccessV1::ReadWrite,
            "test-provider".to_owned(),
            mountpoint,
        )
        .await
    });
    gate.gate().wait_until_entered().await;
    drop_principal_ownership_for_test(&kernel, uid_x).await;
    delete_principal(&kernel, &caller).await;
    create(&kernel, &caller).await;
    let uid_y = kernel.principal_directory.uid_for(&caller).unwrap();
    assert_ne!(uid_x, uid_y);
    assign_uid_to_fleet(&kernel, uid_y, fleet, assigned_by).await;
    gate.gate().release();
    let issued = issue.await.expect("paused fleet issue task");
    let error = issued.expect_err("paused fleet issue must not publish after alias recycle");
    assert!(
        error.contains("retiring"),
        "expected captured-UID fail-closed, got {error}"
    );
    assert_eq!(last_authorized_caller_uid(&kernel), Some(uid_x));
    assert!(
        kernel.storage_mounts.is_empty(),
        "recycled alias must not receive a Y lease or callback"
    );
}

#[cfg(any(unix, windows))]
async fn create_with_groups(kernel: &Arc<Kernel>, principal: &PrincipalId, groups: Vec<String>) {
    let response = handlers::dispatch(
        kernel,
        &PrincipalId::default(),
        AdminRequestKind::AgentCreate {
            name: principal.to_string(),
            groups,
            grants: Vec::new(),
            inherit_from: None,
            clone_from: None,
            allow_admin_clone: false,
        },
    )
    .await;
    assert!(
        matches!(response, AdminResponseBody::Success(_)),
        "agent create failed: {response:?}"
    );
}

#[cfg(any(unix, windows))]
async fn assign_current_uid_to_new_fleet(
    kernel: &Kernel,
    principal: &PrincipalId,
) -> (astrid_core::FleetUid, UserUid) {
    let user = kernel
        .identity_store
        .resolve("cli", principal.as_str())
        .await
        .unwrap()
        .unwrap();
    let principal_identity = kernel
        .identity_store
        .get_principal_identity(user.id)
        .await
        .unwrap()
        .unwrap();
    let owner = UserIdentity::from_genesis(UserGenesis::from_parts(
        user.id,
        user.created_at,
        principal_identity.genesis.initial_public_key,
    ))
    .unwrap();
    let fleet = FleetIdentity::from_genesis(FleetGenesis::from_parts(
        user.id,
        user.created_at,
        owner.uid,
    ))
    .unwrap();
    kernel
        .ownership_store
        .create_user(owner.clone())
        .await
        .unwrap();
    kernel
        .ownership_store
        .create_fleet(fleet.clone())
        .await
        .unwrap();
    assign_uid_to_fleet(kernel, principal_identity.uid, fleet.uid, owner.uid).await;
    (fleet.uid, owner.uid)
}

#[cfg(any(unix, windows))]
async fn assign_uid_to_fleet(
    kernel: &Kernel,
    principal_uid: PrincipalUid,
    fleet_uid: astrid_core::FleetUid,
    assigned_by: UserUid,
) {
    kernel
        .ownership_store
        .assign_principal(PrincipalOwnership {
            principal_uid,
            fleet_uid,
            assigned_by,
        })
        .await
        .unwrap();
}

#[cfg(any(unix, windows))]
async fn drop_principal_ownership_for_test(kernel: &Kernel, uid: PrincipalUid) {
    const NAMESPACE: &str = "system:ownership";
    const KEY: &str = "graph-v1";
    let current = kernel
        .kv
        .get(NAMESPACE, KEY)
        .await
        .expect("load ownership graph")
        .expect("ownership graph present");
    let mut graph: serde_json::Value = serde_json::from_slice(&current).expect("ownership json");
    let removed = graph
        .get_mut("principal_ownership")
        .and_then(serde_json::Value::as_object_mut)
        .and_then(|map| map.remove(&uid.to_string()));
    assert!(removed.is_some(), "expected fleet assignment for {uid}");
    let encoded = serde_json::to_vec(&graph).expect("encode ownership graph");
    assert!(
        kernel
            .kv
            .compare_and_swap(NAMESPACE, KEY, Some(current.as_slice()), encoded)
            .await
            .expect("cas ownership graph"),
        "ownership graph cas must apply"
    );
    assert!(
        kernel
            .ownership_store()
            .load()
            .await
            .unwrap()
            .principal_owner(uid)
            .is_none()
    );
}
