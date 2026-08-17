//! Principal deletion state-reclamation regression tests (#1217).

use std::path::PathBuf;
use std::sync::Arc;

use astrid_core::dirs::AstridHome;
use astrid_core::groups::{BUILTIN_ADMIN, BUILTIN_AGENT};
use astrid_core::principal::PrincipalId;
use astrid_core::profile::PrincipalProfile;
use astrid_core::{Permission, types::Timestamp};
use astrid_crypto::KeyPair;
use astrid_events::kernel_api::{AdminRequestKind, AdminResponseBody};

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
