use super::*;
use crate::kernel_router::admin;
use astrid_core::dirs::AstridHome;
use astrid_core::kernel_api::AdminRequestKind;

#[tokio::test]
async fn empty_secrets_are_rejected_by_both_write_modes() {
    let (_dir, kernel) = fixture().await;
    for conditional in [false, true] {
        let response = env_set(
            &kernel,
            request(
                "token",
                "",
                EnvValueKind::Secret,
                EnvStorageScope::Agent,
                conditional,
            ),
        )
        .await;
        assert!(
            matches!(response, AdminResponseBody::Error(error) if error.contains("must not be empty"))
        );
        assert!(
            !has_effective_value(
                &kernel,
                &PrincipalId::default(),
                "provider",
                "token",
                EnvValueKind::Secret
            )
            .await
            .unwrap()
        );
    }
}

async fn fixture() -> (tempfile::TempDir, Arc<Kernel>) {
    let dir = tempfile::tempdir().unwrap();
    let kernel = crate::test_kernel_with_home(AstridHome::from_path(dir.path())).await;
    admin::test_support::seed_operator(&kernel).await;
    (dir, kernel)
}

fn request(
    key: &str,
    value: &str,
    kind: EnvValueKind,
    scope: EnvStorageScope,
    conditional: bool,
) -> EnvSetRequest {
    EnvSetRequest {
        principal: PrincipalId::default(),
        capsule: "provider".into(),
        key: key.into(),
        value: value.into(),
        kind,
        scope,
        append: false,
        only_if_absent: conditional,
    }
}

fn stored(response: AdminResponseBody) -> bool {
    match response {
        AdminResponseBody::Success(value) => value["stored"].as_bool().unwrap(),
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn defaults_preserve_same_kind_in_both_scopes_but_ignore_wrong_kind() {
    let (_dir, kernel) = fixture().await;
    for scope in [EnvStorageScope::Agent, EnvStorageScope::Shared] {
        for existing_kind in [EnvValueKind::Text, EnvValueKind::Secret] {
            for requested_kind in [EnvValueKind::Text, EnvValueKind::Secret] {
                let key = format!("key-{scope:?}-{existing_kind:?}-{requested_kind:?}");
                assert!(stored(
                    env_set(
                        &kernel,
                        request(&key, "operator", existing_kind, scope, false)
                    )
                    .await
                ));
                assert_eq!(
                    stored(
                        env_set(
                            &kernel,
                            request(
                                &key,
                                "default",
                                requested_kind,
                                EnvStorageScope::Agent,
                                true
                            )
                        )
                        .await
                    ),
                    existing_kind != requested_kind
                );
                let original = env_scope(
                    &kernel,
                    &PrincipalId::default(),
                    "provider",
                    existing_kind,
                    scope,
                )
                .unwrap();
                let value = match existing_kind {
                    EnvValueKind::Text => {
                        astrid_storage::env::get_env(&original, &key).await.unwrap()
                    },
                    EnvValueKind::Secret => astrid_storage::env::get_secret(&original, &key)
                        .await
                        .unwrap(),
                };
                assert_eq!(value.as_deref(), Some("operator"));
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_default_and_explicit_write_always_preserve_operator_value() {
    let (_dir, kernel) = fixture().await;
    for index in 0..16 {
        let key = format!("concurrent-{index}");
        let (default, explicit) = tokio::join!(
            env_set(
                &kernel,
                request(
                    &key,
                    "default",
                    EnvValueKind::Text,
                    EnvStorageScope::Agent,
                    true
                )
            ),
            env_set(
                &kernel,
                request(
                    &key,
                    "operator",
                    EnvValueKind::Text,
                    EnvStorageScope::Agent,
                    false
                )
            ),
        );
        stored(default);
        assert!(stored(explicit));
        let store = env_scope(
            &kernel,
            &PrincipalId::default(),
            "provider",
            EnvValueKind::Text,
            EnvStorageScope::Agent,
        )
        .unwrap();
        assert_eq!(
            astrid_storage::env::get_env(&store, &key)
                .await
                .unwrap()
                .as_deref(),
            Some("operator")
        );
    }
}

#[test]
fn default_write_uses_write_authority_and_redacts_audit_value() {
    let principal = PrincipalId::default();
    let request = AdminRequestKind::EnvSetIfAbsent {
        principal: principal.clone(),
        capsule: "provider".into(),
        key: "token".into(),
        value: "sensitive-test-value".into(),
        kind: EnvValueKind::Secret,
    };
    let scope = admin::resolve_admin_scope(&request, &principal);
    assert_eq!(
        admin::required_capability_for_admin_request(&request, scope),
        "self:env:write"
    );
    let other = PrincipalId::new("other").unwrap();
    let scope = admin::resolve_admin_scope(&request, &other);
    assert_eq!(
        admin::required_capability_for_admin_request(&request, scope),
        "env:write"
    );
    let audit = admin::sanitize_admin_audit_params(&request)
        .unwrap()
        .to_string();
    assert!(!audit.contains("sensitive-test-value"));
    assert!(audit.contains("redacted"));
}
