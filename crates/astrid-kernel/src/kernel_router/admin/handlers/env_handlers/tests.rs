use super::*;
use crate::kernel_router::admin;
use astrid_core::dirs::AstridHome;
use astrid_core::kernel_api::AdminRequestKind;

#[tokio::test]
async fn failed_refresh_retries_without_overwriting_the_committed_default() {
    let (_dir, kernel) = fixture().await;
    let first = env_set_with_refresh(
        &kernel,
        request(
            "retry",
            "original",
            EnvValueKind::Text,
            EnvStorageScope::Agent,
            true,
        ),
        async |kernel, _, _| {
            assert!(kernel.admin_write_lock.try_lock().is_ok());
            assert!(kernel.env_install_fence.try_read().is_ok());
            Err("injected activation failure".into())
        },
    )
    .await;
    assert!(
        matches!(first, AdminResponseBody::Error(error) if error == "injected activation failure")
    );
    assert_eq!(kernel.env_refresh_pending.len(), 1);
    let called = std::sync::atomic::AtomicBool::new(false);
    let retry = env_set_with_refresh(
        &kernel,
        request(
            "retry",
            "replacement",
            EnvValueKind::Text,
            EnvStorageScope::Agent,
            true,
        ),
        async |kernel, principal, capsule| {
            assert!(kernel.admin_write_lock.try_lock().is_ok());
            assert!(kernel.env_install_fence.try_read().is_ok());
            let store = env_scope(
                kernel,
                principal,
                capsule,
                EnvValueKind::Text,
                EnvStorageScope::Agent,
            )
            .unwrap();
            assert_eq!(
                astrid_storage::env::get_env(&store, "retry")
                    .await
                    .unwrap()
                    .as_deref(),
                Some("original")
            );
            called.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        },
    )
    .await;
    default_success(retry);
    assert!(called.load(std::sync::atomic::Ordering::SeqCst));
    assert!(kernel.env_refresh_pending.is_empty());
}

#[tokio::test]
async fn older_refresh_cannot_clear_a_newer_failed_write() {
    let (_dir, kernel) = fixture().await;
    let first = env_set_with_refresh(
        &kernel,
        request(
            "generation",
            "default",
            EnvValueKind::Text,
            EnvStorageScope::Agent,
            true,
        ),
        async |kernel, _, _| {
            let later = env_set_with_refresh(
                kernel,
                request(
                    "generation",
                    "operator",
                    EnvValueKind::Text,
                    EnvStorageScope::Agent,
                    false,
                ),
                async |_, _, _| Err("newer refresh failed".into()),
            )
            .await;
            assert!(matches!(later, AdminResponseBody::Error(_)));
            Ok(())
        },
    )
    .await;
    default_success(first);
    assert_eq!(kernel.env_refresh_pending.len(), 1);
    let retry = env_set_with_refresh(
        &kernel,
        request(
            "generation",
            "unused",
            EnvValueKind::Text,
            EnvStorageScope::Agent,
            true,
        ),
        async |kernel, principal, capsule| {
            let store = env_scope(
                kernel,
                principal,
                capsule,
                EnvValueKind::Text,
                EnvStorageScope::Agent,
            )
            .unwrap();
            assert_eq!(
                astrid_storage::env::get_env(&store, "generation")
                    .await
                    .unwrap()
                    .as_deref(),
                Some("operator")
            );
            Ok(())
        },
    )
    .await;
    default_success(retry);
    assert!(kernel.env_refresh_pending.is_empty());
}

#[tokio::test]
async fn concurrent_defaults_queue_instead_of_reporting_an_install() {
    use std::future::{Future, poll_fn};
    use std::task::Poll;

    let (_dir, kernel) = fixture().await;
    let guard = kernel.admin_write_lock.lock().await;
    let mut first = std::pin::pin!(env_set(
        &kernel,
        request(
            "model",
            "first",
            EnvValueKind::Text,
            EnvStorageScope::Agent,
            true
        )
    ));
    let mut second = std::pin::pin!(env_set(
        &kernel,
        request(
            "model",
            "second",
            EnvValueKind::Text,
            EnvStorageScope::Agent,
            true
        )
    ));
    assert!(poll_fn(|cx| Poll::Ready(first.as_mut().poll(cx).is_pending())).await);
    assert!(poll_fn(|cx| Poll::Ready(second.as_mut().poll(cx).is_pending())).await);
    drop(guard);
    let (first, second) = tokio::join!(first, second);
    default_success(first);
    default_success(second);
    let store = env_scope(
        &kernel,
        &PrincipalId::default(),
        "provider",
        EnvValueKind::Text,
        EnvStorageScope::Agent,
    )
    .unwrap();
    assert_eq!(
        astrid_storage::env::get_env(&store, "model")
            .await
            .unwrap()
            .as_deref(),
        Some("first")
    );
}

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

fn default_success(response: AdminResponseBody) {
    match response {
        AdminResponseBody::Success(value) => assert_eq!(value, serde_json::json!({})),
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
                default_success(
                    env_set(
                        &kernel,
                        request(
                            &key,
                            "default",
                            requested_kind,
                            EnvStorageScope::Agent,
                            true,
                        ),
                    )
                    .await,
                );
                let overlay = env_scope(
                    &kernel,
                    &PrincipalId::default(),
                    "provider",
                    requested_kind,
                    EnvStorageScope::Agent,
                )
                .unwrap();
                let actual = match requested_kind {
                    EnvValueKind::Text => {
                        astrid_storage::env::get_env(&overlay, &key).await.unwrap()
                    },
                    EnvValueKind::Secret => astrid_storage::env::get_secret(&overlay, &key)
                        .await
                        .unwrap(),
                };
                let expected = if existing_kind != requested_kind {
                    Some("default")
                } else if scope == EnvStorageScope::Agent {
                    Some("operator")
                } else {
                    None
                };
                assert_eq!(actual.as_deref(), expected);
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
        default_success(default);
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
