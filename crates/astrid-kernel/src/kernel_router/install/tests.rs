//! Legacy install transaction tests (env staging/rollback and provenance).

use std::sync::Arc;

use super::*;

#[tokio::test]
async fn install_env_transaction_restores_existing_text_and_secret_values() {
    let root = tempfile::tempdir().unwrap();
    let home = astrid_core::dirs::AstridHome::from_path(root.path());
    let kernel = crate::test_kernel_with_home(home.clone()).await;
    let principal = astrid_core::PrincipalId::new("install-env").unwrap();
    kernel
        .principal_directory
        .register(
            principal.clone(),
            astrid_core::identity::PrincipalUid::from_bytes([7; 32]),
        )
        .unwrap();
    astrid_core::profile::PrincipalProfile::default()
        .save_to_path(&astrid_core::profile::PrincipalProfile::path_for(
            &home, &principal,
        ))
        .unwrap();
    let source = root.path().join("fixture");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(
        source.join("Capsule.toml"),
        r#"
            [package]
            name = "fixture"
            version = "1.0.0"
            [env.PLAIN]
            type = "text"
            [env.SECRET]
            type = "secret"
        "#,
    )
    .unwrap();
    let uid = kernel.principal_directory.uid_for(&principal).unwrap();
    let plain = astrid_storage::ScopedKvStore::new(
        Arc::clone(&kernel.kv),
        astrid_storage::env::principal_capsule_namespace(uid, "fixture"),
    )
    .unwrap();
    plain
        .set(&astrid_storage::env::env_key("PLAIN"), b"old".to_vec())
        .await
        .unwrap();
    let secret = astrid_storage::ScopedKvStore::new(
        Arc::clone(&kernel.kv),
        astrid_storage::env::system_secret_namespace("fixture"),
    )
    .unwrap();
    secret
        .set(
            &format!("{}SECRET", astrid_storage::env::SECRET_KEY_PREFIX),
            b"old-secret".to_vec(),
        )
        .await
        .unwrap();

    let values = vec![
        CapsuleInstallEnv {
            key: "PLAIN".into(),
            value: "new".into(),
            kind: astrid_core::kernel_api::EnvValueKind::Text,
        },
        CapsuleInstallEnv {
            key: "SECRET".into(),
            value: "new-secret".into(),
            kind: astrid_core::kernel_api::EnvValueKind::Secret,
        },
    ];
    let transaction = stage_env_values(&kernel, &principal, &source, &values)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        plain
            .get(&astrid_storage::env::env_key("PLAIN"))
            .await
            .unwrap(),
        Some(b"new".to_vec())
    );
    assert_eq!(
        secret
            .get(&format!("{}SECRET", astrid_storage::env::SECRET_KEY_PREFIX))
            .await
            .unwrap(),
        Some(b"new-secret".to_vec())
    );
    transaction.rollback(&kernel).await;
    assert_eq!(
        plain
            .get(&astrid_storage::env::env_key("PLAIN"))
            .await
            .unwrap(),
        Some(b"old".to_vec())
    );
    assert_eq!(
        secret
            .get(&format!("{}SECRET", astrid_storage::env::SECRET_KEY_PREFIX))
            .await
            .unwrap(),
        Some(b"old-secret".to_vec())
    );
}

#[tokio::test]
async fn env_rollback_does_not_clobber_a_concurrent_edit() {
    let root = tempfile::tempdir().unwrap();
    let home = astrid_core::dirs::AstridHome::from_path(root.path());
    let kernel = crate::test_kernel_with_home(home.clone()).await;
    let principal = astrid_core::PrincipalId::new("rollback-edit").unwrap();
    kernel
        .principal_directory
        .register(
            principal.clone(),
            astrid_core::identity::PrincipalUid::from_bytes([8; 32]),
        )
        .unwrap();
    astrid_core::profile::PrincipalProfile::default()
        .save_to_path(&astrid_core::profile::PrincipalProfile::path_for(
            &home, &principal,
        ))
        .unwrap();
    let source = root.path().join("fixture");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(
        source.join("Capsule.toml"),
        r#"
            [package]
            name = "fixture"
            version = "1.0.0"
            [env.PLAIN]
            type = "text"
            [env.SECRET]
            type = "secret"
        "#,
    )
    .unwrap();
    let uid = kernel.principal_directory.uid_for(&principal).unwrap();
    let plain_namespace = astrid_storage::env::principal_capsule_namespace(uid, "fixture");
    let plain_key = astrid_storage::env::env_key("PLAIN");
    let secret_namespace = astrid_storage::env::system_secret_namespace("fixture");
    let secret_key = format!("{}SECRET", astrid_storage::env::SECRET_KEY_PREFIX);
    kernel
        .kv
        .set(&plain_namespace, &plain_key, b"old".to_vec())
        .await
        .unwrap();
    kernel
        .kv
        .set(&secret_namespace, &secret_key, b"old-secret".to_vec())
        .await
        .unwrap();
    let values = vec![
        CapsuleInstallEnv {
            key: "PLAIN".into(),
            value: "staged".into(),
            kind: astrid_core::kernel_api::EnvValueKind::Text,
        },
        CapsuleInstallEnv {
            key: "SECRET".into(),
            value: "staged-secret".into(),
            kind: astrid_core::kernel_api::EnvValueKind::Secret,
        },
    ];
    let transaction = stage_env_values(&kernel, &principal, &source, &values)
        .await
        .unwrap()
        .unwrap();
    kernel
        .kv
        .set(&plain_namespace, &plain_key, b"operator-edit".to_vec())
        .await
        .unwrap();
    transaction.rollback(&kernel).await;
    assert_eq!(
        kernel.kv.get(&plain_namespace, &plain_key).await.unwrap(),
        Some(b"operator-edit".to_vec())
    );
    assert_eq!(
        kernel.kv.get(&secret_namespace, &secret_key).await.unwrap(),
        Some(b"old-secret".to_vec()),
        "Shared secret rollback is a separate owner batch from Agent text"
    );
}

#[test]
fn provenance_source_digest_is_checked_before_install_mutation() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("fixture.capsule");
    std::fs::write(&source, b"capsule-bytes").unwrap();
    let provenance = CapsuleInstallProvenance {
        distro: Some("sealed-distro".into()),
        source_digest: Some(format!("blake3:{}", blake3::hash(b"different").to_hex())),
    };
    let error = validate_install_provenance(&source, Some(&provenance)).unwrap_err();
    assert!(error.contains("source_digest mismatch"), "{error}");
}

#[tokio::test]
async fn install_secret_is_staged_in_system_secret_namespace() {
    let root = tempfile::tempdir().unwrap();
    let home = astrid_core::dirs::AstridHome::from_path(root.path());
    let kernel = crate::test_kernel_with_home(home.clone()).await;
    let principal = astrid_core::PrincipalId::new("install-shared-secret").unwrap();
    kernel
        .principal_directory
        .register(
            principal.clone(),
            astrid_core::identity::PrincipalUid::from_bytes([9; 32]),
        )
        .unwrap();
    astrid_core::profile::PrincipalProfile::default()
        .save_to_path(&astrid_core::profile::PrincipalProfile::path_for(
            &home, &principal,
        ))
        .unwrap();
    let source = root.path().join("fixture");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(
        source.join("Capsule.toml"),
        r#"
            [package]
            name = "fixture"
            version = "1.0.0"
            [env.PLAIN]
            type = "text"
            [env.SECRET]
            type = "secret"
        "#,
    )
    .unwrap();
    let values = vec![
        CapsuleInstallEnv {
            key: "PLAIN".into(),
            value: "site-text".into(),
            kind: astrid_core::kernel_api::EnvValueKind::Text,
        },
        CapsuleInstallEnv {
            key: "SECRET".into(),
            value: "site-secret".into(),
            kind: astrid_core::kernel_api::EnvValueKind::Secret,
        },
    ];
    stage_env_values(&kernel, &principal, &source, &values)
        .await
        .unwrap()
        .unwrap();

    let uid = kernel.principal_directory.uid_for(&principal).unwrap();
    let shared_secret = kernel
        .kv
        .get(
            &astrid_storage::env::system_secret_namespace("fixture"),
            &format!("{}SECRET", astrid_storage::env::SECRET_KEY_PREFIX),
        )
        .await
        .unwrap();
    assert_eq!(shared_secret.as_deref(), Some(b"site-secret".as_slice()));
    let installer_secret = kernel
        .kv
        .get(
            &astrid_storage::env::principal_secret_namespace(uid, "fixture"),
            &format!("{}SECRET", astrid_storage::env::SECRET_KEY_PREFIX),
        )
        .await
        .unwrap();
    assert!(
        installer_secret.is_none(),
        "install secrets must not land in the installer principal secret namespace"
    );
    let installer_text = kernel
        .kv
        .get(
            &astrid_storage::env::principal_capsule_namespace(uid, "fixture"),
            &astrid_storage::env::env_key("PLAIN"),
        )
        .await
        .unwrap();
    assert_eq!(installer_text.as_deref(), Some(b"site-text".as_slice()));
}
