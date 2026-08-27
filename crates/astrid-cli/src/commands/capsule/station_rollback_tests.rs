use super::*;

#[test]
fn coordinate_handoff_rejects_substituted_non_manifest_bytes_before_state() {
    let root = tempfile::tempdir().unwrap();
    let station_home = root.path().join("station");
    std::fs::create_dir_all(&station_home).unwrap();
    let workspace = root.path().join("workspace");
    std::fs::create_dir_all(&workspace).unwrap();
    let manifest = b"[package]\nname = \"demo\"\nversion = \"1.0.0\"\n";
    let (_match_dir, matching) = capsule_archive(manifest);
    let (_sent_dir, sent) = capsule_archive(manifest);
    let mut bytes = std::fs::read(&sent).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x80;
    std::fs::write(&sent, bytes).unwrap();
    let lock = lock_for_archive(&matching, manifest);
    let lock_path = root.path().join("resolved.lock.json");
    write_lock_json(&lock_path, &lock);
    let marker = root.path().join("station-calls");
    let script = fake_station_script(root.path(), &sent, &marker, &lock_path);
    let _current_dir = CurrentDirGuard::install(&workspace);
    let _paths = super::test_station_paths(&script, &station_home);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let principal = PrincipalId::default();
    let home = astrid_core::dirs::AstridHome::from_path(root.path().join("astrid"));
    let _locks = runtime.block_on(super::test_lock_backend::install());
    let _local = crate::commands::capsule::install::test_local_install_backend(true);

    let error = runtime
        .block_on(
            crate::commands::capsule::install::test_install_station_source(
                "@official/demo",
                &home,
                &principal,
                &ManualInstallOptions {
                    yes: true,
                    approve_untrusted: true,
                    ..Default::default()
                },
            ),
        )
        .expect_err("byte substitution must fail the handoff");
    assert!(format!("{error:#}").contains("artifact SHA-256"));
    assert_eq!(super::test_lock_backend::set_calls(), 0);
    assert!(
        runtime
            .block_on(load_lock(&principal, "demo"))
            .unwrap()
            .is_none()
    );
    assert!(crate::commands::capsule::install::test_daemon_install_call().is_none());
}

#[tokio::test]
async fn rollback_delete_is_conditioned_on_the_just_written_lock() {
    let _locks = super::test_lock_backend::install().await;
    let principal = PrincipalId::new("rollback-delete").unwrap();
    let just_written = sample_lock(&digest("blake3:", 0xf1));
    store_lock(&principal, "demo", just_written.clone())
        .await
        .unwrap();
    crate::commands::capsule::install::restore_station_lock(
        &principal,
        "demo",
        None,
        &just_written,
    )
    .await
    .unwrap();
    assert!(load_lock(&principal, "demo").await.unwrap().is_none());
    assert_eq!(super::test_lock_backend::delete_calls(), 1);
}

#[tokio::test]
async fn concurrent_newer_lock_blocks_previous_restore_and_delete() {
    let _locks = super::test_lock_backend::install().await;
    let principal = PrincipalId::new("rollback-race").unwrap();
    let previous = sample_lock(&digest("blake3:", 0xf2));
    let just_written = sample_lock(&digest("blake3:", 0xf3));
    let newer = sample_lock(&digest("blake3:", 0xf4));
    store_lock(&principal, "demo", just_written.clone())
        .await
        .unwrap();
    store_lock(&principal, "demo", newer.clone()).await.unwrap();
    let restore_error = crate::commands::capsule::install::restore_station_lock(
        &principal,
        "demo",
        Some(&previous),
        &just_written,
    )
    .await
    .expect_err("a newer owner must block restoration");
    assert!(
        format!("{restore_error:#}").contains("expected_hash rejected"),
        "error: {restore_error:?}"
    );
    assert_eq!(
        load_lock(&principal, "demo").await.unwrap(),
        Some(newer.clone())
    );

    store_lock(&principal, "race-delete", newer.clone())
        .await
        .unwrap();
    let delete_error = crate::commands::capsule::install::restore_station_lock(
        &principal,
        "race-delete",
        None,
        &just_written,
    )
    .await
    .expect_err("a newer owner must block deletion");
    assert!(
        format!("{delete_error:#}").contains("expected_hash rejected"),
        "error: {delete_error:?}"
    );
    assert_eq!(
        load_lock(&principal, "race-delete").await.unwrap(),
        Some(newer)
    );
}

#[tokio::test]
async fn backend_failure_surfaces_with_original_install_context() {
    let _locks = super::test_lock_backend::install().await;
    let principal = PrincipalId::new("rollback-failure").unwrap();
    let just_written = sample_lock(&digest("blake3:", 0xf5));
    super::store_lock(&principal, "demo", just_written.clone())
        .await
        .unwrap();
    super::test_lock_backend::queue_next_set_failure();
    let error = crate::commands::capsule::install::restore_station_lock(
        &principal,
        "demo",
        Some(&just_written),
        &just_written,
    )
    .await
    .expect_err("backend failures cannot be swallowed");
    assert!(
        format!("{error:#}").contains("injected Station lock backend"),
        "error: {error:?}"
    );
    assert_eq!(
        load_lock(&principal, "demo").await.unwrap(),
        Some(just_written)
    );
    let combined = crate::commands::capsule::install::combine_install_and_restore_errors(
        anyhow::anyhow!("daemon install failed"),
        Err(error),
    );
    assert!(format!("{combined:#}").contains("daemon install failed"));
    assert!(
        combined
            .to_string()
            .contains("Station lock rollback failed")
    );
    assert_eq!(combined.root_cause().to_string(), "daemon install failed");
}

#[tokio::test]
async fn coordinate_failure_surfaces_rollback_failure_without_clobbering_current_lock() {
    let root = tempfile::tempdir().unwrap();
    let station_home = root.path().join("station");
    std::fs::create_dir_all(&station_home).unwrap();
    let workspace = root.path().join("workspace");
    std::fs::create_dir_all(&workspace).unwrap();
    let manifest = b"[package]\nname = \"demo\"\nversion = \"1.0.0\"\n";
    let (_fixture_dir, fixture) = capsule_archive(manifest);
    let lock = lock_for_archive(&fixture, manifest);
    let lock_path = root.path().join("resolved.lock.json");
    write_lock_json(&lock_path, &lock);
    let marker = root.path().join("station-calls");
    let script = fake_station_script(root.path(), &fixture, &marker, &lock_path);
    let _current_dir = CurrentDirGuard::install(&workspace);
    let _paths = super::test_station_paths(&script, &station_home);
    let previous = sample_lock(&digest("blake3:", 0xf6));
    let principal = PrincipalId::new("coordinate-rollback").unwrap();
    let home = astrid_core::dirs::AstridHome::from_path(root.path().join("astrid"));
    let _locks = super::test_lock_backend::install().await;
    super::store_lock(&principal, "demo", previous.clone())
        .await
        .unwrap();
    super::test_lock_backend::queue_set_failure_on_call(3);
    let _local = crate::commands::capsule::install::test_local_install_backend(true);
    let error = crate::commands::capsule::install::test_install_station_source_with_workspace(
        "@official/demo",
        &home,
        &principal,
        &ManualInstallOptions {
            yes: true,
            approve_untrusted: true,
            ..Default::default()
        },
        false,
    )
    .await
    .expect_err("failed daemon installation must roll back");
    assert!(format!("{error:#}").contains("daemon install failed"));
    assert!(format!("{error:#}").contains("Station lock rollback failed"));
    assert_eq!(load_lock(&principal, "demo").await.unwrap(), Some(lock));
    assert_eq!(super::test_lock_backend::set_calls(), 3);
}

#[tokio::test]
async fn backend_delete_failure_surfaces_and_preserves_just_written_lock() {
    let _locks = super::test_lock_backend::install().await;
    let principal = PrincipalId::new("delete-failure").unwrap();
    let just_written = sample_lock(&digest("blake3:", 0xf8));
    super::store_lock(&principal, "demo", just_written.clone())
        .await
        .unwrap();
    super::test_lock_backend::queue_next_delete_failure();
    let error = crate::commands::capsule::install::restore_station_lock(
        &principal,
        "demo",
        None,
        &just_written,
    )
    .await
    .expect_err("conditional deletion failures cannot be swallowed");
    assert!(
        format!("{error:#}").contains("injected Station lock backend"),
        "error: {error:?}"
    );
    assert_eq!(
        load_lock(&principal, "demo").await.unwrap(),
        Some(just_written)
    );
}

#[tokio::test]
async fn existing_lock_failure_restores_the_previous_owner_scoped_lock() {
    let root = tempfile::tempdir().unwrap();
    let station_home = root.path().join("station");
    std::fs::create_dir_all(&station_home).unwrap();
    let workspace = root.path().join("workspace");
    std::fs::create_dir_all(&workspace).unwrap();
    let manifest = b"[package]\nname = \"demo\"\nversion = \"1.0.0\"\n";
    let (_fixture_dir, fixture) = capsule_archive(manifest);
    let lock = lock_for_archive(&fixture, manifest);
    let lock_path = root.path().join("resolved.lock.json");
    write_lock_json(&lock_path, &lock);
    let marker = root.path().join("station-calls");
    let script = fake_station_script(root.path(), &fixture, &marker, &lock_path);
    let _current_dir = CurrentDirGuard::install(&workspace);
    let _paths = super::test_station_paths(&script, &station_home);
    let previous = sample_lock(&digest("blake3:", 0xf7));
    let principal = PrincipalId::new("existing-rollback").unwrap();
    let home = astrid_core::dirs::AstridHome::from_path(root.path().join("astrid"));
    let _locks = super::test_lock_backend::install().await;
    super::store_lock(&principal, "demo", previous.clone())
        .await
        .unwrap();
    let _local = crate::commands::capsule::install::test_local_install_backend(true);
    let error = crate::commands::capsule::install::install_from_station_lock(
        "demo", &lock, false, &home, &principal, true,
    )
    .await
    .expect_err("failed existing-lock update must roll back");
    assert!(format!("{error:#}").contains("daemon install failed"));
    assert_eq!(load_lock(&principal, "demo").await.unwrap(), Some(previous));
    assert_eq!(super::test_lock_backend::set_calls(), 3);
}
