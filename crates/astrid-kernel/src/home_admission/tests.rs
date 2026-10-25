use super::*;

#[test]
fn interrupted_retirement_reaches_volume_authentication_without_fresh_root_admission() {
    let root = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(root.path());
    astrid_core::platform_fs::ensure_private_directory(home.root()).unwrap();
    astrid_core::platform_fs::atomic_write_private_file(&home.storage_volume_path(), b"media")
        .unwrap();
    std::fs::create_dir(home.log_dir()).unwrap();
    std::fs::write(home.log_dir().join("audit"), b"preserve").unwrap();
    assert!(home.ensure().is_err());
    assert!(matches!(
        validate_boot(&home).unwrap(),
        HomeAdmission::Unsentinelled
    ));
    assert!(home.ensure().is_err());
    assert_eq!(
        std::fs::read(home.log_dir().join("audit")).unwrap(),
        b"preserve"
    );
    std::fs::remove_file(home.storage_volume_path()).unwrap();
    assert!(
        validate_boot(&home).is_err(),
        "a fresh root cannot use the recovery path"
    );
}

#[tokio::test]
async fn fresh_retry_rechecks_ledger_before_opening_media() {
    let root = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(root.path());
    astrid_core::platform_fs::ensure_private_directory(home.root()).unwrap();
    astrid_core::platform_fs::atomic_write_private_file(&home.storage_volume_path(), b"media")
        .unwrap();
    astrid_core::platform_fs::atomic_write_private_file(&home.layout_version_path(), b"2").unwrap();
    let admission = validate_boot(&home).unwrap();
    assert!(matches!(admission, HomeAdmission::FreshRetry));
    let ledger = crate::legacy_migration_barrier::ledger_path(&home);
    astrid_core::platform_fs::atomic_write_private_file(&ledger, b"appeared ledger").unwrap();
    let error = admission
        .open_store(
            &home,
            std::sync::Arc::new(|_: &astrid_storage::StateOwner| Ok(None)),
            astrid_storage::PrincipalDirectory::default(),
        )
        .await
        .err()
        .expect("ledger appeared after classification");
    assert!(error.to_string().contains("ledger appeared"));
    assert_eq!(std::fs::read(home.storage_volume_path()).unwrap(), b"media");
    assert_eq!(std::fs::read(ledger).unwrap(), b"appeared ledger");
}
