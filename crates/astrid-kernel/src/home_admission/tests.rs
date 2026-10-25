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
    assert!(matches!(validate(&home).unwrap(), HomeAdmission::Retiring));
    assert!(home.ensure().is_err());
    assert_eq!(
        std::fs::read(home.log_dir().join("audit")).unwrap(),
        b"preserve"
    );
    std::fs::remove_file(home.storage_volume_path()).unwrap();
    assert!(
        validate(&home).is_err(),
        "a fresh root cannot use the recovery path"
    );
}
