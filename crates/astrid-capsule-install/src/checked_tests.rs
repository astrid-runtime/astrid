use std::fs::File;

use astrid_capsule::capsule::CapsuleId;
use astrid_core::PrincipalId;
use astrid_core::dirs::AstridHome;

use crate::{
    InstallOptions, install_from_local_path_checked_for_principal, resolve_target_dir_for,
    unpack_and_install_checked_for_principal,
};

fn write_manifest(dir: &std::path::Path, name: &str, version: &str) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(
        dir.join("Capsule.toml"),
        format!("[package]\nname = \"{name}\"\nversion = \"{version}\"\n"),
    )
    .unwrap();
}

fn existing_target(home: &AstridHome, principal: &PrincipalId, name: &str) -> std::path::PathBuf {
    let target = resolve_target_dir_for(home, principal, name, false).unwrap();
    std::fs::create_dir_all(&target).unwrap();
    std::fs::write(target.join("marker"), b"original").unwrap();
    target
}

#[test]
fn checked_local_rejects_identity_before_target_mutation() {
    let temp = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(temp.path().join("home"));
    let principal = PrincipalId::new("alice").unwrap();
    let expected = CapsuleId::new("expected").unwrap();
    let source = temp.path().join("source");
    write_manifest(&source, "unexpected", "1.0.0");
    let target = existing_target(&home, &principal, expected.as_str());

    let err = install_from_local_path_checked_for_principal(
        &source,
        &home,
        InstallOptions::default(),
        &principal,
        &expected,
        Some("1.0.0"),
    )
    .unwrap_err();

    assert!(err.to_string().contains("identity mismatch"));
    assert_eq!(std::fs::read(target.join("marker")).unwrap(), b"original");
    assert!(
        !resolve_target_dir_for(&home, &principal, "unexpected", false)
            .unwrap()
            .exists()
    );
}

#[test]
fn checked_archive_rejects_version_before_replacing_existing_install() {
    let temp = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(temp.path().join("home"));
    let principal = PrincipalId::new("alice").unwrap();
    let expected = CapsuleId::new("expected").unwrap();
    let source = temp.path().join("source");
    write_manifest(&source, expected.as_str(), "2.0.0");
    let target = existing_target(&home, &principal, expected.as_str());

    let archive_path = temp.path().join("expected.capsule");
    let encoder = flate2::write::GzEncoder::new(
        File::create(&archive_path).unwrap(),
        flate2::Compression::default(),
    );
    let mut archive = tar::Builder::new(encoder);
    archive
        .append_path_with_name(source.join("Capsule.toml"), "Capsule.toml")
        .unwrap();
    archive.into_inner().unwrap().finish().unwrap();

    let err = unpack_and_install_checked_for_principal(
        &archive_path,
        &home,
        InstallOptions::default(),
        &principal,
        &expected,
        Some("1.0.0"),
    )
    .unwrap_err();

    assert!(err.to_string().contains("version mismatch"));
    assert_eq!(std::fs::read(target.join("marker")).unwrap(), b"original");
}
